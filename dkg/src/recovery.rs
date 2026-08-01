//! Canonical encrypted DKG recovery formats.
//!
//! # Status
//!
//! Recovery formats are versioned and intentionally reject unknown versions,
//! oversized collections, and trailing bytes. Plaintext recovery types do not
//! implement `Debug` because they contain threshold shares and private dealings.

use crate::{
    protector::{StorageKey, NONCE_SIZE},
    public::{PublicCheckpoint, STATE_FORMAT_VERSION},
    Reconciliation,
};
use async_trait::async_trait;
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{DealerLog, DealerPrivMsg, DealerPubMsg, Output, PlayerAck},
        primitives::{group::Share, sharing::ModeVersion, variant::Variant},
    },
    sha256::{Digest, Sha256},
    transcript::Summary,
    Hasher, PublicKey,
};
use commonware_runtime::{Buf, BufMut};
use rand::CryptoRng;
use std::num::NonZeroU32;

fn string_encode_size(value: &str) -> usize {
    value.as_bytes().to_vec().encode_size()
}

fn write_string(value: &str, buf: &mut impl BufMut) {
    value.as_bytes().to_vec().write(buf);
}

fn read_string(buf: &mut impl Buf, range: RangeCfg<usize>) -> Result<String, CodecError> {
    String::from_utf8(Vec::<u8>::read_cfg(buf, &(range, ()))?)
        .map_err(|_| CodecError::Invalid("String", "invalid utf-8"))
}

/// Current plaintext recovery format.
pub const RECOVERY_FORMAT_VERSION: u8 = 1;
/// Current encrypted envelope format.
pub const RECOVERY_ENVELOPE_VERSION: u8 = 1;
/// Current import transaction format.
pub const RECOVERY_IMPORT_VERSION: u8 = 1;
/// Maximum number of immutable bundles retained by a manifest.
pub const MAX_RETAINED_BUNDLES: usize = 3;
/// Maximum supported partition prefix length.
pub const MAX_PARTITION_PREFIX_LEN: usize = 255;
/// Maximum supported recovery associated-data domain length.
pub const MAX_RECOVERY_DOMAIN_LEN: usize = 96;
/// Conservative maximum encrypted bundle size.
pub const MAX_BUNDLE_CIPHERTEXT_LEN: usize = 64 * 1024 * 1024;
/// Conservative maximum encrypted manifest size.
pub const MAX_MANIFEST_CIPHERTEXT_LEN: usize = 64 * 1024;
/// Conservative maximum signed local dealer log size.
pub const MAX_SIGNED_LOG_LEN: usize = 4 * 1024 * 1024;
/// Maximum retained logical epochs accepted by the decoder.
pub const MAX_RECOVERY_EPOCHS: usize = 3;

/// Magic for encrypted recovery bundles.
pub const BUNDLE_MAGIC: [u8; 8] = *b"NCHDKGB1";
/// Magic for encrypted recovery manifests.
pub const MANIFEST_MAGIC: [u8; 8] = *b"NCHDKGM1";
/// Associated-data domain for encrypted bundles.
pub const BUNDLE_AD_DOMAIN: &str = "nunchi/dkg-recovery-bundle/v1";
/// Associated-data domain for encrypted manifests.
pub const MANIFEST_AD_DOMAIN: &str = "nunchi/dkg-recovery-manifest/v1";

const ENVELOPE_KEY_DOMAIN: &[u8] = b"nunchi/dkg-recovery-export-key/v1";
const MANIFEST_KEY_DOMAIN: &[u8] = b"nunchi/dkg-recovery-manifest-key/v1";

/// Bounded decoder configuration for recovery plaintext.
#[derive(Clone, Copy)]
pub struct RecoveryReadCfg {
    /// Maximum number of protocol participants.
    pub max_participants: NonZeroU32,
    /// Maximum number of retained epochs.
    pub max_epochs: usize,
    /// Maximum partition-prefix length.
    pub max_partition_prefix_len: usize,
    /// Maximum signed local-log byte length.
    pub max_signed_log_len: usize,
    /// Maximum supported threshold sharing mode.
    pub max_supported_mode: ModeVersion,
}

impl RecoveryReadCfg {
    /// Construct conservative limits from the protocol participant bound.
    pub const fn new(max_participants: NonZeroU32, max_supported_mode: ModeVersion) -> Self {
        Self {
            max_participants,
            max_epochs: MAX_RECOVERY_EPOCHS,
            max_partition_prefix_len: MAX_PARTITION_PREFIX_LEN,
            max_signed_log_len: MAX_SIGNED_LOG_LEN,
            max_supported_mode,
        }
    }
}

/// Stable stage labels for recovery publication failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationStage {
    Queue,
    Lock,
    Encode,
    Encrypt,
    Create,
    Write,
    FileSync,
    Rename,
    ManifestReplace,
    Cleanup,
    DirectorySync,
    ReceiptCheck,
    WorkerShutdown,
}

/// Secret-free recovery failures.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("recovery codec rejected input")]
    Codec(#[source] CodecError),
    #[error("recovery value contains trailing bytes")]
    TrailingBytes,
    #[error("unsupported recovery format version: {0}")]
    UnsupportedFormat(u8),
    #[error("unsupported recovery envelope version: {0}")]
    UnsupportedEnvelope(u8),
    #[error("invalid recovery envelope magic")]
    InvalidMagic,
    #[error("recovery bound exceeded: {0}")]
    Bound(&'static str),
    #[error("recovery identity mismatch: {0}")]
    Identity(&'static str),
    #[error("recovery epoch mismatch")]
    Epoch,
    #[error("recovery checkpoint mismatch")]
    Checkpoint,
    #[error("recovery share validation failed")]
    Share,
    #[error("recovery dealer log validation failed")]
    Log,
    #[error("recovery import is incomplete")]
    ImportIncomplete,
    #[error("recovery import conflict")]
    ImportConflict,
    #[error("recovery receipt mismatch: {0}")]
    Receipt(&'static str),
    #[error("recovery authentication failed")]
    Authentication,
    #[error("recovery publication failed at {0:?}")]
    Publication(PublicationStage),
    #[error("recovery manifest generation overflow")]
    GenerationOverflow,
    #[error("no valid recovery candidate")]
    NoValidRecoveryCandidate,
}

impl From<CodecError> for RecoveryError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

/// The complete canonical logical recovery snapshot.
#[derive(Clone, PartialEq)]
pub struct DkgRecoveryBundle<V: Variant, P: PublicKey> {
    pub format_version: u8,
    pub protocol_config_digest: Digest,
    pub namespace_digest: Digest,
    pub validator: P,
    pub partition_prefix: String,
    pub checkpoint: PublicCheckpoint<V, P>,
    pub checkpoint_digest: Digest,
    pub created_at_ms: u64,
    pub epoch_state: RecoveryEpochState<V, P>,
    pub reconciliation: Option<Reconciliation>,
    pub epochs: Vec<RecoveryEpoch<V, P>>,
}

impl<V: Variant, P: PublicKey> DkgRecoveryBundle<V, P> {
    /// Recompute and validate fields that must be derived from canonical state.
    pub fn validate_canonical(&self) -> Result<(), RecoveryError> {
        if self.format_version != RECOVERY_FORMAT_VERSION {
            return Err(RecoveryError::UnsupportedFormat(self.format_version));
        }
        if self.checkpoint.format_version != STATE_FORMAT_VERSION {
            return Err(RecoveryError::Checkpoint);
        }
        if self.checkpoint_digest != Sha256::hash(&self.checkpoint.encode()) {
            return Err(RecoveryError::Checkpoint);
        }
        if self.epoch_state.epoch != self.checkpoint.epoch {
            return Err(RecoveryError::Epoch);
        }
        if self.protocol_config_digest != self.checkpoint.protocol_config_digest {
            return Err(RecoveryError::Identity("protocol configuration"));
        }
        if self.partition_prefix.is_empty() || self.partition_prefix.len() > MAX_PARTITION_PREFIX_LEN {
            return Err(RecoveryError::Bound("partition prefix"));
        }
        if self.epochs.len() > MAX_RECOVERY_EPOCHS {
            return Err(RecoveryError::Bound("epochs"));
        }
        if !self.epochs.windows(2).all(|pair| pair[0].epoch < pair[1].epoch) {
            return Err(RecoveryError::Identity("epoch ordering"));
        }
        for epoch in &self.epochs {
            if !epoch
                .dealings
                .windows(2)
                .all(|pair| pair[0].dealer < pair[1].dealer)
                || !epoch.logs.windows(2).all(|pair| pair[0].0 < pair[1].0)
            {
                return Err(RecoveryError::Identity("participant ordering"));
            }
            if let Some(dealer) = epoch.local_dealer.as_ref() {
                let recipients = match dealer {
                    RecoveryDealer::Active { recipients, .. }
                    | RecoveryDealer::Finalized { recipients, .. } => recipients,
                };
                if !recipients.windows(2).all(|pair| pair[0].player() < pair[1].player()) {
                    return Err(RecoveryError::Identity("recipient ordering"));
                }
            }
        }
        Ok(())
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for DkgRecoveryBundle<V, P> {
    fn encode_size(&self) -> usize {
        self.format_version.encode_size()
            + self.protocol_config_digest.encode_size()
            + self.namespace_digest.encode_size()
            + self.validator.encode_size()
            + string_encode_size(&self.partition_prefix)
            + self.checkpoint.encode_size()
            + self.checkpoint_digest.encode_size()
            + self.created_at_ms.encode_size()
            + self.epoch_state.encode_size()
            + self.reconciliation.encode_size()
            + self.epochs.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for DkgRecoveryBundle<V, P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.format_version.write(buf);
        self.protocol_config_digest.write(buf);
        self.namespace_digest.write(buf);
        self.validator.write(buf);
        write_string(&self.partition_prefix, buf);
        self.checkpoint.write(buf);
        self.checkpoint_digest.write(buf);
        self.created_at_ms.write(buf);
        self.epoch_state.write(buf);
        self.reconciliation.write(buf);
        self.epochs.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for DkgRecoveryBundle<V, P> {
    type Cfg = RecoveryReadCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let format_version = u8::read(buf)?;
        if format_version != RECOVERY_FORMAT_VERSION {
            return Err(CodecError::Invalid("DkgRecoveryBundle", "unsupported format version"));
        }
        let value = Self {
            format_version,
            protocol_config_digest: ReadExt::read(buf)?,
            namespace_digest: ReadExt::read(buf)?,
            validator: ReadExt::read(buf)?,
            partition_prefix: read_string(
                buf,
                RangeCfg::from(1..=cfg.max_partition_prefix_len),
            )?,
            checkpoint: PublicCheckpoint::read_cfg(
                buf,
                &(cfg.max_participants, cfg.max_supported_mode),
            )?,
            checkpoint_digest: ReadExt::read(buf)?,
            created_at_ms: ReadExt::read(buf)?,
            epoch_state: RecoveryEpochState::read_cfg(
                buf,
                &(cfg.max_participants, cfg.max_supported_mode),
            )?,
            reconciliation: ReadExt::read(buf)?,
            epochs: Vec::<RecoveryEpoch<V, P>>::read_cfg(
                buf,
                &(
                    RangeCfg::from(..=cfg.max_epochs),
                    (cfg.max_participants, cfg.max_signed_log_len),
                ),
            )?,
        };
        value
            .validate_canonical()
            .map_err(|_| CodecError::Invalid("DkgRecoveryBundle", "invalid canonical state"))?;
        Ok(value)
    }
}

/// Exact current epoch state copied from the storage key and value.
#[derive(Clone, PartialEq)]
pub struct RecoveryEpochState<V: Variant, P: PublicKey> {
    pub epoch: Epoch,
    pub round: u64,
    pub rng_seed: Summary,
    pub output: Option<Output<V, P>>,
    pub share: Option<Share>,
}

impl<V: Variant, P: PublicKey> EncodeSize for RecoveryEpochState<V, P> {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.round.encode_size()
            + self.rng_seed.encode_size()
            + self.output.encode_size()
            + self.share.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for RecoveryEpochState<V, P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.round.write(buf);
        self.rng_seed.write(buf);
        self.output.write(buf);
        self.share.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for RecoveryEpochState<V, P> {
    type Cfg = (NonZeroU32, ModeVersion);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: ReadExt::read(buf)?,
            round: ReadExt::read(buf)?,
            rng_seed: ReadExt::read(buf)?,
            output: Read::read_cfg(buf, cfg)?,
            share: ReadExt::read(buf)?,
        })
    }
}

/// All retained messages and local dealer state for one epoch.
#[derive(Clone, PartialEq)]
pub struct RecoveryEpoch<V: Variant, P: PublicKey> {
    pub epoch: Epoch,
    pub dealings: Vec<RecoveryDealing<V, P>>,
    pub logs: Vec<(P, DealerLog<V, P>)>,
    pub local_dealer: Option<RecoveryDealer<V, P>>,
}

/// Exact player-side dealing and the canonical acknowledgement committed for it.
#[derive(Clone, PartialEq)]
pub struct RecoveryDealing<V: Variant, P: PublicKey> {
    pub dealer: P,
    pub public_message: DealerPubMsg<V>,
    pub private_message: DealerPrivMsg,
    pub acknowledgement: Bytes,
}

impl<V: Variant, P: PublicKey> EncodeSize for RecoveryDealing<V, P> {
    fn encode_size(&self) -> usize {
        self.dealer.encode_size()
            + self.public_message.encode_size()
            + self.private_message.encode_size()
            + self.acknowledgement.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for RecoveryDealing<V, P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.dealer.write(buf);
        self.public_message.write(buf);
        self.private_message.write(buf);
        self.acknowledgement.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for RecoveryDealing<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            dealer: ReadExt::read(buf)?,
            public_message: DealerPubMsg::read_cfg(buf, cfg)?,
            private_message: ReadExt::read(buf)?,
            acknowledgement: Bytes::read_cfg(buf, &RangeCfg::from(1..=1024))?,
        })
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for RecoveryEpoch<V, P> {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.dealings.encode_size()
            + self.logs.encode_size()
            + self.local_dealer.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for RecoveryEpoch<V, P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.dealings.write(buf);
        self.logs.write(buf);
        self.local_dealer.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for RecoveryEpoch<V, P> {
    type Cfg = (NonZeroU32, usize);

    fn read_cfg(buf: &mut impl Buf, &(max_participants, max_log_len): &Self::Cfg) -> Result<Self, CodecError> {
        let bound = max_participants.get() as usize;
        Ok(Self {
            epoch: ReadExt::read(buf)?,
            dealings: Vec::read_cfg(
                buf,
                &(RangeCfg::from(..=bound), max_participants),
            )?,
            logs: Vec::read_cfg(
                buf,
                &(RangeCfg::from(..=bound), ((), max_participants)),
            )?,
            local_dealer: Option::read_cfg(buf, &(max_participants, max_log_len))?,
        })
    }
}

/// Immutable persisted local dealer state.
#[derive(Clone, PartialEq)]
pub enum RecoveryDealer<V: Variant, P: PublicKey> {
    Active {
        public_message: DealerPubMsg<V>,
        recipients: Vec<RecipientState<P>>,
    },
    Finalized {
        public_message: DealerPubMsg<V>,
        recipients: Vec<RecipientState<P>>,
        signed_log: Bytes,
    },
}

impl<V: Variant, P: PublicKey> EncodeSize for RecoveryDealer<V, P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Active { public_message, recipients } => {
                public_message.encode_size() + recipients.encode_size()
            }
            Self::Finalized { public_message, recipients, signed_log } => {
                public_message.encode_size() + recipients.encode_size() + signed_log.encode_size()
            }
        }
    }
}

impl<V: Variant, P: PublicKey> Write for RecoveryDealer<V, P> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Active { public_message, recipients } => {
                0u8.write(buf);
                public_message.write(buf);
                recipients.write(buf);
            }
            Self::Finalized { public_message, recipients, signed_log } => {
                1u8.write(buf);
                public_message.write(buf);
                recipients.write(buf);
                signed_log.write(buf);
            }
        }
    }
}

impl<V: Variant, P: PublicKey> Read for RecoveryDealer<V, P> {
    type Cfg = (NonZeroU32, usize);

    fn read_cfg(buf: &mut impl Buf, &(max_participants, max_log_len): &Self::Cfg) -> Result<Self, CodecError> {
        let recipients_cfg = (
            RangeCfg::from(..=max_participants.get() as usize),
            (),
        );
        match u8::read(buf)? {
            0 => Ok(Self::Active {
                public_message: DealerPubMsg::read_cfg(buf, &max_participants)?,
                recipients: Vec::read_cfg(buf, &recipients_cfg)?,
            }),
            1 => Ok(Self::Finalized {
                public_message: DealerPubMsg::read_cfg(buf, &max_participants)?,
                recipients: Vec::read_cfg(buf, &recipients_cfg)?,
                signed_log: Bytes::read_cfg(buf, &RangeCfg::from(..=max_log_len))?,
            }),
            other => Err(CodecError::InvalidEnum(other)),
        }
    }
}

/// Exact per-recipient private dealing state.
#[derive(Clone, PartialEq)]
pub enum RecipientState<P: PublicKey> {
    Unacknowledged { player: P, private_message: DealerPrivMsg },
    Acknowledged { player: P, private_message: DealerPrivMsg, ack: PlayerAck<P> },
}

impl<P: PublicKey> RecipientState<P> {
    fn player(&self) -> &P {
        match self {
            Self::Unacknowledged { player, .. } | Self::Acknowledged { player, .. } => player,
        }
    }
}

impl<P: PublicKey> EncodeSize for RecipientState<P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Unacknowledged { player, private_message } => player.encode_size() + private_message.encode_size(),
            Self::Acknowledged { player, private_message, ack } => {
                player.encode_size() + private_message.encode_size() + ack.encode_size()
            }
        }
    }
}

impl<P: PublicKey> Write for RecipientState<P> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Unacknowledged { player, private_message } => {
                0u8.write(buf);
                player.write(buf);
                private_message.write(buf);
            }
            Self::Acknowledged { player, private_message, ack } => {
                1u8.write(buf);
                player.write(buf);
                private_message.write(buf);
                ack.write(buf);
            }
        }
    }
}

impl<P: PublicKey> Read for RecipientState<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Unacknowledged {
                player: ReadExt::read(buf)?,
                private_message: ReadExt::read(buf)?,
            }),
            1 => Ok(Self::Acknowledged {
                player: ReadExt::read(buf)?,
                private_message: ReadExt::read(buf)?,
                ack: ReadExt::read(buf)?,
            }),
            other => Err(CodecError::InvalidEnum(other)),
        }
    }
}

/// Canonical identity bound as AEAD associated data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAssociatedData<P: PublicKey> {
    pub domain: String,
    pub domain_version: u8,
    pub protocol_config_digest: Digest,
    pub namespace_digest: Digest,
    pub validator: P,
    pub partition_prefix: String,
}

impl<P: PublicKey> EncodeSize for RecoveryAssociatedData<P> {
    fn encode_size(&self) -> usize {
        string_encode_size(&self.domain)
            + self.domain_version.encode_size()
            + self.protocol_config_digest.encode_size()
            + self.namespace_digest.encode_size()
            + self.validator.encode_size()
            + string_encode_size(&self.partition_prefix)
    }
}

impl<P: PublicKey> Write for RecoveryAssociatedData<P> {
    fn write(&self, buf: &mut impl BufMut) {
        write_string(&self.domain, buf);
        self.domain_version.write(buf);
        self.protocol_config_digest.write(buf);
        self.namespace_digest.write(buf);
        self.validator.write(buf);
        write_string(&self.partition_prefix, buf);
    }
}

impl<P: PublicKey> Read for RecoveryAssociatedData<P> {
    type Cfg = (usize, usize);

    fn read_cfg(buf: &mut impl Buf, &(max_domain, max_prefix): &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            domain: read_string(buf, RangeCfg::from(1..=max_domain))?,
            domain_version: ReadExt::read(buf)?,
            protocol_config_digest: ReadExt::read(buf)?,
            namespace_digest: ReadExt::read(buf)?,
            validator: ReadExt::read(buf)?,
            partition_prefix: read_string(buf, RangeCfg::from(1..=max_prefix))?,
        })
    }
}

macro_rules! envelope {
    ($name:ident, $magic:expr, $max:expr) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            pub magic: [u8; 8],
            pub envelope_version: u8,
            pub nonce: [u8; NONCE_SIZE],
            pub ciphertext: Bytes,
        }

        impl EncodeSize for $name {
            fn encode_size(&self) -> usize {
                self.magic.encode_size() + self.envelope_version.encode_size()
                    + self.nonce.encode_size() + self.ciphertext.encode_size()
            }
        }

        impl Write for $name {
            fn write(&self, buf: &mut impl BufMut) {
                self.magic.write(buf);
                self.envelope_version.write(buf);
                self.nonce.write(buf);
                self.ciphertext.write(buf);
            }
        }

        impl Read for $name {
            type Cfg = ();

            fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
                let magic = ReadExt::read(buf)?;
                if magic != $magic {
                    return Err(CodecError::Invalid(stringify!($name), "invalid magic"));
                }
                let envelope_version = u8::read(buf)?;
                if envelope_version != RECOVERY_ENVELOPE_VERSION {
                    return Err(CodecError::Invalid(stringify!($name), "unsupported envelope version"));
                }
                Ok(Self {
                    magic,
                    envelope_version,
                    nonce: ReadExt::read(buf)?,
                    ciphertext: Bytes::read_cfg(buf, &RangeCfg::from(..=$max))?,
                })
            }
        }
    };
}

envelope!(EncryptedRecoveryBundle, BUNDLE_MAGIC, MAX_BUNDLE_CIPHERTEXT_LEN);
envelope!(EncryptedRecoveryManifest, MANIFEST_MAGIC, MAX_MANIFEST_CIPHERTEXT_LEN);

impl EncryptedRecoveryBundle {
    /// Digest the complete canonical encrypted envelope.
    pub fn digest(&self) -> Digest {
        Sha256::hash(&self.encode())
    }
}

/// Public metadata paired with one encrypted bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryMetadata {
    pub checkpoint_epoch: Epoch,
    pub created_at_ms: u64,
    pub checkpoint_digest: Digest,
}

/// Receipt returned only after publication is durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableReceipt {
    pub manifest_generation: u64,
    pub checkpoint_epoch: Epoch,
    pub created_at_ms: u64,
    pub checkpoint_digest: Digest,
    pub bundle_digest: Digest,
}

/// One authenticated manifest entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryManifestEntry {
    pub bundle_digest: Digest,
    pub created_at_ms: u64,
    pub checkpoint_epoch: Epoch,
    pub checkpoint_digest: Digest,
}

/// Authenticated retained bundle set, newest first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryManifest {
    pub format_version: u8,
    pub generation: u64,
    pub entries: Vec<RecoveryManifestEntry>,
}

macro_rules! fixed_codec {
    ($ty:ty, $( $field:ident ),+ $(,)?) => {
        impl EncodeSize for $ty {
            fn encode_size(&self) -> usize { 0 $(+ self.$field.encode_size())+ }
        }
        impl Write for $ty {
            fn write(&self, buf: &mut impl BufMut) { $(self.$field.write(buf);)+ }
        }
    };
}

fixed_codec!(RecoveryMetadata, checkpoint_epoch, created_at_ms, checkpoint_digest);
fixed_codec!(DurableReceipt, manifest_generation, checkpoint_epoch, created_at_ms, checkpoint_digest, bundle_digest);
fixed_codec!(RecoveryManifestEntry, bundle_digest, created_at_ms, checkpoint_epoch, checkpoint_digest);

impl Read for RecoveryMetadata {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self { checkpoint_epoch: ReadExt::read(buf)?, created_at_ms: ReadExt::read(buf)?, checkpoint_digest: ReadExt::read(buf)? })
    }
}

impl Read for DurableReceipt {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self { manifest_generation: ReadExt::read(buf)?, checkpoint_epoch: ReadExt::read(buf)?, created_at_ms: ReadExt::read(buf)?, checkpoint_digest: ReadExt::read(buf)?, bundle_digest: ReadExt::read(buf)? })
    }
}

impl Read for RecoveryManifestEntry {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self { bundle_digest: ReadExt::read(buf)?, created_at_ms: ReadExt::read(buf)?, checkpoint_epoch: ReadExt::read(buf)?, checkpoint_digest: ReadExt::read(buf)? })
    }
}

impl EncodeSize for RecoveryManifest {
    fn encode_size(&self) -> usize { self.format_version.encode_size() + self.generation.encode_size() + self.entries.encode_size() }
}
impl Write for RecoveryManifest {
    fn write(&self, buf: &mut impl BufMut) { self.format_version.write(buf); self.generation.write(buf); self.entries.write(buf); }
}
impl Read for RecoveryManifest {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let format_version = u8::read(buf)?;
        if format_version != RECOVERY_FORMAT_VERSION {
            return Err(CodecError::Invalid("RecoveryManifest", "unsupported format version"));
        }
        let value = Self {
            format_version,
            generation: ReadExt::read(buf)?,
            entries: Vec::read_cfg(buf, &(RangeCfg::from(1..=MAX_RETAINED_BUNDLES), ()))?,
        };
        if value.generation == 0
            || value.entries.iter().enumerate().any(|(index, entry)| {
                value.entries[..index].iter().any(|prior| prior.bundle_digest == entry.bundle_digest)
            })
        {
            return Err(CodecError::Invalid("RecoveryManifest", "invalid structure"));
        }
        Ok(value)
    }
}

/// Transaction phase for a sealed logical import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryImportPhase { Importing, Complete }
impl EncodeSize for RecoveryImportPhase { fn encode_size(&self) -> usize { 1 } }
impl Write for RecoveryImportPhase {
    fn write(&self, buf: &mut impl BufMut) { match self { Self::Importing => 0u8, Self::Complete => 1u8 }.write(buf); }
}
impl Read for RecoveryImportPhase {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? { 0 => Ok(Self::Importing), 1 => Ok(Self::Complete), other => Err(CodecError::InvalidEnum(other)) }
    }
}

/// Sealed transactional import marker plaintext.
#[derive(Clone, PartialEq)]
pub struct RecoveryImportTransaction {
    pub format_version: u8,
    pub bundle_digest: Digest,
    pub logical_state_digest: Digest,
    pub checkpoint_digest: Digest,
    pub target_epoch: Epoch,
    pub phase: RecoveryImportPhase,
}
fixed_codec!(RecoveryImportTransaction, format_version, bundle_digest, logical_state_digest, checkpoint_digest, target_epoch, phase);
impl Read for RecoveryImportTransaction {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let format_version = u8::read(buf)?;
        if format_version != RECOVERY_IMPORT_VERSION {
            return Err(CodecError::Invalid("RecoveryImportTransaction", "unsupported format version"));
        }
        Ok(Self { format_version, bundle_digest: ReadExt::read(buf)?, logical_state_digest: ReadExt::read(buf)?, checkpoint_digest: ReadExt::read(buf)?, target_epoch: ReadExt::read(buf)?, phase: ReadExt::read(buf)? })
    }
}

/// Pair of domain-separated protectors derived from one short-lived root key.
pub struct RecoveryProtectors {
    pub bundle: BundleProtector,
    pub manifest: ManifestProtector,
}

impl RecoveryProtectors {
    /// Derive both recovery keys. The root key is consumed and is not retained.
    pub fn new(root: StorageKey) -> Self {
        let (bundle_key, manifest_key) = derive_recovery_keys(root);
        Self {
            bundle: BundleProtector { cipher: ChaCha20Poly1305::new((&bundle_key.0).into()) },
            manifest: ManifestProtector { cipher: ChaCha20Poly1305::new((&manifest_key.0).into()) },
        }
    }
}

fn derive_key(domain: &[u8], root: &StorageKey) -> Digest {
    let mut material = Vec::with_capacity(domain.len() + root.len());
    material.extend_from_slice(domain);
    material.extend_from_slice(root);
    Sha256::hash(&material)
}

pub(crate) fn derive_recovery_keys(root: StorageKey) -> (Digest, Digest) {
    (
        derive_key(ENVELOPE_KEY_DOMAIN, &root),
        derive_key(MANIFEST_KEY_DOMAIN, &root),
    )
}

/// Protector for logical DKG bundles.
#[derive(Clone)]
pub struct BundleProtector { cipher: ChaCha20Poly1305 }

impl BundleProtector {
    /// Encrypt one canonical bundle with a fresh caller-provided RNG nonce.
    pub fn encrypt<V: Variant, P: PublicKey>(
        &self,
        bundle: &DkgRecoveryBundle<V, P>,
        associated_data: &RecoveryAssociatedData<P>,
        rng: &mut impl CryptoRng,
    ) -> Result<EncryptedRecoveryBundle, RecoveryError> {
        bundle.validate_canonical()?;
        validate_bundle_identity(bundle, associated_data)?;
        validate_ad(associated_data, BUNDLE_AD_DOMAIN)?;
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        let ciphertext = self.cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: &bundle.encode(), aad: &associated_data.encode() },
        ).map_err(|_| RecoveryError::Authentication)?;
        Ok(EncryptedRecoveryBundle { magic: BUNDLE_MAGIC, envelope_version: RECOVERY_ENVELOPE_VERSION, nonce, ciphertext: Bytes::from(ciphertext) })
    }

    /// Authenticate and strictly decode one bundle.
    pub fn decrypt<V: Variant, P: PublicKey>(
        &self,
        envelope: &EncryptedRecoveryBundle,
        associated_data: &RecoveryAssociatedData<P>,
        cfg: &RecoveryReadCfg,
    ) -> Result<DkgRecoveryBundle<V, P>, RecoveryError> {
        if envelope.magic != BUNDLE_MAGIC { return Err(RecoveryError::InvalidMagic); }
        if envelope.envelope_version != RECOVERY_ENVELOPE_VERSION { return Err(RecoveryError::UnsupportedEnvelope(envelope.envelope_version)); }
        validate_ad(associated_data, BUNDLE_AD_DOMAIN)?;
        let plaintext = self.cipher.decrypt(
            Nonce::from_slice(&envelope.nonce),
            Payload { msg: &envelope.ciphertext, aad: &associated_data.encode() },
        ).map_err(|_| RecoveryError::Authentication)?;
        let mut input = plaintext.as_slice();
        let bundle = DkgRecoveryBundle::read_cfg(&mut input, cfg)?;
        if input.has_remaining() { return Err(RecoveryError::TrailingBytes); }
        validate_bundle_identity(&bundle, associated_data)?;
        bundle.validate_canonical()?;
        Ok(bundle)
    }
}

fn validate_bundle_identity<V: Variant, P: PublicKey>(
    bundle: &DkgRecoveryBundle<V, P>,
    ad: &RecoveryAssociatedData<P>,
) -> Result<(), RecoveryError> {
    if bundle.protocol_config_digest != ad.protocol_config_digest { return Err(RecoveryError::Identity("protocol configuration")); }
    if bundle.namespace_digest != ad.namespace_digest { return Err(RecoveryError::Identity("namespace")); }
    if bundle.validator != ad.validator { return Err(RecoveryError::Identity("validator")); }
    if bundle.partition_prefix != ad.partition_prefix { return Err(RecoveryError::Identity("partition prefix")); }
    Ok(())
}

fn validate_ad<P: PublicKey>(ad: &RecoveryAssociatedData<P>, domain: &str) -> Result<(), RecoveryError> {
    if ad.domain != domain { return Err(RecoveryError::Identity("associated-data domain")); }
    if ad.domain_version != RECOVERY_ENVELOPE_VERSION { return Err(RecoveryError::UnsupportedEnvelope(ad.domain_version)); }
    if ad.partition_prefix.is_empty() || ad.partition_prefix.len() > MAX_PARTITION_PREFIX_LEN { return Err(RecoveryError::Bound("partition prefix")); }
    Ok(())
}

/// Protector for authenticated recovery manifests.
#[derive(Clone)]
pub struct ManifestProtector { cipher: ChaCha20Poly1305 }

impl ManifestProtector {
    pub fn encrypt<P: PublicKey>(&self, manifest: &RecoveryManifest, ad: &RecoveryAssociatedData<P>, rng: &mut impl CryptoRng) -> Result<EncryptedRecoveryManifest, RecoveryError> {
        validate_ad(ad, MANIFEST_AD_DOMAIN)?;
        let canonical = manifest.encode();
        let mut check = canonical.as_ref();
        let _ = RecoveryManifest::read(&mut check)?;
        if check.has_remaining() { return Err(RecoveryError::TrailingBytes); }
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        let ciphertext = self.cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: &canonical, aad: &ad.encode() }).map_err(|_| RecoveryError::Authentication)?;
        Ok(EncryptedRecoveryManifest { magic: MANIFEST_MAGIC, envelope_version: RECOVERY_ENVELOPE_VERSION, nonce, ciphertext: Bytes::from(ciphertext) })
    }

    pub fn decrypt<P: PublicKey>(&self, envelope: &EncryptedRecoveryManifest, ad: &RecoveryAssociatedData<P>) -> Result<RecoveryManifest, RecoveryError> {
        if envelope.magic != MANIFEST_MAGIC { return Err(RecoveryError::InvalidMagic); }
        if envelope.envelope_version != RECOVERY_ENVELOPE_VERSION { return Err(RecoveryError::UnsupportedEnvelope(envelope.envelope_version)); }
        validate_ad(ad, MANIFEST_AD_DOMAIN)?;
        let plaintext = self.cipher.decrypt(Nonce::from_slice(&envelope.nonce), Payload { msg: &envelope.ciphertext, aad: &ad.encode() }).map_err(|_| RecoveryError::Authentication)?;
        let mut input = plaintext.as_slice();
        let manifest = RecoveryManifest::read(&mut input)?;
        if input.has_remaining() { return Err(RecoveryError::TrailingBytes); }
        Ok(manifest)
    }
}

/// Runtime-independent publication interface owned by the DKG actor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryPublication {
    GenesisFirst,
    NormalReplay,
    DisasterRestore,
    Runtime,
}

/// One ordered envelope returned from authenticated recovery metadata.
#[derive(Clone, Debug)]
pub struct RecoveryCandidate {
    pub bundle: EncryptedRecoveryBundle,
    pub metadata: RecoveryMetadata,
}

#[async_trait]
pub trait RecoverySink: Send {
    async fn load_candidates(&mut self) -> Result<Vec<RecoveryCandidate>, RecoveryError>;

    async fn publish(
        &mut self,
        operation: RecoveryPublication,
        bundle: EncryptedRecoveryBundle,
        metadata: RecoveryMetadata,
    ) -> Result<DurableReceipt, RecoveryError>;
}
