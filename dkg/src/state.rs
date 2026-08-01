//! Persistent storage for DKG protocol state.
//!
//! Stores epoch state using key-value metadata storage and per-epoch messages
//! (dealer broadcasts, player acks, logs) using append-only journals for crash recovery.
//! In-memory BTreeMaps provide fast lookups while storage ensures durability.
//!
use crate::protector::{ProtectionError, SealedRecord, StorageProtector, NONCE_SIZE};
use crate::{
    public::PublicCheckpoint,
    recovery::{
        DkgRecoveryBundle, RecipientState, RecoveryDealer, RecoveryDealing, RecoveryEpoch,
        RecoveryEpochState, RecoveryError, RecoveryImportPhase, RecoveryImportTransaction,
        RECOVERY_FORMAT_VERSION, RECOVERY_IMPORT_VERSION,
    },
};
use bytes::Bytes;
use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::types::Epoch as EpochNum;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{
            Dealer as CryptoDealer, DealerLog, DealerPrivMsg, DealerPubMsg, Info, Logs, Output,
            Player as CryptoPlayer, PlayerAck, SignedDealerLog, Verdict,
        },
        primitives::{group::Share, sharing::ModeVersion, variant::Variant},
    },
    sha256::{Digest, Sha256},
    transcript::{Summary, Transcript},
    BatchVerifier, Hasher, PublicKey, Signer,
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef, Buf, BufMut, BufferPooler, Clock, Metrics, Storage as RuntimeStorage,
};
use commonware_storage::{
    journal::{
        self,
        segmented::variable::{Config as SVConfig, Journal as SVJournal},
    },
    metadata::{self, Config as MetadataConfig, Metadata},
};
use commonware_utils::{Faults, NZUsize, NZU16};
use futures::StreamExt;
use rand::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
};
use tracing::{debug, error, warn};

// Configure 32MB page cache
const PAGE_SIZE: NonZeroU16 = NZU16!(1 << 12);
const PAGE_CACHE_CAPACITY: NonZeroUsize = NZUsize!(1 << 13);

const WRITE_BUFFER: NonZeroUsize = NZUsize!(1 << 12);
const READ_BUFFER: NonZeroUsize = NZUsize!(1 << 20);

const RECORD_AD_DOMAIN: &[u8] = b"nunchi-dkg-storage";
const RECORD_KIND_EPOCH: u8 = 0;
const RECORD_KIND_EVENT: u8 = 1;
const RECORD_KIND_LOCAL_DEALER: u8 = 2;
const RECORD_KIND_RECOVERY_IMPORT: u8 = 3;
const RECONCILIATION_KEY: u8 = 0;
const RECOVERY_IMPORT_KEY: u8 = 0;

/// Read-only classification of all DKG-owned primary partitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageInspection {
    Empty,
    Coherent,
    Partial,
    Importing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SealedImportRecord {
    target_epoch: EpochNum,
    checkpoint_digest: Digest,
    sealed: SealedRecord,
}

impl EncodeSize for SealedImportRecord {
    fn encode_size(&self) -> usize {
        self.target_epoch.encode_size()
            + self.checkpoint_digest.encode_size()
            + self.sealed.encode_size()
    }
}

impl Write for SealedImportRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.target_epoch.write(buf);
        self.checkpoint_digest.write(buf);
        self.sealed.write(buf);
    }
}

impl Read for SealedImportRecord {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            target_epoch: ReadExt::read(buf)?,
            checkpoint_digest: ReadExt::read(buf)?,
            sealed: SealedRecord::read_cfg(buf, cfg)?,
        })
    }
}

/// Error returned when resuming a player from protected storage.
#[derive(Debug, thiserror::Error)]
pub enum CreatePlayerError {
    /// Public dealer logs are present, but matching private dealer messages are not.
    #[error("missing private player dealing")]
    MissingPlayerDealing,
    /// The crypto player could not be resumed from the persisted state.
    #[error("failed to resume DKG player: {0}")]
    Crypto(commonware_cryptography::bls12381::dkg::feldman_desmedt::Error),
    /// The exact persisted acknowledgement is missing, malformed, or conflicts.
    #[error("persisted player acknowledgement is invalid")]
    PersistedAcknowledgement,
}

/// Error returned when creating or resuming the exact local dealer.
#[derive(Debug, thiserror::Error)]
pub enum CreateDealerError {
    #[error("protected DKG storage error: {0}")]
    Storage(#[from] Error),
    #[error("failed to create DKG dealer: {0}")]
    Crypto(commonware_cryptography::bls12381::dkg::feldman_desmedt::Error),
    #[error("persisted local dealer does not match reconstructed cryptographic state")]
    StateMismatch,
    #[error("persisted signed dealer log is invalid")]
    InvalidSignedLog,
}

/// Result of inserting a value at a logical key that must never change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExactInsert {
    /// No prior value existed and the value was durably inserted.
    Inserted,
    /// The exact canonical value was already present.
    Identical,
    /// The key was already bound to a different value.
    Conflict,
}

/// Durable authenticated-state import phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationPhase {
    Importing,
    Complete,
}

impl EncodeSize for ReconciliationPhase {
    fn encode_size(&self) -> usize {
        1
    }
}

impl Write for ReconciliationPhase {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Importing => 0u8.write(buf),
            Self::Complete => 1u8.write(buf),
        }
    }
}

impl Read for ReconciliationPhase {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Importing),
            1 => Ok(Self::Complete),
            other => Err(CodecError::InvalidEnum(other)),
        }
    }
}

/// Crash-recovery marker for an authenticated checkpoint import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reconciliation {
    pub format_version: u16,
    pub checkpoint_digest: Digest,
    pub target_epoch: EpochNum,
    pub phase: ReconciliationPhase,
}

impl EncodeSize for Reconciliation {
    fn encode_size(&self) -> usize {
        self.format_version.encode_size()
            + self.checkpoint_digest.encode_size()
            + self.target_epoch.encode_size()
            + self.phase.encode_size()
    }
}

impl Write for Reconciliation {
    fn write(&self, buf: &mut impl BufMut) {
        self.format_version.write(buf);
        self.checkpoint_digest.write(buf);
        self.target_epoch.write(buf);
        self.phase.write(buf);
    }
}

impl Read for Reconciliation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            format_version: ReadExt::read(buf)?,
            checkpoint_digest: ReadExt::read(buf)?,
            target_epoch: ReadExt::read(buf)?,
            phase: ReadExt::read(buf)?,
        })
    }
}

/// Errors returned by DKG persistent storage.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("metadata storage error: {0}")]
    Metadata(#[from] metadata::Error),
    #[error("journal storage error: {0}")]
    Journal(#[from] journal::Error),
    #[error("record protection error: {0}")]
    Protection(#[from] ProtectionError),
    #[error("record decode error: {0}")]
    Decode(#[from] CodecError),
    #[error("decoded record has trailing bytes")]
    TrailingBytes,
    #[error("missing epoch state for key: {0}")]
    MissingEpochState(u64),
    #[error("conflicting records for epoch {epoch}, record kind {kind}")]
    ConflictingRecord { epoch: u64, kind: &'static str },
}

/// Epoch-level DKG state persisted across restarts.
#[derive(Clone)]
pub struct Epoch<V: Variant, P: PublicKey> {
    pub round: u64,
    pub rng_seed: Summary,
    pub output: Option<Output<V, P>>,
    pub share: Option<Share>,
}

impl<V: Variant, P: PublicKey> EncodeSize for Epoch<V, P> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.rng_seed.encode_size()
            + self.output.encode_size()
            + self.share.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for Epoch<V, P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.rng_seed.write(buf);
        self.output.write(buf);
        self.share.write(buf);
    }
}

impl<V, P> Read for Epoch<V, P>
where
    V: Variant,
    P: PublicKey,
{
    type Cfg = (NonZeroU32, ModeVersion);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            round: ReadExt::read(buf)?,
            rng_seed: ReadExt::read(buf)?,
            output: Read::read_cfg(buf, cfg)?,
            share: ReadExt::read(buf)?,
        })
    }
}

/// An event we want to record to replay later, if we crash.
enum Event<V: Variant, P: PublicKey> {
    /// A dealer message we received and committed to ack (as a player).
    /// Once persisted, we will always generate the same ack for this dealer.
    Dealing(P, DealerPubMsg<V>, DealerPrivMsg, Bytes),
    /// A player ack we received (as a dealer).
    Ack(P, PlayerAck<P>),
    /// A finalized dealer log.
    Log(P, DealerLog<V, P>),
}

impl<V: Variant, P: PublicKey> EncodeSize for Event<V, P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealing(x0, x1, x2, x3) => {
                x0.encode_size() + x1.encode_size() + x2.encode_size() + x3.encode_size()
            }
            Self::Ack(x0, x1) => x0.encode_size() + x1.encode_size(),
            Self::Log(x0, x1) => x0.encode_size() + x1.encode_size(),
        }
    }
}

impl<V: Variant, P: PublicKey> Write for Event<V, P> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Dealing(x0, x1, x2, x3) => {
                0u8.write(buf);
                x0.write(buf);
                x1.write(buf);
                x2.write(buf);
                x3.write(buf);
            }
            Self::Ack(x0, x1) => {
                1u8.write(buf);
                x0.write(buf);
                x1.write(buf);
            }
            Self::Log(x0, x1) => {
                2u8.write(buf);
                x0.write(buf);
                x1.write(buf);
            }
        }
    }
}

impl<V: Variant, P: PublicKey> Read for Event<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Dealing(
                ReadExt::read(buf)?,
                Read::read_cfg(buf, cfg)?,
                ReadExt::read(buf)?,
                Bytes::read_cfg(buf, &RangeCfg::from(1..=1024))?,
            )),
            1 => Ok(Self::Ack(ReadExt::read(buf)?, ReadExt::read(buf)?)),
            2 => Ok(Self::Log(ReadExt::read(buf)?, Read::read_cfg(buf, cfg)?)),
            other => Err(commonware_codec::Error::InvalidEnum(other)),
        }
    }
}

/// In-memory cache for a single epoch's DKG messages.
struct EpochCache<V: Variant, P: PublicKey> {
    dealings: BTreeMap<P, (DealerPubMsg<V>, DealerPrivMsg, Bytes)>,
    acks: BTreeMap<P, PlayerAck<P>>,
    logs: BTreeMap<P, DealerLog<V, P>>,
}

impl<V: Variant, P: PublicKey> Default for EpochCache<V, P> {
    fn default() -> Self {
        Self {
            dealings: BTreeMap::new(),
            acks: BTreeMap::new(),
            logs: BTreeMap::new(),
        }
    }
}

/// DKG persistent storage.
///
/// Wraps metadata storage for epoch state and journaled storage for protocol messages,
/// with in-memory BTreeMaps for fast lookups. Using metadata with epoch keys eliminates
/// the position/epoch confusion that can occur with position-based journals.
pub struct Storage<E, V, P>
where
    E: BufferPooler + Clock + RuntimeStorage + Metrics + CryptoRng,
    V: Variant,
    P: PublicKey,
{
    context: E,
    protector: StorageProtector,
    partition_prefix: String,
    namespace: Vec<u8>,
    public_key: P,

    states: Metadata<E, u64, SealedRecord>,
    reconciliation: Metadata<E, u8, Reconciliation>,
    local_dealer_records: Metadata<E, u64, SealedRecord>,
    recovery_import: Metadata<E, u8, SealedImportRecord>,
    msgs: SVJournal<E, SealedRecord>,

    // In-memory state
    current: Option<(EpochNum, Epoch<V, P>)>,
    epochs: BTreeMap<EpochNum, EpochCache<V, P>>,
    local_dealers: BTreeMap<EpochNum, RecoveryDealer<V, P>>,
    import_transaction: Option<RecoveryImportTransaction>,
}

impl<E, V, P> Storage<E, V, P>
where
    E: BufferPooler + Clock + RuntimeStorage + Metrics + CryptoRng,
    V: Variant,
    P: PublicKey,
{
    /// Initialize storage, creating partitions if needed.
    /// Replays metadata and journals to populate in-memory caches.
    pub async fn init(
        context: E,
        partition_prefix: &str,
        protector: StorageProtector,
        namespace: Vec<u8>,
        public_key: P,
        max_read_size: NonZeroU32,
        max_supported_mode: ModeVersion,
    ) -> Result<Self, Error> {
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_CAPACITY);

        let states: Metadata<E, u64, SealedRecord> = Metadata::init(
            context.child("states"),
            MetadataConfig {
                partition: format!("{partition_prefix}_states"),
                codec_config: RangeCfg::from(..),
            },
        )
        .await?;
        let reconciliation = Metadata::init(
            context.child("reconciliation"),
            MetadataConfig {
                partition: format!("{partition_prefix}_reconciliation"),
                codec_config: (),
            },
        )
        .await?;
        let local_dealer_records = Metadata::init(
            context.child("local_dealer"),
            MetadataConfig {
                partition: format!("{partition_prefix}_local_dealer"),
                codec_config: RangeCfg::from(..),
            },
        )
        .await?;
        let recovery_import = Metadata::init(
            context.child("recovery_import"),
            MetadataConfig {
                partition: format!("{partition_prefix}_recovery_import"),
                codec_config: RangeCfg::from(..),
            },
        )
        .await?;

        let mut msgs = SVJournal::init(
            context.child("msgs"),
            SVConfig {
                partition: format!("{partition_prefix}_msgs"),
                compression: None,
                codec_config: RangeCfg::from(..),
                page_cache,
                write_buffer: WRITE_BUFFER,
            },
        )
        .await?;

        // Find the current epoch by looking for the highest key in metadata.
        let partition_prefix = partition_prefix.to_owned();
        let current = if let Some(&epoch_num) = states.keys().max() {
            let record = states
                .get(&epoch_num)
                .ok_or(Error::MissingEpochState(epoch_num))?;
            let state = Self::open_epoch_record(
                &protector,
                &partition_prefix,
                &namespace,
                &public_key,
                (max_read_size, max_supported_mode),
                EpochNum::new(epoch_num),
                record,
            )?;
            Some((EpochNum::new(epoch_num), state))
        } else {
            None
        };

        let mut local_dealers = BTreeMap::new();
        for &epoch_num in local_dealer_records.keys() {
            let epoch = EpochNum::new(epoch_num);
            let record = local_dealer_records
                .get(&epoch_num)
                .ok_or(Error::MissingEpochState(epoch_num))?;
            let dealer = Self::open_local_dealer_record(
                &protector,
                &partition_prefix,
                &namespace,
                &public_key,
                max_read_size,
                epoch,
                record,
            )?;
            local_dealers.insert(epoch, dealer);
        }

        let import_transaction = recovery_import
            .get(&RECOVERY_IMPORT_KEY)
            .map(|record| {
                Self::open_import_record(
                    &protector,
                    &partition_prefix,
                    &namespace,
                    &public_key,
                    record,
                )
            })
            .transpose()?;

        // Replay msgs to populate epoch caches
        let mut epochs = BTreeMap::<EpochNum, EpochCache<V, P>>::new();
        {
            let replay = msgs.replay(0, 0, READ_BUFFER).await?;
            futures::pin_mut!(replay);

            while let Some(result) = replay.next().await {
                let (section, _, _, record) = result?;
                let epoch = EpochNum::new(section);
                let event = Self::open_event_record(
                    &protector,
                    &partition_prefix,
                    &namespace,
                    &public_key,
                    max_read_size,
                    epoch,
                    &record,
                )?;
                let cache = epochs.entry(epoch).or_default();
                match event {
                    Event::Dealing(dealer, pub_msg, priv_msg, acknowledgement) => {
                        if cache
                            .dealings
                            .insert(
                                dealer,
                                (pub_msg.clone(), priv_msg.clone(), acknowledgement.clone()),
                            )
                            .is_some_and(|existing| {
                                existing != (pub_msg, priv_msg, acknowledgement)
                            })
                        {
                            return Err(Error::ConflictingRecord {
                                epoch: epoch.get(),
                                kind: "dealing",
                            });
                        }
                    }
                    Event::Ack(player, ack) => {
                        if cache
                            .acks
                            .insert(player, ack.clone())
                            .is_some_and(|existing| existing != ack)
                        {
                            return Err(Error::ConflictingRecord {
                                epoch: epoch.get(),
                                kind: "acknowledgement",
                            });
                        }
                    }
                    Event::Log(dealer, log) => {
                        if cache
                            .logs
                            .insert(dealer, log.clone())
                            .is_some_and(|existing| existing != log)
                        {
                            return Err(Error::ConflictingRecord {
                                epoch: epoch.get(),
                                kind: "dealer log",
                            });
                        }
                    }
                }
            }
        }

        Ok(Self {
            context,
            protector,
            partition_prefix,
            namespace,
            public_key,
            states,
            reconciliation,
            local_dealer_records,
            recovery_import,
            msgs,
            current,
            epochs,
            local_dealers,
            import_transaction,
        })
    }

    fn associated_data(
        partition_prefix: &str,
        namespace: &[u8],
        public_key: &P,
        kind: u8,
        epoch: EpochNum,
    ) -> Vec<u8> {
        fn append_bytes(out: &mut Vec<u8>, value: &[u8]) {
            out.extend_from_slice(&(value.len() as u64).to_be_bytes());
            out.extend_from_slice(value);
        }

        let public_key = public_key.encode();
        let mut ad = Vec::with_capacity(
            RECORD_AD_DOMAIN.len() + 1 + 8 + partition_prefix.len() + namespace.len() + public_key.len(),
        );
        append_bytes(&mut ad, RECORD_AD_DOMAIN);
        ad.push(kind);
        append_bytes(&mut ad, partition_prefix.as_bytes());
        append_bytes(&mut ad, namespace);
        append_bytes(&mut ad, &public_key);
        ad.extend_from_slice(&epoch.get().to_be_bytes());
        ad
    }

    fn open_epoch_record(
        protector: &StorageProtector,
        partition_prefix: &str,
        namespace: &[u8],
        public_key: &P,
        cfg: (NonZeroU32, ModeVersion),
        epoch: EpochNum,
        record: &SealedRecord,
    ) -> Result<Epoch<V, P>, Error> {
        let ad = Self::associated_data(
            partition_prefix,
            namespace,
            public_key,
            RECORD_KIND_EPOCH,
            epoch,
        );
        let plaintext = protector.open(record, &ad)?;
        let mut buf = plaintext.as_ref();
        let state = Epoch::read_cfg(&mut buf, &cfg)?;
        if buf.has_remaining() {
            return Err(Error::TrailingBytes);
        }
        Ok(state)
    }

    fn open_event_record(
        protector: &StorageProtector,
        partition_prefix: &str,
        namespace: &[u8],
        public_key: &P,
        max_read_size: NonZeroU32,
        epoch: EpochNum,
        record: &SealedRecord,
    ) -> Result<Event<V, P>, Error> {
        let ad = Self::associated_data(
            partition_prefix,
            namespace,
            public_key,
            RECORD_KIND_EVENT,
            epoch,
        );
        let plaintext = protector.open(record, &ad)?;
        let mut buf = plaintext.as_ref();
        let event = Event::read_cfg(&mut buf, &max_read_size)?;
        if buf.has_remaining() {
            return Err(Error::TrailingBytes);
        }
        Ok(event)
    }

    fn open_local_dealer_record(
        protector: &StorageProtector,
        partition_prefix: &str,
        namespace: &[u8],
        public_key: &P,
        max_read_size: NonZeroU32,
        epoch: EpochNum,
        record: &SealedRecord,
    ) -> Result<RecoveryDealer<V, P>, Error> {
        let ad = Self::associated_data(
            partition_prefix,
            namespace,
            public_key,
            RECORD_KIND_LOCAL_DEALER,
            epoch,
        );
        let plaintext = protector.open(record, &ad)?;
        let mut buf = plaintext.as_ref();
        let dealer = RecoveryDealer::read_cfg(
            &mut buf,
            &(max_read_size, crate::recovery::MAX_SIGNED_LOG_LEN),
        )?;
        if buf.has_remaining() {
            return Err(Error::TrailingBytes);
        }
        Ok(dealer)
    }

    fn import_associated_data(
        partition_prefix: &str,
        namespace: &[u8],
        public_key: &P,
        target_epoch: EpochNum,
        checkpoint_digest: &Digest,
    ) -> Vec<u8> {
        let mut ad = Self::associated_data(
            partition_prefix,
            namespace,
            public_key,
            RECORD_KIND_RECOVERY_IMPORT,
            target_epoch,
        );
        ad.extend_from_slice(&checkpoint_digest.0);
        ad
    }

    fn open_import_record(
        protector: &StorageProtector,
        partition_prefix: &str,
        namespace: &[u8],
        public_key: &P,
        record: &SealedImportRecord,
    ) -> Result<RecoveryImportTransaction, Error> {
        let ad = Self::import_associated_data(
            partition_prefix,
            namespace,
            public_key,
            record.target_epoch,
            &record.checkpoint_digest,
        );
        let plaintext = protector.open(&record.sealed, &ad)?;
        let mut input = plaintext.as_ref();
        let transaction = RecoveryImportTransaction::read(&mut input)?;
        if input.has_remaining() {
            return Err(Error::TrailingBytes);
        }
        if transaction.target_epoch != record.target_epoch
            || transaction.checkpoint_digest != record.checkpoint_digest
        {
            return Err(Error::ConflictingRecord {
                epoch: record.target_epoch.get(),
                kind: "recovery import",
            });
        }
        Ok(transaction)
    }

    fn seal_record(
        &mut self,
        kind: u8,
        epoch: EpochNum,
        plaintext: &[u8],
    ) -> Result<SealedRecord, Error> {
        let mut nonce = [0u8; NONCE_SIZE];
        self.context.fill_bytes(&mut nonce);
        let ad = Self::associated_data(
            &self.partition_prefix,
            &self.namespace,
            &self.public_key,
            kind,
            epoch,
        );
        Ok(self.protector.seal(plaintext, &ad, nonce)?)
    }

    fn seal_import_record(
        &mut self,
        transaction: &RecoveryImportTransaction,
    ) -> Result<SealedImportRecord, Error> {
        let mut nonce = [0u8; NONCE_SIZE];
        self.context.fill_bytes(&mut nonce);
        let ad = Self::import_associated_data(
            &self.partition_prefix,
            &self.namespace,
            &self.public_key,
            transaction.target_epoch,
            &transaction.checkpoint_digest,
        );
        Ok(SealedImportRecord {
            target_epoch: transaction.target_epoch,
            checkpoint_digest: transaction.checkpoint_digest,
            sealed: self.protector.seal(&transaction.encode(), &ad, nonce)?,
        })
    }

    /// Returns all dealer messages received during the given epoch.
    pub fn dealings(&self, epoch: EpochNum) -> Vec<(P, DealerPubMsg<V>, DealerPrivMsg)> {
        self.epochs
            .get(&epoch)
            .map(|cache| {
                cache
                    .dealings
                    .iter()
                    .map(|(k, (v1, v2, _))| (k.clone(), v1.clone(), v2.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all player acknowledgments received during the given epoch.
    pub fn acks(&self, epoch: EpochNum) -> Vec<(P, PlayerAck<P>)> {
        self.epochs
            .get(&epoch)
            .map(|cache| {
                cache
                    .acks
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all finalized dealer logs for the given epoch.
    pub fn logs(&self, epoch: EpochNum) -> BTreeMap<P, DealerLog<V, P>> {
        self.epochs
            .get(&epoch)
            .map(|cache| cache.logs.clone())
            .unwrap_or_default()
    }

    /// Checks if a dealer has already submitted a log this epoch.
    pub fn has_log(&self, epoch: EpochNum, dealer: &P) -> bool {
        self.epochs
            .get(&epoch)
            .map(|cache| cache.logs.contains_key(dealer))
            .unwrap_or(false)
    }

    /// Returns the current epoch state, if initialized.
    pub fn epoch(&self) -> Option<(EpochNum, Epoch<V, P>)> {
        self.current.as_ref().map(|(e, s)| (*e, s.clone()))
    }

    /// Return the durable authenticated-state reconciliation marker.
    pub fn reconciliation(&self) -> Option<Reconciliation> {
        self.reconciliation.get(&RECONCILIATION_KEY).cloned()
    }

    /// Inspect all DKG-owned logical partitions without mutating them.
    pub fn inspect(&self) -> StorageInspection {
        if self
            .import_transaction
            .as_ref()
            .is_some_and(|transaction| transaction.phase == RecoveryImportPhase::Importing)
        {
            return StorageInspection::Importing;
        }
        let no_primary = self.current.is_none()
            && self.epochs.is_empty()
            && self.local_dealers.is_empty()
            && self.reconciliation().is_none();
        if no_primary && self.import_transaction.is_none() {
            return StorageInspection::Empty;
        }
        let Some((current_epoch, _)) = self.current.as_ref() else {
            return StorageInspection::Partial;
        };
        if self
            .epochs
            .keys()
            .chain(self.local_dealers.keys())
            .any(|epoch| epoch > current_epoch)
            || self
                .reconciliation()
                .is_some_and(|marker| marker.phase == ReconciliationPhase::Importing)
        {
            return StorageInspection::Partial;
        }
        StorageInspection::Coherent
    }

    /// Verify that a completed recovery transaction still replays to its exact
    /// canonical logical state before treating it as normal primary storage.
    pub fn validate_complete_import(
        &self,
        checkpoint: &PublicCheckpoint<V, P>,
    ) -> Result<(), RecoveryError> {
        let Some(transaction) = self.import_transaction.as_ref() else {
            return Ok(());
        };
        if transaction.phase != RecoveryImportPhase::Complete {
            return Err(RecoveryError::ImportIncomplete);
        }
        if transaction.target_epoch != checkpoint.epoch
            || transaction.checkpoint_digest != Sha256::hash(&checkpoint.encode())
        {
            return Err(RecoveryError::ImportConflict);
        }
        let replay = self.recovery_bundle(checkpoint.clone(), 0)?;
        if Self::logical_state_digest(&replay) != transaction.logical_state_digest {
            return Err(RecoveryError::ImportConflict);
        }
        Ok(())
    }

    /// Return the exact persisted local dealer state for an epoch.
    pub fn local_dealer(&self, epoch: EpochNum) -> Option<RecoveryDealer<V, P>> {
        self.local_dealers.get(&epoch).cloned()
    }

    /// Persist all local dealer output as one immutable active record.
    pub async fn initialize_local_dealer(
        &mut self,
        epoch: EpochNum,
        public_message: DealerPubMsg<V>,
        private_messages: impl IntoIterator<Item = (P, DealerPrivMsg)>,
    ) -> Result<ExactInsert, Error> {
        let mut canonical = BTreeMap::new();
        for (player, private_message) in private_messages {
            if canonical.insert(player, private_message).is_some() {
                return Ok(ExactInsert::Conflict);
            }
        }
        let recipients = canonical
            .into_iter()
            .map(|(player, private_message)| RecipientState::Unacknowledged {
                player,
                private_message,
            })
            .collect::<Vec<_>>();
        let value = RecoveryDealer::Active {
            public_message,
            recipients,
        };
        if let Some(existing) = self.local_dealers.get(&epoch) {
            return Ok(if existing == &value {
                ExactInsert::Identical
            } else {
                ExactInsert::Conflict
            });
        }
        let record = self.seal_record(RECORD_KIND_LOCAL_DEALER, epoch, &value.encode())?;
        self.local_dealer_records.put(epoch.get(), record);
        self.local_dealer_records.sync().await?;
        self.local_dealers.insert(epoch, value);
        Ok(ExactInsert::Inserted)
    }

    /// Transition one exact local recipient from unacknowledged to acknowledged.
    pub async fn acknowledge_local_recipient(
        &mut self,
        epoch: EpochNum,
        player: P,
        ack: PlayerAck<P>,
    ) -> Result<ExactInsert, Error> {
        let Some(existing) = self.local_dealers.get(&epoch) else {
            return Ok(ExactInsert::Conflict);
        };
        let RecoveryDealer::Active {
            public_message,
            recipients,
        } = existing
        else {
            return Ok(ExactInsert::Conflict);
        };
        let mut updated = recipients.clone();
        let Some(recipient) = updated.iter_mut().find(|recipient| match recipient {
            RecipientState::Unacknowledged { player: candidate, .. }
            | RecipientState::Acknowledged { player: candidate, .. } => candidate == &player,
        }) else {
            return Ok(ExactInsert::Conflict);
        };
        match recipient {
            RecipientState::Acknowledged { ack: existing, .. } => {
                return Ok(if existing == &ack {
                    ExactInsert::Identical
                } else {
                    ExactInsert::Conflict
                });
            }
            RecipientState::Unacknowledged {
                player,
                private_message,
            } => {
                *recipient = RecipientState::Acknowledged {
                    player: player.clone(),
                    private_message: private_message.clone(),
                    ack,
                };
            }
        }
        let value = RecoveryDealer::Active {
            public_message: public_message.clone(),
            recipients: updated,
        };
        let record = self.seal_record(RECORD_KIND_LOCAL_DEALER, epoch, &value.encode())?;
        self.local_dealer_records.put(epoch.get(), record);
        self.local_dealer_records.sync().await?;
        self.local_dealers.insert(epoch, value);
        Ok(ExactInsert::Inserted)
    }

    /// Finalize a local dealer once while retaining the exact signed bytes.
    pub async fn finalize_local_dealer(
        &mut self,
        epoch: EpochNum,
        signed_log: Bytes,
    ) -> Result<ExactInsert, Error> {
        let Some(existing) = self.local_dealers.get(&epoch) else {
            return Ok(ExactInsert::Conflict);
        };
        let value = match existing {
            RecoveryDealer::Active {
                public_message,
                recipients,
            } => RecoveryDealer::Finalized {
                public_message: public_message.clone(),
                recipients: recipients.clone(),
                signed_log,
            },
            RecoveryDealer::Finalized {
                signed_log: existing,
                ..
            } => {
                return Ok(if existing == &signed_log {
                    ExactInsert::Identical
                } else {
                    ExactInsert::Conflict
                });
            }
        };
        let record = self.seal_record(RECORD_KIND_LOCAL_DEALER, epoch, &value.encode())?;
        self.local_dealer_records.put(epoch.get(), record);
        self.local_dealer_records.sync().await?;
        self.local_dealers.insert(epoch, value);
        Ok(ExactInsert::Inserted)
    }

    async fn insert_local_dealer_exact(
        &mut self,
        epoch: EpochNum,
        value: RecoveryDealer<V, P>,
    ) -> Result<ExactInsert, Error> {
        if let Some(existing) = self.local_dealers.get(&epoch) {
            return Ok(if existing == &value {
                ExactInsert::Identical
            } else {
                ExactInsert::Conflict
            });
        }
        let record = self.seal_record(RECORD_KIND_LOCAL_DEALER, epoch, &value.encode())?;
        self.local_dealer_records.put(epoch.get(), record);
        self.local_dealer_records.sync().await?;
        self.local_dealers.insert(epoch, value);
        Ok(ExactInsert::Inserted)
    }

    async fn set_import_transaction(
        &mut self,
        transaction: RecoveryImportTransaction,
    ) -> Result<(), Error> {
        let sealed = self.seal_import_record(&transaction)?;
        self.recovery_import.put(RECOVERY_IMPORT_KEY, sealed);
        self.recovery_import.sync().await?;
        self.import_transaction = Some(transaction);
        Ok(())
    }

    fn logical_state_digest(bundle: &DkgRecoveryBundle<V, P>) -> Digest {
        let mut canonical = bundle.clone();
        canonical.created_at_ms = 0;
        Sha256::hash(&canonical.encode())
    }

    /// Validate and transactionally import a logical bundle into empty storage.
    ///
    /// A v1 `Importing` marker is never resumed. A completed transaction is
    /// idempotent only when replay produces the same canonical logical digest.
    pub async fn import_recovery_bundle(
        &mut self,
        bundle: DkgRecoveryBundle<V, P>,
        authenticated: &PublicCheckpoint<V, P>,
        bundle_digest: Digest,
    ) -> Result<(), RecoveryError> {
        bundle.validate_canonical()?;
        if &bundle.checkpoint != authenticated
            || bundle.checkpoint_digest != Sha256::hash(&authenticated.encode())
        {
            return Err(RecoveryError::Checkpoint);
        }
        if bundle.validator != self.public_key
            || bundle.namespace_digest != Sha256::hash(&self.namespace)
            || bundle.partition_prefix != self.partition_prefix
        {
            return Err(RecoveryError::Identity("storage"));
        }
        if bundle.epoch_state.output.as_ref() != Some(&authenticated.output) {
            return Err(RecoveryError::Checkpoint);
        }
        match bundle.epoch_state.share.as_ref() {
            Some(share) => crate::validate_share(&authenticated.output, &self.public_key, share)
                .map_err(|_| RecoveryError::Share)?,
            None if authenticated.output.players().position(&self.public_key).is_some() => {
                return Err(RecoveryError::Share);
            }
            None => {}
        }

        let logical_state_digest = Self::logical_state_digest(&bundle);
        if let Some(transaction) = self.import_transaction.as_ref() {
            if transaction.phase == RecoveryImportPhase::Importing {
                return Err(RecoveryError::ImportIncomplete);
            }
            if transaction.target_epoch != authenticated.epoch
                || transaction.checkpoint_digest != bundle.checkpoint_digest
                || transaction.logical_state_digest != logical_state_digest
            {
                return Err(RecoveryError::ImportConflict);
            }
            let replay = self.recovery_bundle(authenticated.clone(), 0)?;
            if Self::logical_state_digest(&replay) != logical_state_digest {
                return Err(RecoveryError::ImportConflict);
            }
            return Ok(());
        }
        if self.inspect() != StorageInspection::Empty {
            return Err(RecoveryError::ImportConflict);
        }

        let importing = RecoveryImportTransaction {
            format_version: RECOVERY_IMPORT_VERSION,
            bundle_digest,
            logical_state_digest,
            checkpoint_digest: bundle.checkpoint_digest,
            target_epoch: authenticated.epoch,
            phase: RecoveryImportPhase::Importing,
        };
        self.set_import_transaction(importing.clone())
            .await
            .map_err(|_| RecoveryError::ImportIncomplete)?;

        self.set_epoch(
            bundle.epoch_state.epoch,
            Epoch {
                round: bundle.epoch_state.round,
                rng_seed: bundle.epoch_state.rng_seed,
                output: bundle.epoch_state.output.clone(),
                share: bundle.epoch_state.share.clone(),
            },
        )
        .await
        .map_err(|_| RecoveryError::ImportIncomplete)?;
        for epoch in &bundle.epochs {
            for dealing in &epoch.dealings {
                if self
                    .append_dealing(
                        epoch.epoch,
                        dealing.dealer.clone(),
                        dealing.public_message.clone(),
                        dealing.private_message.clone(),
                        dealing.acknowledgement.clone(),
                    )
                    .await
                    .map_err(|_| RecoveryError::ImportIncomplete)?
                    == ExactInsert::Conflict
                {
                    return Err(RecoveryError::ImportConflict);
                }
            }
            for (dealer, log) in &epoch.logs {
                if self
                    .append_log(epoch.epoch, dealer.clone(), log.clone())
                    .await
                    .map_err(|_| RecoveryError::ImportIncomplete)?
                    == ExactInsert::Conflict
                {
                    return Err(RecoveryError::ImportConflict);
                }
            }
            if let Some(local_dealer) = epoch.local_dealer.clone() {
                if self
                    .insert_local_dealer_exact(epoch.epoch, local_dealer)
                    .await
                    .map_err(|_| RecoveryError::ImportIncomplete)?
                    == ExactInsert::Conflict
                {
                    return Err(RecoveryError::ImportConflict);
                }
            }
        }
        if let Some(reconciliation) = bundle.reconciliation.clone() {
            self.set_reconciliation(reconciliation)
                .await
                .map_err(|_| RecoveryError::ImportIncomplete)?;
        }

        let replay = self.recovery_bundle(authenticated.clone(), 0)?;
        if Self::logical_state_digest(&replay) != logical_state_digest {
            return Err(RecoveryError::ImportConflict);
        }
        self.set_import_transaction(RecoveryImportTransaction {
            phase: RecoveryImportPhase::Complete,
            ..importing
        })
        .await
        .map_err(|_| RecoveryError::ImportIncomplete)?;
        Ok(())
    }

    /// Build a canonical logical recovery snapshot from the decoded actor view.
    pub fn recovery_bundle(
        &self,
        checkpoint: PublicCheckpoint<V, P>,
        created_at_ms: u64,
    ) -> Result<DkgRecoveryBundle<V, P>, RecoveryError> {
        let (epoch, state) = self.current.as_ref().ok_or(RecoveryError::Epoch)?;
        if *epoch != checkpoint.epoch
            || state.round != checkpoint.successful_round
            || state.output.as_ref() != Some(&checkpoint.output)
        {
            return Err(RecoveryError::Checkpoint);
        }

        let retained_epochs = self
            .epochs
            .keys()
            .chain(self.local_dealers.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        let epochs = retained_epochs
            .into_iter()
            .map(|epoch| RecoveryEpoch {
                epoch,
                dealings: self.epochs.get(&epoch).map(|cache| cache
                    .dealings
                    .iter()
                    .map(|(dealer, (public, private, acknowledgement))| RecoveryDealing {
                        dealer: dealer.clone(),
                        public_message: public.clone(),
                        private_message: private.clone(),
                        acknowledgement: acknowledgement.clone(),
                    })
                    .collect()).unwrap_or_default(),
                logs: self.epochs.get(&epoch).map(|cache| cache
                    .logs
                    .iter()
                    .map(|(dealer, log)| (dealer.clone(), log.clone()))
                    .collect()).unwrap_or_default(),
                local_dealer: self.local_dealers.get(&epoch).cloned(),
            })
            .collect();
        let checkpoint_digest = Sha256::hash(&checkpoint.encode());
        let bundle = DkgRecoveryBundle {
            format_version: RECOVERY_FORMAT_VERSION,
            protocol_config_digest: checkpoint.protocol_config_digest,
            namespace_digest: Sha256::hash(&self.namespace),
            validator: self.public_key.clone(),
            partition_prefix: self.partition_prefix.clone(),
            checkpoint,
            checkpoint_digest,
            created_at_ms,
            epoch_state: RecoveryEpochState {
                epoch: *epoch,
                round: state.round,
                rng_seed: state.rng_seed,
                output: state.output.clone(),
                share: state.share.clone(),
            },
            reconciliation: self.reconciliation(),
            epochs,
        };
        bundle.validate_canonical()?;
        Ok(bundle)
    }

    /// Persist and sync an authenticated-state reconciliation phase.
    pub async fn set_reconciliation(
        &mut self,
        reconciliation: Reconciliation,
    ) -> Result<(), Error> {
        self.reconciliation
            .put(RECONCILIATION_KEY, reconciliation);
        self.reconciliation.sync().await?;
        Ok(())
    }

    fn get_or_create_epoch(&mut self, epoch: EpochNum) -> &mut EpochCache<V, P> {
        self.epochs.entry(epoch).or_default()
    }

    /// Persists a dealer message for crash recovery.
    /// Reports whether the exact dealing was inserted, already present, or conflicts.
    pub async fn append_dealing(
        &mut self,
        epoch: EpochNum,
        dealer: P,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
        acknowledgement: Bytes,
    ) -> Result<ExactInsert, Error> {
        if let Some(existing) = self
            .epochs
            .get(&epoch)
            .and_then(|cache| cache.dealings.get(&dealer))
        {
            return Ok(if existing
                == &(pub_msg.clone(), priv_msg.clone(), acknowledgement.clone())
            {
                ExactInsert::Identical
            } else {
                ExactInsert::Conflict
            });
        }

        // Persist to journal
        let section = epoch.get();
        let event = Event::Dealing(
            dealer.clone(),
            pub_msg.clone(),
            priv_msg.clone(),
            acknowledgement.clone(),
        );
        let record = self.seal_record(RECORD_KIND_EVENT, epoch, &event.encode())?;
        self.msgs.append(section, &record).await?;
        self.msgs.sync(section).await?;

        // Update in-memory cache
        self.get_or_create_epoch(epoch)
            .dealings
            .insert(dealer, (pub_msg, priv_msg, acknowledgement));
        Ok(ExactInsert::Inserted)
    }

    /// Persists a player acknowledgment we received (as a dealer) for crash recovery.
    /// Reports whether the exact acknowledgement was inserted, already present, or conflicts.
    pub async fn append_ack(
        &mut self,
        epoch: EpochNum,
        player: P,
        ack: PlayerAck<P>,
    ) -> Result<ExactInsert, Error> {
        if let Some(existing) = self
            .epochs
            .get(&epoch)
            .and_then(|cache| cache.acks.get(&player))
        {
            return Ok(if existing == &ack {
                ExactInsert::Identical
            } else {
                ExactInsert::Conflict
            });
        }

        // Persist to journal
        let section = epoch.get();
        let event: Event<V, P> = Event::Ack(player.clone(), ack.clone());
        let record = self.seal_record(RECORD_KIND_EVENT, epoch, &event.encode())?;
        self.msgs.append(section, &record).await?;
        self.msgs.sync(section).await?;

        // Update in-memory cache
        self.get_or_create_epoch(epoch).acks.insert(player, ack);
        Ok(ExactInsert::Inserted)
    }

    /// Persists a finalized dealer log.
    /// Reports whether the exact log was inserted, already present, or conflicts.
    pub async fn append_log(
        &mut self,
        epoch: EpochNum,
        dealer: P,
        log: DealerLog<V, P>,
    ) -> Result<ExactInsert, Error> {
        if let Some(existing) = self
            .epochs
            .get(&epoch)
            .and_then(|cache| cache.logs.get(&dealer))
        {
            return Ok(if existing == &log {
                ExactInsert::Identical
            } else {
                ExactInsert::Conflict
            });
        }

        // Persist to journal
        let section = epoch.get();
        let event = Event::Log(dealer.clone(), log.clone());
        let record = self.seal_record(RECORD_KIND_EVENT, epoch, &event.encode())?;
        self.msgs.append(section, &record).await?;
        self.msgs.sync(section).await?;

        // Update in-memory cache
        self.get_or_create_epoch(epoch).logs.insert(dealer, log);
        Ok(ExactInsert::Inserted)
    }

    /// Persists epoch state.
    pub async fn set_epoch(&mut self, epoch: EpochNum, state: Epoch<V, P>) -> Result<(), Error> {
        // Persist to metadata using epoch number as key
        let epoch_key = epoch.get();
        let record = self.seal_record(RECORD_KIND_EPOCH, epoch, &state.encode())?;
        if self.states.put(epoch_key, record).is_some() {
            warn!(%epoch, "overwriting existing epoch state");
        }
        self.states.sync().await?;

        // Update in-memory state
        self.current = Some((epoch, state));
        Ok(())
    }

    /// Removes all data from epochs older than `min`.
    pub async fn prune(&mut self, min: EpochNum) -> Result<(), Error> {
        let min_epoch = min.get();

        // Prune msgs journal
        self.msgs.prune(min_epoch).await?;

        // Prune states metadata - remove all epochs < min
        self.states.retain(|&epoch_key, _| epoch_key >= min_epoch);
        self.states.sync().await?;

        self.local_dealer_records
            .retain(|&epoch_key, _| epoch_key >= min_epoch);
        self.local_dealer_records.sync().await?;

        // Remove old epoch caches
        self.epochs.retain(|&epoch, _| epoch >= min);
        self.local_dealers.retain(|&epoch, _| epoch >= min);
        Ok(())
    }

    /// Create a Dealer for the given epoch, replaying any stored acks.
    /// Returns None if we've already submitted a log this epoch.
    pub async fn create_dealer<C: Signer<PublicKey = P>, M: Faults>(
        &mut self,
        epoch: EpochNum,
        signer: C,
        round_info: Info<V, P>,
        share: Option<Share>,
        rng_seed: Summary,
    ) -> Result<Option<Dealer<V, C>>, CreateDealerError> {
        // If we've already observed our log in a finalized block, there is nothing more to do!
        if self.has_log(epoch, &signer.public_key()) {
            return Ok(None);
        }

        // The crypto implementation has no dealer resume constructor. Reconstruct
        // it deterministically, then require exact equality with the persisted
        // record before it can expose any send or finalization capability.
        let (mut crypto_dealer, pub_msg, priv_msgs) = CryptoDealer::start::<M>(
            Transcript::resume(rng_seed).noise(b"dealer-rng"),
            round_info.clone(),
            signer,
            share,
        )
        .map_err(CreateDealerError::Crypto)?;
        let generated: BTreeMap<P, DealerPrivMsg> = priv_msgs.into_iter().collect();

        let Some(persisted) = self.local_dealer(epoch) else {
            match self
                .initialize_local_dealer(
                    epoch,
                    pub_msg.clone(),
                    generated
                        .iter()
                        .map(|(player, private)| (player.clone(), private.clone())),
                )
                .await?
            {
                ExactInsert::Inserted | ExactInsert::Identical => {}
                ExactInsert::Conflict => return Err(CreateDealerError::StateMismatch),
            }
            return Ok(Some(Dealer::new(Some(crypto_dealer), pub_msg, generated)));
        };

        let (persisted_public, recipients, finalized) = match persisted {
            RecoveryDealer::Active {
                public_message,
                recipients,
            } => (public_message, recipients, None),
            RecoveryDealer::Finalized {
                public_message,
                recipients,
                signed_log,
            } => {
                let mut input = signed_log.as_ref();
                let cfg = NonZeroU32::new(recipients.len() as u32)
                    .ok_or(CreateDealerError::InvalidSignedLog)?;
                let signed = SignedDealerLog::<V, C>::read_cfg(&mut input, &cfg)
                    .map_err(Error::Decode)?;
                if input.has_remaining() {
                    return Err(Error::TrailingBytes.into());
                }
                if signed.clone().check(&round_info).is_none() {
                    return Err(CreateDealerError::InvalidSignedLog);
                }
                (public_message, recipients, Some(signed))
            }
        };
        if persisted_public != pub_msg || recipients.len() != generated.len() {
            return Err(CreateDealerError::StateMismatch);
        }

        let mut unsent = BTreeMap::new();
        for recipient in recipients {
            match recipient {
                RecipientState::Unacknowledged {
                    player,
                    private_message,
                } => {
                    if generated.get(&player) != Some(&private_message) {
                        return Err(CreateDealerError::StateMismatch);
                    }
                    unsent.insert(player, private_message);
                }
                RecipientState::Acknowledged {
                    player,
                    private_message,
                    ack,
                } => {
                    if generated.get(&player) != Some(&private_message)
                        || crypto_dealer
                            .receive_player_ack(player.clone(), ack)
                            .is_err()
                    {
                        return Err(CreateDealerError::StateMismatch);
                    }
                    debug!(?epoch, ?player, "replayed player ack");
                }
            }
        }
        if let Some(signed) = finalized {
            return Ok(Some(Dealer::new(None, pub_msg, BTreeMap::new()).with_finalized(signed)));
        }
        Ok(Some(Dealer::new(Some(crypto_dealer), pub_msg, unsent)))
    }

    /// Create a Player for the given epoch by resuming from persisted state.
    pub fn create_player<C: Signer<PublicKey = P>, M: Faults>(
        &self,
        epoch: EpochNum,
        signer: C,
        round_info: Info<V, P>,
    ) -> Result<Player<V, C>, CreatePlayerError> {
        let logs = self.logs(epoch);
        let dealings = self.dealings(epoch);
        let (crypto_player, generated_acks) =
            CryptoPlayer::resume::<M>(round_info, signer, &logs, dealings).map_err(|err| {
                if matches!(
                    err,
                    commonware_cryptography::bls12381::dkg::feldman_desmedt::Error::MissingPlayerDealing
                ) {
                    CreatePlayerError::MissingPlayerDealing
                } else {
                    CreatePlayerError::Crypto(err)
                }
            })?;
        let mut acks = BTreeMap::new();
        for (dealer, generated) in generated_acks {
            let bytes = self
                .epochs
                .get(&epoch)
                .and_then(|cache| cache.dealings.get(&dealer))
                .map(|(_, _, bytes)| bytes)
                .ok_or(CreatePlayerError::PersistedAcknowledgement)?;
            let mut input = bytes.as_ref();
            let persisted = PlayerAck::read(&mut input)
                .map_err(|_| CreatePlayerError::PersistedAcknowledgement)?;
            if input.has_remaining() || persisted != generated {
                return Err(CreatePlayerError::PersistedAcknowledgement);
            }
            debug!(?epoch, ?dealer, "restored committed dealer message");
            acks.insert(dealer, persisted);
        }

        Ok(Player {
            player: crypto_player,
            acks,
        })
    }
}

/// Internal state for a dealer in the current round.
pub struct Dealer<V: Variant, C: Signer> {
    dealer: Option<CryptoDealer<V, C>>,
    pub_msg: DealerPubMsg<V>,
    unsent: BTreeMap<C::PublicKey, DealerPrivMsg>,
    finalized: Option<SignedDealerLog<V, C>>,
}

impl<V: Variant, C: Signer> Dealer<V, C> {
    pub const fn new(
        dealer: Option<CryptoDealer<V, C>>,
        pub_msg: DealerPubMsg<V>,
        unsent: BTreeMap<C::PublicKey, DealerPrivMsg>,
    ) -> Self {
        Self {
            dealer,
            pub_msg,
            unsent,
            finalized: None,
        }
    }

    fn with_finalized(mut self, finalized: SignedDealerLog<V, C>) -> Self {
        self.finalized = Some(finalized);
        self
    }

    /// Handle an incoming ack from a player.
    ///
    /// If the ack is valid and new, persists it to storage.
    /// Returns true if the ack was successfully processed.
    pub async fn handle<E>(
        &mut self,
        storage: &mut Storage<E, V, C::PublicKey>,
        epoch: EpochNum,
        player: C::PublicKey,
        ack: PlayerAck<C::PublicKey>,
    ) -> bool
    where
        E: BufferPooler + Clock + RuntimeStorage + Metrics + CryptoRng,
    {
        if !self.unsent.contains_key(&player) {
            return false;
        }
        if let Some(ref mut dealer) = self.dealer {
            if dealer
                .receive_player_ack(player.clone(), ack.clone())
                .is_ok()
            {
                match storage
                    .acknowledge_local_recipient(epoch, player.clone(), ack)
                    .await
                {
                    Ok(ExactInsert::Inserted) => {
                        self.unsent.remove(&player);
                    }
                    Ok(ExactInsert::Identical | ExactInsert::Conflict) => return false,
                    Err(err) => {
                        error!(?epoch, ?player, %err, "failed to persist DKG ack");
                        return false;
                    }
                }
                return true;
            }
        }
        false
    }

    /// Finalize the dealer and produce a signed log for inclusion in a block.
    pub async fn finalize<E, M>(&mut self, storage: &mut Storage<E, V, C::PublicKey>, epoch: EpochNum) -> bool
    where
        E: BufferPooler + Clock + RuntimeStorage + Metrics + CryptoRng,
        M: Faults,
    {
        if self.finalized.is_some() {
            return true;
        }

        let Some(dealer) = self.dealer.take() else { return false; };
        let log = dealer.finalize::<M>();
        match storage.finalize_local_dealer(epoch, log.encode()).await {
            Ok(ExactInsert::Inserted | ExactInsert::Identical) => {
                self.finalized = Some(log);
                true
            }
            Ok(ExactInsert::Conflict) | Err(_) => false,
        }
    }

    /// Returns a clone of the finalized log if it exists.
    pub fn finalized(&self) -> Option<SignedDealerLog<V, C>> {
        self.finalized.clone()
    }

    /// Takes and returns the finalized log, leaving None in its place.
    pub const fn take_finalized(&mut self) -> Option<SignedDealerLog<V, C>> {
        self.finalized.take()
    }

    /// Returns shares to distribute to players.
    ///
    /// Returns an iterator of (player, pub_msg, priv_msg) tuples for each player
    /// that hasn't yet acknowledged their share.
    pub fn shares_to_distribute(
        &self,
    ) -> impl Iterator<Item = (C::PublicKey, DealerPubMsg<V>, DealerPrivMsg)> + '_ {
        self.unsent
            .iter()
            .map(|(player, priv_msg)| (player.clone(), self.pub_msg.clone(), priv_msg.clone()))
    }
}

/// Internal state for a player in the current round.
pub struct Player<V: Variant, C: Signer> {
    player: CryptoPlayer<V, C>,
    /// Acks we've generated, keyed by dealer. Once we generate an ack for a dealer,
    /// we will not generate a different one (to avoid conflicting votes).
    acks: BTreeMap<C::PublicKey, PlayerAck<C::PublicKey>>,
}

impl<V: Variant, C: Signer> Player<V, C> {
    /// Handle an incoming dealer message.
    ///
    /// If this is a new valid dealer message, persists it to storage before returning.
    pub async fn handle<E, M>(
        &mut self,
        storage: &mut Storage<E, V, C::PublicKey>,
        epoch: EpochNum,
        dealer: C::PublicKey,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) -> Option<PlayerAck<C::PublicKey>>
    where
        E: BufferPooler + Clock + RuntimeStorage + Metrics + CryptoRng,
        M: Faults,
    {
        // If we've already generated an ack, return the cached version
        if let Some(ack) = self.acks.get(&dealer) {
            return Some(ack.clone());
        }

        // Otherwise generate a new ack
        let Verdict::Valid(ack) = self.player.dealer_message::<M>(
            dealer.clone(),
            pub_msg.clone(),
            priv_msg.clone(),
        ) else {
            return None;
        };
        match storage
            .append_dealing(epoch, dealer.clone(), pub_msg, priv_msg, ack.encode())
            .await
        {
            Ok(ExactInsert::Inserted) => {}
            Ok(ExactInsert::Identical | ExactInsert::Conflict) => return None,
            Err(err) => {
                error!(?epoch, ?dealer, %err, "failed to persist DKG dealing");
                return None;
            }
        }
        self.acks.insert(dealer, ack.clone());
        Some(ack)
    }

    /// Finalize the player's participation in the DKG round.
    pub fn finalize<M: Faults, B: BatchVerifier<PublicKey = C::PublicKey>>(
        self,
        rng: &mut impl CryptoRng,
        logs: Logs<V, C::PublicKey, M>,
        strategy: &impl Strategy,
    ) -> Result<
        (Output<V, C::PublicKey>, Share),
        commonware_cryptography::bls12381::dkg::feldman_desmedt::Error,
    > {
        self.player.finalize::<M, B>(rng, logs, strategy)
    }
}
