//! Authenticated public state for DKG resharing.
//!
//! This module contains the canonical protocol configuration, the public
//! checkpoint committed by an application, and the deterministic transition
//! used by both applications and DKG actors.

use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::types::{Epoch, Epocher, FixedEpocher, Height};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{
            observe, DealerLog, Info, Logs, Output, SignedDealerLog,
        },
        primitives::{
            group::Share,
            sharing::{Mode, ModeVersion},
            variant::{MinSig, Variant},
        },
    },
    ed25519,
    sha256::{Digest, Sha256},
    BatchVerifier, Hasher, PublicKey, Signer,
};
use commonware_parallel::Strategy;
use commonware_utils::{ordered::Set, N3f1, Participant, TryCollect};
use rand::{rngs::StdRng, seq::IteratorRandom, CryptoRng, SeedableRng};
use std::{collections::BTreeMap, num::{NonZeroU32, NonZeroU64}};

/// Current authenticated DKG state format.
pub const STATE_FORMAT_VERSION: u16 = 1;

/// Identifier committed for the `N3f1` fault model.
pub const N3F1_FAULT_MODEL: u8 = 1;

const CONFIG_DOMAIN: &[u8] = b"NUNCHI_DKG_PROTOCOL_CONFIG";

/// Canonical protocol configuration committed by every public checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgProtocolConfig<V: Variant = MinSig, P: PublicKey = ed25519::PublicKey> {
    pub state_format_version: u16,
    pub namespace: Vec<u8>,
    pub epoch_length: NonZeroU64,
    pub participants: Set<P>,
    pub num_participants_per_round: Vec<u32>,
    pub mode: Mode,
    pub mode_version: u8,
    pub fault_model: u8,
    pub trusted_initial_identity: V::Public,
}

impl<V: Variant, P: PublicKey> DkgProtocolConfig<V, P> {
    /// Validate semantic constraints that are not expressible through the codec.
    pub fn validate(&self) -> Result<(), Error> {
        if self.state_format_version != STATE_FORMAT_VERSION {
            return Err(Error::UnsupportedFormat(self.state_format_version));
        }
        if self.namespace.is_empty() {
            return Err(Error::EmptyNamespace);
        }
        if self.participants.is_empty() {
            return Err(Error::EmptyParticipants);
        }
        if self.num_participants_per_round.is_empty() {
            return Err(Error::EmptyRoundSchedule);
        }
        if self.mode_version != 0 {
            return Err(Error::UnsupportedModeVersion(self.mode_version));
        }
        if self.fault_model != N3F1_FAULT_MODEL {
            return Err(Error::UnsupportedFaultModel(self.fault_model));
        }
        let total = self.participants.len();
        if self
            .num_participants_per_round
            .iter()
            .any(|&count| count == 0 || count as usize > total)
        {
            return Err(Error::InvalidRoundSchedule);
        }
        Ok(())
    }

    /// Hash the canonical Commonware codec encoding.
    pub fn digest(&self) -> Result<Digest, Error> {
        self.validate()?;
        Ok(Sha256::hash(&self.encode()))
    }

    /// Return the maximum configured participant count.
    pub fn max_participants_per_round(&self) -> u32 {
        self.num_participants_per_round
            .iter()
            .copied()
            .max()
            .expect("validated schedule is non-empty")
    }

    /// Select the participants for a successful-round number.
    pub fn participants_for_round(&self, round: u64) -> Set<P> {
        let schedule_index = (round % self.num_participants_per_round.len() as u64) as usize;
        let count = self.num_participants_per_round[schedule_index] as usize;
        let participants = self.participants.iter().cloned();
        if round == 0 {
            return participants.take(count).try_collect().unwrap();
        }
        let mut rng = StdRng::seed_from_u64(round);
        participants
            .sample(&mut rng, count)
            .into_iter()
            .try_collect()
            .unwrap()
    }

    /// Reconstruct the exact public round information for a checkpoint.
    pub fn round_info(
        &self,
        checkpoint: &PublicCheckpoint<V, P>,
    ) -> Result<Info<V, P>, Error> {
        self.validate_checkpoint(checkpoint)?;
        let dealers = self.participants_for_round(checkpoint.successful_round);
        let players = self.participants_for_round(checkpoint.successful_round + 1);
        Info::new::<N3f1>(
            &self.namespace,
            checkpoint.epoch.get(),
            Some(checkpoint.output.clone()),
            self.mode,
            dealers,
            players,
        )
        .map_err(|error| Error::RoundInfo(error.to_string()))
    }

    /// Validate that a checkpoint belongs to this protocol configuration.
    pub fn validate_checkpoint(
        &self,
        checkpoint: &PublicCheckpoint<V, P>,
    ) -> Result<(), Error> {
        let expected = self.digest()?;
        if checkpoint.format_version != self.state_format_version {
            return Err(Error::UnsupportedFormat(checkpoint.format_version));
        }
        if checkpoint.protocol_config_digest != expected {
            return Err(Error::ProtocolConfigMismatch);
        }
        if checkpoint.output.public().public() != &self.trusted_initial_identity {
            return Err(Error::ThresholdIdentityMismatch);
        }
        Ok(())
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for DkgProtocolConfig<V, P> {
    fn encode_size(&self) -> usize {
        CONFIG_DOMAIN.len()
            + self.state_format_version.encode_size()
            + self.namespace.encode_size()
            + self.epoch_length.encode_size()
            + self.participants.encode_size()
            + self.num_participants_per_round.encode_size()
            + self.mode.encode_size()
            + self.mode_version.encode_size()
            + self.fault_model.encode_size()
            + self.trusted_initial_identity.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for DkgProtocolConfig<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_slice(CONFIG_DOMAIN);
        self.state_format_version.write(buf);
        self.namespace.write(buf);
        self.epoch_length.write(buf);
        self.participants.write(buf);
        self.num_participants_per_round.write(buf);
        self.mode.write(buf);
        self.mode_version.write(buf);
        self.fault_model.write(buf);
        self.trusted_initial_identity.write(buf);
    }
}

/// Codec limits for a protocol configuration.
#[derive(Clone, Copy)]
pub struct ProtocolConfigReadCfg {
    pub max_namespace_len: usize,
    pub max_participants: NonZeroU32,
    pub max_round_schedule_len: usize,
    pub max_supported_mode: ModeVersion,
}

impl<V: Variant, P: PublicKey> Read for DkgProtocolConfig<V, P> {
    type Cfg = ProtocolConfigReadCfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, CodecError> {
        let domain: [u8; CONFIG_DOMAIN.len()] = ReadExt::read(buf)?;
        if domain.as_slice() != CONFIG_DOMAIN {
            return Err(CodecError::Invalid("DkgProtocolConfig", "invalid domain"));
        }
        let value = Self {
            state_format_version: ReadExt::read(buf)?,
            namespace: Vec::<u8>::read_cfg(
                buf,
                &(RangeCfg::from(1..=cfg.max_namespace_len), ()),
            )?,
            epoch_length: ReadExt::read(buf)?,
            participants: Set::<P>::read_cfg(
                buf,
                &(RangeCfg::from(1..=cfg.max_participants.get() as usize), ()),
            )?,
            num_participants_per_round: Vec::<u32>::read_cfg(
                buf,
                &(RangeCfg::from(1..=cfg.max_round_schedule_len), ()),
            )?,
            mode: Mode::read_cfg(buf, &cfg.max_supported_mode)?,
            mode_version: ReadExt::read(buf)?,
            fault_model: ReadExt::read(buf)?,
            trusted_initial_identity: ReadExt::read(buf)?,
        };
        value
            .validate()
            .map_err(|_| CodecError::Invalid("DkgProtocolConfig", "invalid configuration"))?;
        Ok(value)
    }
}

/// Public DKG state authenticated by the application state root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicCheckpoint<V: Variant = MinSig, P: PublicKey = ed25519::PublicKey> {
    pub format_version: u16,
    pub protocol_config_digest: Digest,
    pub epoch: Epoch,
    pub successful_round: u64,
    pub activation_height: Height,
    pub output: Output<V, P>,
}

impl<V: Variant, P: PublicKey> PublicCheckpoint<V, P> {
    /// Construct the epoch-zero checkpoint from trusted configuration.
    pub fn genesis(
        config: &DkgProtocolConfig<V, P>,
        output: Output<V, P>,
    ) -> Result<Self, Error> {
        let checkpoint = Self {
            format_version: config.state_format_version,
            protocol_config_digest: config.digest()?,
            epoch: Epoch::zero(),
            successful_round: 0,
            activation_height: Height::zero(),
            output,
        };
        config.validate_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for PublicCheckpoint<V, P> {
    fn encode_size(&self) -> usize {
        self.format_version.encode_size()
            + self.protocol_config_digest.encode_size()
            + self.epoch.encode_size()
            + self.successful_round.encode_size()
            + self.activation_height.encode_size()
            + self.output.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for PublicCheckpoint<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.format_version.write(buf);
        self.protocol_config_digest.write(buf);
        self.epoch.write(buf);
        self.successful_round.write(buf);
        self.activation_height.write(buf);
        self.output.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for PublicCheckpoint<V, P> {
    type Cfg = (NonZeroU32, ModeVersion);

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let format_version = u16::read(buf)?;
        if format_version != STATE_FORMAT_VERSION {
            return Err(CodecError::Invalid(
                "PublicCheckpoint",
                "unsupported format version",
            ));
        }
        Ok(Self {
            format_version,
            protocol_config_digest: ReadExt::read(buf)?,
            epoch: ReadExt::read(buf)?,
            successful_round: ReadExt::read(buf)?,
            activation_height: ReadExt::read(buf)?,
            output: Output::read_cfg(buf, cfg)?,
        })
    }
}

/// Result of a deterministic public transition.
pub struct PublicTransition<V: Variant = MinSig, P: PublicKey = ed25519::PublicKey> {
    pub checkpoint: PublicCheckpoint<V, P>,
    pub succeeded: bool,
}

/// Execute the public transition committed at an epoch boundary.
pub fn transition<V, P, S, B>(
    config: &DkgProtocolConfig<V, P>,
    checkpoint: &PublicCheckpoint<V, P>,
    signed_logs: impl IntoIterator<Item = SignedDealerLog<V, S>>,
    boundary_height: Height,
    rng: &mut impl CryptoRng,
    strategy: &impl Strategy,
) -> Result<PublicTransition<V, P>, Error>
where
    V: Variant,
    P: PublicKey,
    S: Signer<PublicKey = P>,
    B: BatchVerifier<PublicKey = P>,
{
    config.validate_checkpoint(checkpoint)?;
    let epocher = FixedEpocher::new(config.epoch_length);
    if epocher.last(checkpoint.epoch) != Some(boundary_height) {
        return Err(Error::WrongBoundaryHeight);
    }
    let info = config.round_info(checkpoint)?;
    let eligible = config.participants_for_round(checkpoint.successful_round);
    let mut unique = BTreeMap::<P, SignedDealerLog<V, S>>::new();
    for signed in signed_logs {
        let checked = signed.clone().check(&info).ok_or(Error::InvalidSignedLog)?;
        let dealer = checked.0;
        if eligible.position(&dealer).is_none() {
            return Err(Error::IneligibleDealer);
        }
        if let Some(existing) = unique.get(&dealer) {
            if existing != &signed {
                return Err(Error::ConflictingDealerLog);
            }
            continue;
        }
        unique.insert(dealer, signed);
    }

    let mut checked = BTreeMap::new();
    for signed in unique.into_values() {
        let (dealer, log) = signed.check(&info)
            .ok_or(Error::InvalidSignedLog)?;
        checked.insert(dealer, log);
    }
    transition_logs::<V, P, B>(
        config,
        checkpoint,
        checked,
        boundary_height,
        rng,
        strategy,
    )
}

/// Execute a transition from logs whose dealer signatures were already
/// authenticated while ingesting finalized blocks.
///
/// This is the actor-facing half of [`transition`]. Applications should use
/// [`transition`] so signatures and duplicate submissions are checked in the
/// same call.
pub fn transition_logs<V, P, B>(
    config: &DkgProtocolConfig<V, P>,
    checkpoint: &PublicCheckpoint<V, P>,
    checked_logs: BTreeMap<P, DealerLog<V, P>>,
    boundary_height: Height,
    rng: &mut impl CryptoRng,
    strategy: &impl Strategy,
) -> Result<PublicTransition<V, P>, Error>
where
    V: Variant,
    P: PublicKey,
    B: BatchVerifier<PublicKey = P>,
{
    config.validate_checkpoint(checkpoint)?;
    let epocher = FixedEpocher::new(config.epoch_length);
    if epocher.last(checkpoint.epoch) != Some(boundary_height) {
        return Err(Error::WrongBoundaryHeight);
    }
    let info = config.round_info(checkpoint)?;
    let eligible = config.participants_for_round(checkpoint.successful_round);
    let mut logs = Logs::<V, P, N3f1>::new(info);
    for (dealer, log) in checked_logs {
        if eligible.position(&dealer).is_none() {
            return Err(Error::IneligibleDealer);
        }
        logs.record(dealer, log);
    }
    let observed = observe::<V, P, N3f1, B>(rng, logs, strategy);
    let (succeeded, successful_round, output) = match observed {
        Ok(output) => (true, checkpoint.successful_round + 1, output),
        Err(_) => (
            false,
            checkpoint.successful_round,
            checkpoint.output.clone(),
        ),
    };
    Ok(PublicTransition {
        checkpoint: PublicCheckpoint {
            format_version: checkpoint.format_version,
            protocol_config_digest: checkpoint.protocol_config_digest,
            epoch: checkpoint.epoch.next(),
            successful_round,
            activation_height: boundary_height,
            output,
        },
        succeeded,
    })
}

/// Validate exact checkpoint semantics at a certified startup anchor.
pub fn validate_anchor<V: Variant, P: PublicKey>(
    config: &DkgProtocolConfig<V, P>,
    checkpoint: &PublicCheckpoint<V, P>,
    anchor_height: Height,
) -> Result<(), Error> {
    config.validate_checkpoint(checkpoint)?;
    if anchor_height == Height::zero() {
        return (checkpoint.epoch == Epoch::zero()
            && checkpoint.activation_height == Height::zero())
            .then_some(())
            .ok_or(Error::CheckpointHeightMismatch);
    }
    let epocher = FixedEpocher::new(config.epoch_length);
    let bounds = epocher
        .containing(anchor_height)
        .ok_or(Error::CheckpointHeightMismatch)?;
    let expected = if anchor_height == bounds.last() {
        (bounds.epoch().next(), anchor_height)
    } else {
        let epoch = bounds.epoch();
        let activation = epoch
            .previous()
            .and_then(|previous| epocher.last(previous))
            .unwrap_or(Height::zero());
        (epoch, activation)
    };
    (checkpoint.epoch == expected.0 && checkpoint.activation_height == expected.1)
        .then_some(())
        .ok_or(Error::CheckpointHeightMismatch)
}

/// Validate a protected private share against authenticated public state.
pub fn validate_share<V: Variant, P: PublicKey>(
    output: &Output<V, P>,
    participant: &P,
    share: &Share,
) -> Result<(), Error> {
    let index = output
        .players()
        .position(participant)
        .map(Participant::from_usize)
        .ok_or(Error::ParticipantHasNoShare)?;
    if share.index != index {
        return Err(Error::InvalidLocalShare);
    }
    let expected = output
        .public()
        .partial_public(index)
        .map_err(|_| Error::InvalidLocalShare)?;
    if expected != share.public::<V>() {
        return Err(Error::InvalidLocalShare);
    }
    Ok(())
}

/// Construct a threshold scheme only after validating its private share.
pub fn checked_threshold_scheme(
    namespace: &[u8],
    output: &Output<MinSig, ed25519::PublicKey>,
    participant: &ed25519::PublicKey,
    share: Share,
) -> Result<crate::Scheme, Error> {
    validate_share(output, participant, &share)?;
    crate::ThresholdScheme::signer(
        namespace,
        output.players().clone(),
        output.public().clone(),
        share,
    )
    .ok_or(Error::InvalidLocalShare)
}

/// Public-state validation failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported DKG state format version {0}")]
    UnsupportedFormat(u16),
    #[error("DKG namespace must not be empty")]
    EmptyNamespace,
    #[error("DKG participant set must not be empty")]
    EmptyParticipants,
    #[error("DKG round schedule must not be empty")]
    EmptyRoundSchedule,
    #[error("DKG round schedule contains an invalid participant count")]
    InvalidRoundSchedule,
    #[error("unsupported DKG mode version {0}")]
    UnsupportedModeVersion(u8),
    #[error("unsupported DKG fault model {0}")]
    UnsupportedFaultModel(u8),
    #[error("checkpoint protocol configuration digest does not match")]
    ProtocolConfigMismatch,
    #[error("checkpoint threshold identity does not match")]
    ThresholdIdentityMismatch,
    #[error("failed to construct DKG round info: {0}")]
    RoundInfo(String),
    #[error("transition height is not the current epoch boundary")]
    WrongBoundaryHeight,
    #[error("signed dealer log is invalid for the checkpoint")]
    InvalidSignedLog,
    #[error("dealer is not eligible in this DKG round")]
    IneligibleDealer,
    #[error("dealer submitted conflicting logs")]
    ConflictingDealerLog,
    #[error("checkpoint does not match the certified anchor height")]
    CheckpointHeightMismatch,
    #[error("validator is not a player in the checkpoint output")]
    ParticipantHasNoShare,
    #[error("protected local share does not match authenticated public state")]
    InvalidLocalShare,
}
