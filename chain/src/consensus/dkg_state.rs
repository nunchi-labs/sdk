//! Authenticated public DKG state stored in the chain QMDB.

use commonware_codec::{Encode, Read};
use commonware_consensus::types::{Epocher, FixedEpocher, Height};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig,
    ed25519::{self, Batch},
};
use commonware_parallel::Sequential;
use nunchi_common::{
    CommitState, Namespace, StateError, StateStore, MAX_STATE_VALUE_SIZE,
};
use nunchi_dkg::{
    public_transition, DkgProtocolConfig, PublicCheckpoint, STATE_FORMAT_VERSION,
};
use rand::CryptoRng;

const DKG_NAMESPACE: Namespace = Namespace::new(b"_NUNCHI_CHAIN_DKG_STATE");

#[repr(u8)]
enum Table {
    Marker = 0,
    Checkpoint = 1,
    Log = 2,
}

impl From<Table> for u8 {
    fn from(value: Table) -> Self {
        value as Self
    }
}

/// Authenticated DKG state configuration installed in a DKG-enabled application.
#[derive(Clone)]
pub struct DkgState {
    config: DkgProtocolConfig,
    max_participants: std::num::NonZeroU32,
}

impl DkgState {
    pub fn new(config: DkgProtocolConfig) -> Result<Self, Error> {
        config.validate()?;
        let max_participants = std::num::NonZeroU32::new(
            config.max_participants_per_round(),
        )
        .ok_or(Error::InvalidConfiguration)?;
        validate_size_bounds(max_participants)?;
        Ok(Self {
            config,
            max_participants,
        })
    }

    pub const fn config(&self) -> &DkgProtocolConfig {
        &self.config
    }

    /// Stage the format marker and epoch-zero checkpoint.
    pub async fn seed<S: StateStore + CommitState + Send + Sync>(
        &self,
        state: &mut S,
        empty_root: commonware_cryptography::sha256::Digest,
        initial_output: commonware_cryptography::bls12381::dkg::feldman_desmedt::Output<
            MinSig,
            ed25519::PublicKey,
        >,
    ) -> Result<PublicCheckpoint, Error> {
        let expected = PublicCheckpoint::genesis(&self.config, initial_output)?;
        let marker = self.marker_value()?;
        match state.get(&marker_key()).await? {
            Some(existing) if existing != marker => return Err(Error::MismatchedMarker),
            Some(_) => {
                let checkpoint = self.load_checkpoint(state).await?;
                if checkpoint.epoch == commonware_consensus::types::Epoch::zero()
                    && checkpoint != expected
                {
                    return Err(Error::MismatchedInitialCheckpoint);
                }
                return Ok(checkpoint);
            }
            None if state.root() != empty_root => return Err(Error::UnmarkedState),
            None => {}
        }
        put_bounded(state, checkpoint_key(), expected.encode().to_vec())?;
        put_bounded(state, marker_key(), marker)?;
        Ok(expected)
    }

    /// Require the current state format marker and load its checkpoint.
    pub async fn load_checkpoint<S: StateStore + Sync>(
        &self,
        state: &S,
    ) -> Result<PublicCheckpoint, Error> {
        let marker = state
            .get(&marker_key())
            .await?
            .ok_or(Error::MissingMarker)?;
        if marker != self.marker_value()? {
            return Err(Error::MismatchedMarker);
        }
        let raw = state
            .get(&checkpoint_key())
            .await?
            .ok_or(Error::MissingCheckpoint)?;
        let checkpoint = decode_checkpoint(&raw, self.max_participants)?;
        self.config.validate_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }

    /// Validate and stage one block's public DKG effects.
    pub async fn apply_block<S, R>(
        &self,
        state: &mut S,
        height: Height,
        signed_log: Option<&nunchi_dkg::DealerLog>,
        rng: &mut R,
    ) -> Result<(), Error>
    where
        S: StateStore + Send + Sync,
        R: CryptoRng,
    {
        let checkpoint = self.load_checkpoint(state).await?;
        let info = self.config.round_info(&checkpoint)?;
        if let Some(signed_log) = signed_log {
            let (dealer, _) = signed_log
                .clone()
                .check(&info)
                .ok_or(Error::InvalidDealerLog)?;
            let eligible = self
                .config
                .participants_for_round(checkpoint.successful_round);
            if eligible.position(&dealer).is_none() {
                return Err(Error::IneligibleDealer);
            }
            let key = log_key(checkpoint.epoch.get(), &dealer);
            let encoded = signed_log.encode();
            if let Some(existing) = state.get(&key).await? {
                let existing = decode_log(&existing, self.max_participants)?;
                if existing != *signed_log {
                    return Err(Error::ConflictingDealerLog);
                }
            } else {
                put_bounded(state, key, encoded.to_vec())?;
            }
        }

        let epocher = FixedEpocher::new(self.config.epoch_length);
        if epocher.last(checkpoint.epoch) != Some(height) {
            return Ok(());
        }

        let eligible = self
            .config
            .participants_for_round(checkpoint.successful_round);
        let mut logs = Vec::new();
        for dealer in &eligible {
            let key = log_key(checkpoint.epoch.get(), dealer);
            if let Some(raw) = state.get(&key).await? {
                logs.push(decode_log(&raw, self.max_participants)?);
            }
        }
        let next = public_transition::<MinSig, ed25519::PublicKey, ed25519::PrivateKey, Batch>(
            &self.config,
            &checkpoint,
            logs,
            height,
            rng,
            &Sequential,
        )?;

        // The checkpoint and current-log set change atomically in this batch.
        for dealer in &eligible {
            state.remove(log_key(checkpoint.epoch.get(), dealer));
        }
        put_bounded(state, checkpoint_key(), next.checkpoint.encode().to_vec())?;
        Ok(())
    }

    /// Load all current finalized signed logs from authenticated state.
    pub async fn load_logs<S: StateStore + Sync>(
        &self,
        state: &S,
    ) -> Result<Vec<nunchi_dkg::DealerLog>, Error> {
        let checkpoint = self.load_checkpoint(state).await?;
        let eligible = self
            .config
            .participants_for_round(checkpoint.successful_round);
        let mut logs = Vec::new();
        for dealer in &eligible {
            if let Some(raw) = state
                .get(&log_key(checkpoint.epoch.get(), dealer))
                .await?
            {
                logs.push(decode_log(&raw, self.max_participants)?);
            }
        }
        Ok(logs)
    }

    fn marker_value(&self) -> Result<Vec<u8>, Error> {
        Ok((STATE_FORMAT_VERSION, self.config.digest()?).encode().to_vec())
    }
}

fn validate_size_bounds(max_participants: std::num::NonZeroU32) -> Result<(), Error> {
    let participants = usize::try_from(max_participants.get())
        .map_err(|_| Error::InvalidConfiguration)?;
    // Conservative codec formulas use the larger BLS element size and charge
    // every player result for an identity, tag, and Ed25519 signature.
    let polynomial = participants
        .checked_mul(96)
        .and_then(|size| size.checked_add(16))
        .ok_or(Error::InvalidConfiguration)?;
    let ordered_set = participants
        .checked_mul(32)
        .and_then(|size| size.checked_add(10))
        .ok_or(Error::InvalidConfiguration)?;
    let checkpoint = polynomial
        .checked_add(
            ordered_set
                .checked_mul(3)
                .ok_or(Error::InvalidConfiguration)?,
        )
        .and_then(|size| size.checked_add(128))
        .ok_or(Error::InvalidConfiguration)?;
    let dealer_log = polynomial
        .checked_add(
            participants
                .checked_mul(32 + 1 + 64)
                .ok_or(Error::InvalidConfiguration)?,
        )
        .and_then(|size| size.checked_add(32 + 64 + 32))
        .ok_or(Error::InvalidConfiguration)?;
    if checkpoint > MAX_STATE_VALUE_SIZE || dealer_log > MAX_STATE_VALUE_SIZE {
        return Err(Error::ConfigurationTooLarge {
            checkpoint,
            dealer_log,
            maximum: MAX_STATE_VALUE_SIZE,
        });
    }
    Ok(())
}

fn put_bounded<S: StateStore>(
    state: &mut S,
    key: commonware_cryptography::sha256::Digest,
    value: Vec<u8>,
) -> Result<(), Error> {
    if value.len() > MAX_STATE_VALUE_SIZE {
        return Err(Error::ValueTooLarge(value.len()));
    }
    state.set(key, value);
    Ok(())
}

fn decode_checkpoint(
    raw: &[u8],
    max_participants: std::num::NonZeroU32,
) -> Result<PublicCheckpoint, Error> {
    let mut buf = raw;
    let checkpoint = PublicCheckpoint::read_cfg(
        &mut buf,
        &(max_participants, nunchi_dkg::MAX_SUPPORTED_MODE),
    )?;
    if !buf.is_empty() {
        return Err(Error::TrailingBytes);
    }
    Ok(checkpoint)
}

fn decode_log(
    raw: &[u8],
    max_participants: std::num::NonZeroU32,
) -> Result<nunchi_dkg::DealerLog, Error> {
    let mut buf = raw;
    let log = nunchi_dkg::DealerLog::read_cfg(&mut buf, &max_participants)?;
    if !buf.is_empty() {
        return Err(Error::TrailingBytes);
    }
    Ok(log)
}

fn marker_key() -> commonware_cryptography::sha256::Digest {
    DKG_NAMESPACE.key(Table::Marker, &[])
}

fn checkpoint_key() -> commonware_cryptography::sha256::Digest {
    DKG_NAMESPACE.key(Table::Checkpoint, &[])
}

fn log_key(
    epoch: u64,
    dealer: &ed25519::PublicKey,
) -> commonware_cryptography::sha256::Digest {
    let mut logical = epoch.encode().to_vec();
    logical.extend_from_slice(&dealer.encode());
    DKG_NAMESPACE.key(Table::Log, &logical)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid DKG state configuration")]
    InvalidConfiguration,
    #[error(
        "DKG configuration exceeds QMDB value bounds: checkpoint {checkpoint}, dealer log {dealer_log}, maximum {maximum}"
    )]
    ConfigurationTooLarge {
        checkpoint: usize,
        dealer_log: usize,
        maximum: usize,
    },
    #[error("authenticated state error: {0}")]
    State(#[from] StateError),
    #[error("public DKG state error: {0}")]
    Public(#[from] nunchi_dkg::public::Error),
    #[error("public DKG state codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
    #[error("public DKG state value contains trailing bytes")]
    TrailingBytes,
    #[error("authenticated state has no DKG format marker; re-genesis or perform verified peer state sync")]
    MissingMarker,
    #[error("authenticated state is non-empty but has no DKG format marker; re-genesis or perform verified peer state sync")]
    UnmarkedState,
    #[error("authenticated state DKG format or protocol configuration differs; re-genesis required")]
    MismatchedMarker,
    #[error("authenticated state has no DKG checkpoint")]
    MissingCheckpoint,
    #[error("existing authenticated DKG genesis checkpoint differs")]
    MismatchedInitialCheckpoint,
    #[error("dealer log is invalid for the authenticated checkpoint")]
    InvalidDealerLog,
    #[error("dealer is not eligible for the authenticated checkpoint round")]
    IneligibleDealer,
    #[error("dealer submitted a conflicting finalized log")]
    ConflictingDealerLog,
    #[error("authenticated DKG value size {0} exceeds the QMDB limit")]
    ValueTooLarge(usize),
}
