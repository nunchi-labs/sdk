use crate::StateCommitment;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_storage::{mmr::Family, qmdb::sync::Target, Context};
use nunchi_authority::{AuthorityGenesis, AuthorityLedger};
use nunchi_coins::{Address, CoinId, CoinsGenesis, Ledger};
use nunchi_common::{
    CommitState, Namespace, Overlay, QmdbConfig, QmdbState, StateError, StateStore,
};
use nunchi_oracle::{OracleGenesis, OracleLedger};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{fs, path::Path};
use thiserror::Error;

const GENESIS_NAMESPACE: Namespace = Namespace::new(b"_NUNCHI_COINS_CHAIN_GENESIS");

#[repr(u8)]
enum Table {
    Marker = 0,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

/// Top-level JSON genesis file for the coins-chain example.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainGenesis {
    #[serde(default)]
    pub authority: Option<AuthorityGenesis>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee: Option<FeeGenesis>,
    #[serde(default)]
    pub coins: Option<CoinsGenesis>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle: Option<OracleGenesis>,
}

/// Chain-level fee policy seeded at genesis.
#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeeGenesis {
    pub native_coin: CoinId,
    #[serde_as(as = "DisplayFromStr")]
    pub collector: Address,
    pub burn_bps: u16,
    pub schedule: FeeSchedule,
}

/// Static v1 fee schedule.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeeSchedule {
    pub base: u128,
    pub per_byte: u128,
    pub per_weight: u128,
    pub signature: u128,
}

#[derive(Debug, Error)]
pub enum GenesisError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid genesis json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("authority genesis error: {0}")]
    Authority(#[from] nunchi_authority::AuthorityError),
    #[error("coins genesis error: {0}")]
    Coins(#[from] nunchi_coins::LedgerError),
    #[error("oracle genesis error: {0}")]
    Oracle(#[from] nunchi_oracle::OracleError),
    #[error("invalid fee genesis: {0}")]
    Fee(#[from] FeeGenesisError),
    #[error("state error: {0}")]
    State(#[from] StateError),
    #[error("existing chain state was initialized with a different genesis")]
    MismatchedGenesis,
    #[error("existing chain state is non-empty but has no genesis marker")]
    UnmarkedState,
}

#[derive(Debug, Error)]
pub enum FeeGenesisError {
    #[error("burn_bps {0} exceeds 10000")]
    BurnBpsTooHigh(u16),
    #[error("native fee coin is not present in coin genesis: {0:?}")]
    MissingNativeCoin(CoinId),
}

impl ChainGenesis {
    pub fn read(path: impl AsRef<Path>) -> Result<Self, GenesisError> {
        let raw = fs::read(path)?;
        Self::from_slice(&raw)
    }

    pub fn from_slice(raw: &[u8]) -> Result<Self, GenesisError> {
        serde_json::from_slice(raw).map_err(GenesisError::Json)
    }

    pub fn fingerprint(&self) -> Result<Digest, GenesisError> {
        Ok(Sha256::hash(&serde_json::to_vec(self)?))
    }

    pub async fn apply_to_state<S>(
        &self,
        state: &mut S,
        empty: &StateCommitment,
    ) -> Result<(), GenesisError>
    where
        S: StateStore + CommitState + Send + Sync,
    {
        let fingerprint = self.fingerprint()?;
        match genesis_marker(state).await? {
            Some(existing) if existing == fingerprint => return Ok(()),
            Some(_) => return Err(GenesisError::MismatchedGenesis),
            None => {
                if state.root() != empty.root {
                    return Err(GenesisError::UnmarkedState);
                }
            }
        }

        let mut overlay = Overlay::new(state);
        if let Some(authority) = &self.authority {
            let mut ledger = AuthorityLedger::new(overlay);
            ledger.apply_genesis(authority).await?;
            overlay = ledger.into_inner();
        }
        if let Some(coins) = &self.coins {
            let mut ledger = Ledger::new(overlay);
            ledger.apply_genesis(coins).await?;
            overlay = ledger.into_inner();
        }
        if let Some(fee) = &self.fee {
            let ledger = Ledger::new(overlay);
            validate_fee_genesis(&ledger, fee).await?;
            overlay = ledger.into_inner();
        }
        if let Some(oracle) = &self.oracle {
            let mut ledger = OracleLedger::new(overlay);
            ledger.apply_genesis(oracle).await?;
            overlay = ledger.into_inner();
        }
        set_genesis_marker(&mut overlay, fingerprint);
        overlay.commit();
        state.commit().await?;
        Ok(())
    }
}

async fn validate_fee_genesis<D>(ledger: &Ledger<D>, fee: &FeeGenesis) -> Result<(), GenesisError>
where
    D: nunchi_coins::CoinDB,
{
    if fee.burn_bps > 10_000 {
        return Err(FeeGenesisError::BurnBpsTooHigh(fee.burn_bps).into());
    }
    if ledger.token(&fee.native_coin).await?.is_none() {
        return Err(FeeGenesisError::MissingNativeCoin(fee.native_coin).into());
    }
    Ok(())
}

pub async fn genesis_target<E>(
    context: E,
    config: QmdbConfig,
    genesis: &ChainGenesis,
    empty: &StateCommitment,
) -> Result<StateCommitment, GenesisError>
where
    E: Context + commonware_runtime::BufferPooler,
{
    let mut state = QmdbState::init_with_config(context, config).await?;
    genesis.apply_to_state(&mut state, empty).await?;
    Ok(state_commitment(state.sync_target().await))
}

pub fn state_commitment(target: Target<Family, Digest>) -> StateCommitment {
    StateCommitment {
        root: target.root,
        range: target.range,
    }
}

async fn genesis_marker<S>(state: &S) -> Result<Option<Digest>, GenesisError>
where
    S: StateStore + Sync,
{
    let Some(bytes) = state.get(&marker_key()).await? else {
        return Ok(None);
    };
    Digest::decode(bytes.as_ref())
        .map(Some)
        .map_err(|err| GenesisError::State(StateError::Backend(err.to_string())))
}

fn set_genesis_marker<S: StateStore>(state: &mut S, fingerprint: Digest) {
    state.set(marker_key(), fingerprint.encode().to_vec());
}

fn marker_key() -> Digest {
    GENESIS_NAMESPACE.key(Table::Marker, &[])
}
