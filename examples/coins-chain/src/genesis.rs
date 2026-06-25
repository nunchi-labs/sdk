use crate::StateCommitment;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_storage::{mmr::Family, qmdb::sync::Target, Context};
use nunchi_authority::{AuthorityGenesis, AuthorityLedger};
use nunchi_coins::{CoinsGenesis, Ledger};
use nunchi_common::{
    CommitState, Namespace, Overlay, QmdbConfig, QmdbState, StateError, StateStore,
};
use serde::{Deserialize, Serialize};
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
    #[serde(default)]
    pub coins: Option<CoinsGenesis>,
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
    #[error("state error: {0}")]
    State(#[from] StateError),
    #[error("existing chain state was initialized with a different genesis")]
    MismatchedGenesis,
    #[error("existing chain state is non-empty but has no genesis marker")]
    UnmarkedState,
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
        set_genesis_marker(&mut overlay, fingerprint);
        overlay.commit();
        state.commit().await?;
        Ok(())
    }
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
