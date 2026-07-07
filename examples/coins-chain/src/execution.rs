//! Coins-chain node-facing handles and query adapter.

use crate::{application::Application, Transaction};
use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::Mailbox as StatefulMailbox;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_storage::Context;
use jsonrpsee::core::async_trait;
use nunchi_coins::{rpc::CoinQuery, Address, CoinId, Ledger, LedgerError, TokenDefinition};
use nunchi_common::QmdbReader;
use nunchi_mempool::MempoolHandle;
use nunchi_memclob::MemClobHandle;

pub use nunchi_chain::SharedAppliedHeight;

/// A coins-chain node's externally reachable handles.
#[derive(Clone)]
pub struct NodeHandle<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng,
{
    pub submitter: MempoolHandle<Transaction>,
    pub memclob: MemClobHandle,
    pub stateful: StatefulMailbox<E, Application>,
    pub applied_height: SharedAppliedHeight,
}

impl<E> NodeHandle<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng,
{
    pub fn new(
        submitter: MempoolHandle<Transaction>,
        memclob: MemClobHandle,
        stateful: StatefulMailbox<E, Application>,
        applied_height: SharedAppliedHeight,
    ) -> Self {
        Self {
            submitter,
            memclob,
            stateful,
            applied_height,
        }
    }

    /// A read-only coin query backend over this node's committed databases, suitable for
    /// serving the coin RPC (see [`crate::rpc::module`]).
    pub fn query(&self) -> StatefulQuery<E> {
        StatefulQuery::new(self.stateful.clone())
    }
}

/// Read-only coin queries answered from the stateful actor's committed databases.
pub struct StatefulQuery<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng,
{
    stateful: StatefulMailbox<E, Application>,
}

impl<E> Clone for StatefulQuery<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng,
{
    fn clone(&self) -> Self {
        Self {
            stateful: self.stateful.clone(),
        }
    }
}

impl<E> StatefulQuery<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng,
{
    pub fn new(stateful: StatefulMailbox<E, Application>) -> Self {
        Self { stateful }
    }

    async fn ledger(&self) -> Ledger<QmdbReader<E>> {
        Ledger::new(QmdbReader::new(self.stateful.subscribe_databases().await))
    }
}

#[async_trait]
impl<E> CoinQuery for StatefulQuery<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng + Send + Sync + 'static,
{
    async fn nonce(&self, account: Address) -> Result<u64, LedgerError> {
        self.ledger().await.nonce(&account).await
    }

    async fn token(&self, coin: CoinId) -> Result<Option<TokenDefinition>, LedgerError> {
        self.ledger().await.token(&coin).await
    }

    async fn balance(&self, account: Address, coin: CoinId) -> Result<u128, LedgerError> {
        self.ledger().await.balance(&account, &coin).await
    }

    async fn state_root(&self) -> Result<Digest, LedgerError> {
        let db = self.stateful.subscribe_databases().await;
        Ok(QmdbReader::new(db).root().await)
    }
}
