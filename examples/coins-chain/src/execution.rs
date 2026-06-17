//! Coins-chain node-facing handles and query adapter.

use commonware_cryptography::sha256::Digest;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_storage::Context;
use jsonrpsee::core::async_trait;
use nunchi_coins::{rpc::CoinQuery, Address, CoinId, Ledger, LedgerError, TokenDefinition};
use nunchi_common::QmdbReader;
use std::ops::Deref;

pub use nunchi_chain::SharedAppliedHeight;

use crate::{application::Application, CoinsRuntime, RuntimeTransaction};

type DkgExtension = nunchi_chain::DkgExtension<RuntimeTransaction>;

pub type ChainNodeHandle<E> = nunchi_chain::NodeHandle<E, CoinsRuntime, DkgExtension>;
pub type ChainStatefulQuery<E> = nunchi_chain::StatefulQuery<E, CoinsRuntime, DkgExtension>;

/// A coins-chain node's externally reachable handles.
#[derive(Clone)]
pub struct NodeHandle<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng,
{
    inner: ChainNodeHandle<E>,
}

impl<E> NodeHandle<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng,
{
    pub fn new(
        submitter: nunchi_chain::RuntimeSubmitter<CoinsRuntime>,
        stateful: commonware_glue::stateful::Mailbox<E, Application>,
        applied_height: SharedAppliedHeight,
    ) -> Self {
        Self {
            inner: ChainNodeHandle::new(submitter, stateful, applied_height),
        }
    }

    /// A read-only coin query backend over this node's committed databases, suitable for
    /// serving the coin RPC (see [`crate::rpc::module`]).
    pub fn query(&self) -> StatefulQuery<E> {
        StatefulQuery(self.inner.query())
    }
}

impl<E> Deref for NodeHandle<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng,
{
    type Target = ChainNodeHandle<E>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Read-only coin queries answered from the stateful actor's committed databases.
pub struct StatefulQuery<E>(ChainStatefulQuery<E>)
where
    E: Context + Spawner + Metrics + Clock + rand::Rng;

impl<E> Clone for StatefulQuery<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<E> StatefulQuery<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng,
{
    pub fn new(stateful: commonware_glue::stateful::Mailbox<E, Application>) -> Self {
        Self(ChainStatefulQuery::new(stateful))
    }

    async fn ledger(&self) -> Ledger<QmdbReader<E>> {
        Ledger::new(self.0.reader().await)
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
        Ok(self.0.reader().await.root().await)
    }
}
