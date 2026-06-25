//! Node-facing handles for submitting transactions and observing stateful execution.

use commonware_glue::stateful::Mailbox as StatefulMailbox;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_storage::Context as StorageContext;
use nunchi_common::{QmdbDatabaseSet, QmdbReader, Runtime};
use nunchi_mempool::{MempoolHandle, PoolTransaction};

use crate::{
    Application, ConsensusExtension, EventReporter, NoConsensusExtension, NoopEventReporter,
    SharedAppliedHeight,
};

/// A node's externally reachable handles.
///
/// In production a node has exactly one of these. In-process multi-node harnesses can collect them
/// into a map keyed by public key to drive and observe multiple validators.
#[derive(Clone)]
pub struct NodeHandle<E, R, Ext = NoConsensusExtension, Reporter = NoopEventReporter>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    R::Transaction: PoolTransaction,
    Ext: ConsensusExtension + Sync,
    Reporter: EventReporter<<R::Transaction as PoolTransaction>::Digest>,
{
    pub submitter: MempoolHandle<R::Transaction>,
    pub stateful: StatefulMailbox<E, Application<R, Ext, Reporter>>,
    pub applied_height: SharedAppliedHeight,
}

impl<E, R, Ext, Reporter> NodeHandle<E, R, Ext, Reporter>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    R::Transaction: PoolTransaction,
    Ext: ConsensusExtension + Sync,
    Reporter: EventReporter<<R::Transaction as PoolTransaction>::Digest>,
{
    pub fn new(
        submitter: MempoolHandle<R::Transaction>,
        stateful: StatefulMailbox<E, Application<R, Ext, Reporter>>,
        applied_height: SharedAppliedHeight,
    ) -> Self {
        Self {
            submitter,
            stateful,
            applied_height,
        }
    }

    /// A read-only query backend over this node's committed databases.
    pub fn query(&self) -> StatefulQuery<E, R, Ext, Reporter> {
        StatefulQuery::new(self.stateful.clone())
    }
}

/// Read-only queries answered from the stateful actor's committed databases.
pub struct StatefulQuery<E, R, Ext = NoConsensusExtension, Reporter = NoopEventReporter>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    R::Transaction: PoolTransaction,
    Ext: ConsensusExtension + Sync,
    Reporter: EventReporter<<R::Transaction as PoolTransaction>::Digest>,
{
    stateful: StatefulMailbox<E, Application<R, Ext, Reporter>>,
}

impl<E, R, Ext, Reporter> Clone for StatefulQuery<E, R, Ext, Reporter>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    R::Transaction: PoolTransaction,
    Ext: ConsensusExtension + Sync,
    Reporter: EventReporter<<R::Transaction as PoolTransaction>::Digest>,
{
    fn clone(&self) -> Self {
        Self {
            stateful: self.stateful.clone(),
        }
    }
}

impl<E, R, Ext, Reporter> StatefulQuery<E, R, Ext, Reporter>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    R::Transaction: PoolTransaction,
    Ext: ConsensusExtension + Sync,
    Reporter: EventReporter<<R::Transaction as PoolTransaction>::Digest>,
{
    pub fn new(stateful: StatefulMailbox<E, Application<R, Ext, Reporter>>) -> Self {
        Self { stateful }
    }

    pub async fn databases(&self) -> QmdbDatabaseSet<E> {
        self.stateful.subscribe_databases().await
    }

    pub async fn reader(&self) -> QmdbReader<E> {
        QmdbReader::new(self.databases().await)
    }
}
