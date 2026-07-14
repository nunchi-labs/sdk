//! Node-facing handles for submitting transactions and observing stateful execution.

use commonware_glue::stateful::Mailbox as StatefulMailbox;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_storage::Context as StorageContext;
use nunchi_common::{QmdbDatabaseSet, QmdbReader, Runtime};
use nunchi_mempool::{MempoolHandle, PoolTransaction};

use crate::{
    Application, ConsensusExtension, EventConsumer, NoConsensusExtension, NoopEventConsumer,
    SharedAppliedHeight,
};

/// A node's externally reachable handles.
///
/// In production a node has exactly one of these. In-process multi-node harnesses can collect them
/// into a map keyed by public key to drive and observe multiple validators.
#[derive(Clone)]
pub struct NodeHandle<E, R, Ext = NoConsensusExtension, Events = NoopEventConsumer>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    R::Transaction: PoolTransaction + Sync,
    Ext: ConsensusExtension + Sync,
    Events: EventConsumer,
{
    pub submitter: MempoolHandle<R::Transaction>,
    pub stateful: StatefulMailbox<E, Application<R, Ext, Events>>,
    pub applied_height: SharedAppliedHeight,
}

impl<E, R, Ext, Events> NodeHandle<E, R, Ext, Events>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    R::Transaction: PoolTransaction + Sync,
    Ext: ConsensusExtension + Sync,
    Events: EventConsumer,
{
    pub fn new(
        submitter: MempoolHandle<R::Transaction>,
        stateful: StatefulMailbox<E, Application<R, Ext, Events>>,
        applied_height: SharedAppliedHeight,
    ) -> Self {
        Self {
            submitter,
            stateful,
            applied_height,
        }
    }

    /// A read-only query backend over this node's committed databases.
    pub fn query(&self) -> StatefulQuery<E, R, Ext, Events> {
        StatefulQuery::new(self.stateful.clone())
    }
}

/// Read-only queries answered from the stateful actor's committed databases.
pub struct StatefulQuery<E, R, Ext = NoConsensusExtension, Events = NoopEventConsumer>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    R::Transaction: PoolTransaction + Sync,
    Ext: ConsensusExtension + Sync,
    Events: EventConsumer,
{
    stateful: StatefulMailbox<E, Application<R, Ext, Events>>,
}

impl<E, R, Ext, Events> Clone for StatefulQuery<E, R, Ext, Events>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    R::Transaction: PoolTransaction + Sync,
    Ext: ConsensusExtension + Sync,
    Events: EventConsumer,
{
    fn clone(&self) -> Self {
        Self {
            stateful: self.stateful.clone(),
        }
    }
}

impl<E, R, Ext, Events> StatefulQuery<E, R, Ext, Events>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    R::Transaction: PoolTransaction + Sync,
    Ext: ConsensusExtension + Sync,
    Events: EventConsumer,
{
    pub fn new(stateful: StatefulMailbox<E, Application<R, Ext, Events>>) -> Self {
        Self { stateful }
    }

    pub async fn databases(&self) -> QmdbDatabaseSet<E> {
        self.stateful.subscribe_databases().await
    }

    pub async fn reader(&self) -> QmdbReader<E> {
        QmdbReader::new(self.databases().await)
    }
}
