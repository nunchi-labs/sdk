//! Node-facing handles for submitting transactions and observing stateful execution.

use commonware_glue::stateful::Mailbox as StatefulMailbox;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_storage::Context as StorageContext;
use nunchi_common::{QmdbDatabaseSet, QmdbReader, Runtime};

use crate::{
    Application, ConsensusExtension, NoConsensusExtension, RuntimeSubmitter, SharedAppliedHeight,
};

/// A node's externally reachable handles.
///
/// In production a node has exactly one of these. In-process multi-node harnesses can collect them
/// into a map keyed by public key to drive and observe multiple validators.
#[derive(Clone)]
pub struct NodeHandle<E, R, Ext = NoConsensusExtension>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    Ext: ConsensusExtension + Sync,
{
    pub submitter: RuntimeSubmitter<R>,
    pub stateful: StatefulMailbox<E, Application<R, Ext>>,
    pub applied_height: SharedAppliedHeight,
}

impl<E, R, Ext> NodeHandle<E, R, Ext>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    Ext: ConsensusExtension + Sync,
{
    pub fn new(
        submitter: RuntimeSubmitter<R>,
        stateful: StatefulMailbox<E, Application<R, Ext>>,
        applied_height: SharedAppliedHeight,
    ) -> Self {
        Self {
            submitter,
            stateful,
            applied_height,
        }
    }

    /// A read-only query backend over this node's committed databases.
    pub fn query(&self) -> StatefulQuery<E, R, Ext> {
        StatefulQuery::new(self.stateful.clone())
    }
}

/// Read-only queries answered from the stateful actor's committed databases.
pub struct StatefulQuery<E, R, Ext = NoConsensusExtension>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    Ext: ConsensusExtension + Sync,
{
    stateful: StatefulMailbox<E, Application<R, Ext>>,
}

impl<E, R, Ext> Clone for StatefulQuery<E, R, Ext>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    Ext: ConsensusExtension + Sync,
{
    fn clone(&self) -> Self {
        Self {
            stateful: self.stateful.clone(),
        }
    }
}

impl<E, R, Ext> StatefulQuery<E, R, Ext>
where
    E: StorageContext + Spawner + Metrics + Clock + rand::Rng,
    R: Runtime + Clone + Send + Sync + 'static,
    Ext: ConsensusExtension + Sync,
{
    pub fn new(stateful: StatefulMailbox<E, Application<R, Ext>>) -> Self {
        Self { stateful }
    }

    pub async fn databases(&self) -> QmdbDatabaseSet<E> {
        self.stateful.subscribe_databases().await
    }

    pub async fn reader(&self) -> QmdbReader<E> {
        QmdbReader::new(self.databases().await)
    }
}
