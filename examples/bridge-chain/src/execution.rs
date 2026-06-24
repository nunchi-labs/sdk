//! Bridge-chain node-facing handles.

use crate::{Application, Block, Scheme};
use commonware_consensus::marshal::{core::Mailbox as MarshalMailbox, standard::Standard};
use commonware_glue::stateful::Mailbox as StatefulMailbox;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_storage::Context;
use nunchi_bridge::BridgeMailbox;

pub use nunchi_chain::SharedAppliedHeight;

/// A bridge-chain node's externally reachable handles.
#[derive(Clone)]
pub struct NodeHandle<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng,
{
    pub bridge: BridgeMailbox,
    pub stateful: StatefulMailbox<E, Application>,
    pub marshal: MarshalMailbox<Scheme, Standard<Block>>,
    pub applied_height: SharedAppliedHeight,
}

impl<E> NodeHandle<E>
where
    E: Context + Spawner + Metrics + Clock + rand::Rng,
{
    pub fn new(
        bridge: BridgeMailbox,
        stateful: StatefulMailbox<E, Application>,
        marshal: MarshalMailbox<Scheme, Standard<Block>>,
        applied_height: SharedAppliedHeight,
    ) -> Self {
        Self {
            bridge,
            stateful,
            marshal,
            applied_height,
        }
    }
}
