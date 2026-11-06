//! Bridge module genesis.
//!
//! The bridge needs to know its own chain identity so every lock can stamp a record's
//! `source_chain_id`. A chain that receives bridged transfers also pins the single foreign chain
//! whose finalization certificates may certify claim roots. Both are set once here.

use crate::record::{set_foreign_chain_id, set_local_chain_id, ChainId};
use nunchi_common::StateStore;

/// Genesis configuration for the bridge module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeGenesis {
    /// This chain's bridge id, stamped as `source_chain_id` on every lock.
    pub local_chain_id: ChainId,
    /// The one foreign chain whose verified finalization certificates certify claim roots.
    ///
    /// A chain that only originates transfers (never receives claims) can leave this `None`.
    pub foreign_chain_id: Option<ChainId>,
}

impl BridgeGenesis {
    /// Create a genesis config pinning `local_chain_id`, with no foreign chain.
    pub fn new(local_chain_id: ChainId) -> Self {
        Self {
            local_chain_id,
            foreign_chain_id: None,
        }
    }

    /// Set the one foreign chain this chain accepts finalization certificates from.
    pub fn with_foreign_chain(mut self, foreign_chain_id: ChainId) -> Self {
        self.foreign_chain_id = Some(foreign_chain_id);
        self
    }

    /// Pin this chain's [`ChainId`] (and foreign chain, if any) into bridge state.
    pub fn apply<S: StateStore>(&self, store: &mut S) {
        set_local_chain_id(store, &self.local_chain_id);
        if let Some(foreign_chain_id) = &self.foreign_chain_id {
            set_foreign_chain_id(store, foreign_chain_id);
        }
    }
}
