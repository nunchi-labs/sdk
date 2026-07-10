//! Bridge module genesis.
//!
//! The bridge needs to know its own chain identity so every lock can stamp a record's
//! `source_chain_id`. That identity is pinned once here; the derivation policy for a chain's id
//! (for example a genesis/config hash) lives with the chain, not this module.

use crate::record::{set_local_chain_id, ChainId};
use nunchi_common::StateStore;

/// Genesis configuration for the bridge module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeGenesis {
    /// This chain's bridge id, stamped as `source_chain_id` on every lock.
    pub local_chain_id: ChainId,
}

impl BridgeGenesis {
    /// Create a genesis config pinning `local_chain_id`.
    pub fn new(local_chain_id: ChainId) -> Self {
        Self { local_chain_id }
    }

    /// Pin this chain's [`ChainId`] into bridge state.
    pub fn apply<S: StateStore>(&self, store: &mut S) {
        set_local_chain_id(store, &self.local_chain_id);
    }
}
