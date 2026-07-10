//! Bridge module genesis.
//!
//! The bridge needs to know its own chain identity so every lock can stamp a record's
//! `source_chain_id`. A chain that receives bridged transfers also pins the account allowed to
//! anchor foreign roots. Both are set once here; the derivation of a chain's id and the choice of
//! attestor live with the chain, not this module.

use crate::record::{set_attestor, set_local_chain_id, ChainId};
use nunchi_common::{Address, StateStore};

/// Genesis configuration for the bridge module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeGenesis {
    /// This chain's bridge id, stamped as `source_chain_id` on every lock.
    pub local_chain_id: ChainId,
    /// Account allowed to anchor foreign roots on this chain. A chain that only originates
    /// transfers (never receives claims) can leave this `None`.
    pub attestor: Option<Address>,
}

impl BridgeGenesis {
    /// Create a genesis config pinning `local_chain_id`, with no anchor attestor.
    pub fn new(local_chain_id: ChainId) -> Self {
        Self {
            local_chain_id,
            attestor: None,
        }
    }

    /// Set the account allowed to anchor foreign roots on this chain.
    pub fn with_attestor(mut self, attestor: Address) -> Self {
        self.attestor = Some(attestor);
        self
    }

    /// Pin this chain's [`ChainId`] (and attestor, if any) into bridge state.
    pub fn apply<S: StateStore>(&self, store: &mut S) {
        set_local_chain_id(store, &self.local_chain_id);
        if let Some(attestor) = &self.attestor {
            set_attestor(store, attestor);
        }
    }
}
