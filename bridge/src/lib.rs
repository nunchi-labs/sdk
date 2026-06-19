//! Bridge consensus extension for carrying foreign finalization certificates.
//!
//! A caller submits verified foreign finalizations through [`BridgeHandle`],
//! and [`BridgeExtension`] embeds the latest accepted certificate into proposed
//! blocks.

use std::{future::Future, sync::Arc};

use commonware_consensus::Viewable;
use commonware_parallel::Sequential;
use commonware_utils::sync::Mutex;
use nunchi_chain::{Block, BlockExtension, ConsensusExtension, Finalized, Notarized};
use nunchi_dkg::{Finalization, Scheme};
use rand::rngs::OsRng;

/// Consensus-side bridge payload committed into a block.
pub type BridgePayload = Option<Finalization>;

/// Block type for chains that carry bridge finalization payloads.
pub type BridgeBlock<Tx> = Block<Tx, BridgeExtension>;

/// Notarized block type for chains that carry bridge finalization payloads.
pub type BridgeNotarized<Tx> = Notarized<Tx, BridgeExtension>;

/// Finalized block type for chains that carry bridge finalization payloads.
pub type BridgeFinalized<Tx> = Finalized<Tx, BridgeExtension>;

/// Outcome of submitting a foreign finalization certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitResult {
    /// The certificate failed verification for the configured foreign network.
    Rejected,
    /// The certificate verified and replaced the cached latest finalization.
    Updated,
    /// The certificate verified but was not newer than the cached latest finalization.
    Stale,
}

#[derive(Debug)]
struct State {
    latest: BridgePayload,
}

/// Shared handle used to submit and inspect foreign finalization certificates.
#[derive(Clone, Debug)]
pub struct BridgeHandle {
    foreign_network: Arc<Scheme>,
    state: Arc<Mutex<State>>,
}

impl BridgeHandle {
    /// Create a bridge handle that verifies certificates from `foreign_network`.
    pub fn new(foreign_network: Scheme) -> Self {
        Self {
            foreign_network: Arc::new(foreign_network),
            state: Arc::new(Mutex::new(State { latest: None })),
        }
    }

    /// Return the latest accepted foreign finalization certificate, if any.
    pub fn latest(&self) -> BridgePayload {
        self.state.lock().latest.clone()
    }

    /// Clear the currently cached foreign finalization certificate.
    pub fn clear(&self) {
        self.state.lock().latest = None;
    }

    /// Verify a bridge payload against the configured foreign network.
    pub fn verify_payload(&self, payload: &BridgePayload) -> bool {
        let Some(finalization) = payload else {
            return true;
        };
        finalization.verify(&mut OsRng, &self.foreign_network, &Sequential)
    }

    /// Submit a foreign finalization certificate.
    ///
    /// Invalid certificates are rejected. Valid stale certificates do not replace the cached latest
    /// certificate.
    pub fn submit(&self, finalization: Finalization) -> SubmitResult {
        if !self.verify_payload(&Some(finalization.clone())) {
            return SubmitResult::Rejected;
        }

        let mut state = self.state.lock();
        let replace = match &state.latest {
            Some(current) => finalization.view() > current.view(),
            None => true,
        };
        if replace {
            state.latest = Some(finalization);
            SubmitResult::Updated
        } else {
            SubmitResult::Stale
        }
    }
}

/// Consensus extension that proposes and verifies foreign finalization certificates.
#[derive(Clone, Debug)]
pub struct BridgeExtension {
    handle: BridgeHandle,
}

impl BridgeExtension {
    /// Create a bridge extension and its shared handle.
    pub fn new(foreign_network: Scheme) -> Self {
        Self {
            handle: BridgeHandle::new(foreign_network),
        }
    }

    /// Create a bridge extension from an existing shared handle.
    pub const fn from_handle(handle: BridgeHandle) -> Self {
        Self { handle }
    }

    /// Return a handle for submitting foreign finalization certificates.
    pub fn handle(&self) -> BridgeHandle {
        self.handle.clone()
    }
}

impl BlockExtension for BridgeExtension {
    type Payload = BridgePayload;
    type ReadCfg = ();

    fn genesis_payload() -> Self::Payload {
        None
    }
}

impl ConsensusExtension for BridgeExtension {
    fn propose(&mut self) -> impl Future<Output = Self::Payload> + Send {
        std::future::ready(self.handle.latest())
    }

    fn verify_payload(&mut self, payload: &Self::Payload) -> impl Future<Output = bool> + Send {
        std::future::ready(self.handle.verify_payload(payload))
    }
}

#[cfg(test)]
mod tests;
