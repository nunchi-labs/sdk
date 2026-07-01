//! Coins-chain application aliases over the reusable chain application.

use commonware_cryptography::{sha256, Hasher, Sha256};

use crate::CoinsRuntime;

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"nunchi coins chain";

/// The consensus application for the DKG-backed coins chain.
pub type Application = nunchi_chain::Application<CoinsRuntime>;

/// Coins-chain application without a consensus extension, used by focused tests.
pub type BasicApplication = nunchi_chain::Application<CoinsRuntime>;

pub fn genesis_payload() -> sha256::Digest {
    Sha256::hash(GENESIS)
}
