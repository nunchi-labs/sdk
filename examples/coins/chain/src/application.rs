//! Coins-chain application aliases over the reusable chain application.

use commonware_cryptography::{sha256, Hasher, Sha256};
use nunchi_clob::ClobExtension;

use crate::CoinsRuntime;

/// Seed for the coins chain's genesis block payload digest.
///
/// This constant is hashed with SHA-256 to produce the very first consensus
/// block's payload digest (see [`genesis_payload`]). It is a **network constant**:
/// every node on the coins chain must agree on this exact byte sequence.
///
/// Changing this value -- even a single character -- produces a different genesis
/// digest, making the modified node incompatible with all existing nodes. Only
/// change this when intentionally starting a new, incompatible network.
const GENESIS: &[u8] = b"nunchi coins chain";

/// The consensus application for the DKG-backed coins chain.
pub type Application = nunchi_chain::Application<CoinsRuntime, ClobExtension>;

/// Coins-chain application without a consensus extension, used by focused tests.
pub type BasicApplication = nunchi_chain::Application<CoinsRuntime>;

pub fn genesis_payload() -> sha256::Digest {
    Sha256::hash(GENESIS)
}
