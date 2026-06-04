//! A demo blockchain that runs the Nunchi coins module under real consensus.
//!
//! The chain reuses the consensus, marshal, and engine wiring of the `nunchi-template` example, but
//! its blocks carry [`nunchi_coins`] transactions and each validator executes the finalized block
//! stream into its own authenticated coin [`Ledger`](nunchi_coins::Ledger).
//!
//! Transactions enter the chain exactly as they would on a real network: a client signs a
//! transaction and submits it to a *specific* node's [`txpool`] (there is no gossip — each node only
//! proposes the transactions it received). When that node leads, it includes them in its block;
//! once finalized, every node executes them into its ledger. The [`execution::NodeRegistry`]
//! exposes each node's transaction submitter and committed ledger so clients (and the integration
//! tests in `tests/`) can drive and observe the chain.

use commonware_consensus::types::Epoch;
use commonware_utils::NZU64;
use std::num::NonZero;

mod block;
mod consensus;

pub mod application;
pub mod engine;
pub mod execution;
pub mod txpool;

pub use block::{Block, Finalized, Notarized, MAX_TRANSACTIONS};
pub use consensus::{
    Activity, Context, Finalization, Identity, Notarization, PublicKey, Scheme, Seed, Seedable,
    Signature,
};

/// Namespace prefix used in all consensus signing operations to prevent signature replay attacks.
pub const NAMESPACE: &[u8] = b"_NUNCHI_COINS_CHAIN";

/// The consensus epoch. The demo chain never reconfigures, so the epoch is hardcoded to 0.
pub const EPOCH: Epoch = Epoch::zero();

/// The epoch length. Hardcoded to `u64::MAX` so the chain stays in the first epoch forever.
pub const EPOCH_LENGTH: NonZero<u64> = NZU64!(u64::MAX);
