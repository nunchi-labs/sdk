//! A demo blockchain that runs the Nunchi coins module under real consensus.
//!
//! The chain reuses the consensus, marshal, and engine wiring of the `nunchi-template` example, but
//! its blocks carry [`nunchi_coins`] transactions and each validator executes the finalized block
//! stream into its own authenticated coin [`Ledger`](nunchi_coins::Ledger).
//!
//! Transactions enter the chain exactly as they would on a real network: a client signs a
//! transaction and submits it to a *specific* node's [`txpool`] (there is no gossip — each node only
//! proposes the transactions it received). When that node leads, it includes them in its block;
//! once finalized, every node executes them into its ledger. Each [`execution::NodeHandle`]
//! exposes a node's transaction submitter and committed ledger so clients (and the integration
//! tests in `tests/`) can drive and observe the chain.

use commonware_consensus::types::Epoch;
use std::num::NonZeroU64;

mod block;
mod consensus;

pub mod application;
pub mod engine;
pub mod execution;
pub mod txpool;

pub use block::{Block, Finalized, Notarized, MAX_TRANSACTIONS};
pub use consensus::{
    Activity, Context, EdScheme, EpochProvider, Finalization, Identity, Notarization, Provider,
    PublicKey, Scheme, Seed, Seedable, Signature, ThresholdScheme,
};

/// Namespace prefix used in all consensus signing operations to prevent signature replay attacks.
pub const NAMESPACE: &[u8] = b"_NUNCHI_COINS_CHAIN";

/// The consensus epoch. The demo chain never reconfigures, so the epoch is hardcoded to 0.
pub const EPOCH: Epoch = Epoch::zero();

/// The number of blocks in an epoch.
///
/// Production systems should use a much larger value, as DKG/reshare safety depends on
/// synchrony during the epoch window.
pub const BLOCKS_PER_EPOCH: NonZeroU64 = commonware_utils::NZU64!(200);
