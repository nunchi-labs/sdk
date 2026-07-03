//! A demo blockchain that runs the Nunchi coins module under real consensus.
//!
//! The chain reuses the consensus, marshal, and engine wiring of the `nunchi-template` example, but
//! its blocks carry [`nunchi_coins`] transactions and the Commonware stateful actor executes each
//! finalized block into an authenticated coin [`Ledger`](nunchi_coins::Ledger).
//!
//! Transactions enter the chain exactly as they would on a real network: a client signs a
//! transaction and submits it to a *specific* node's [`nunchi_mempool::MempoolHandle`] (there is no
//! gossip; each node only proposes the transactions it received). When that node leads, it includes executable
//! transactions in its block; once finalized, stateful execution commits them into QMDB. The
//! [`execution::NodeHandle`] exposes each node's transaction submitter and stateful database
//! subscription so clients (and the integration tests in `tests/`) can drive and observe the chain.

commonware_macros::stability_scope!(ALPHA {
use commonware_consensus::types::Epoch;
use std::num::NonZeroU64;

pub mod application;
pub mod engine;
pub mod execution;
pub mod genesis;
pub mod indexer;
pub mod rpc;
pub mod runtime;
pub mod testnet;
pub mod transaction;

#[cfg(test)]
mod tests;

pub use nunchi_chain::{StateCommitment, MAX_TRANSACTIONS};
pub use nunchi_dkg::{
    Activity, Context, EdScheme, EpochProvider, Finalization, Identity, Notarization, Provider,
    PublicKey, Scheme, Seed, Seedable, Signature, ThresholdScheme, MAX_SUPPORTED_MODE,
};
pub use runtime::{CoinsRuntime, RuntimeError};
pub use transaction::Transaction;

pub type Block<Tx = Transaction> = nunchi_chain::Block<Tx>;
pub type Notarized<Tx = Transaction> = nunchi_chain::Notarized<Tx>;
pub type Finalized<Tx = Transaction> = nunchi_chain::Finalized<Tx>;

/// Namespace prefix used in all consensus signing operations to prevent signature replay attacks.
pub const NAMESPACE: &[u8] = b"_NUNCHI_COINS_CHAIN";

/// P2P channel identifiers shared by every coins-chain node.
///
/// These are wire-protocol constants: every node on a network (and the test harness) must agree
/// on them, so they live here rather than with any single network setup.
pub mod channels {
    pub const PENDING: u64 = 0;
    pub const RECOVERED: u64 = 1;
    pub const RESOLVER: u64 = 2;
    pub const BROADCAST: u64 = 3;
    pub const DKG: u64 = 4;
    pub const BACKFILL: u64 = 5;
    pub const MEMPOOL: u64 = 6;
}

/// The consensus epoch. The demo chain never reconfigures, so the epoch is hardcoded to 0.
pub const EPOCH: Epoch = Epoch::zero();

/// The number of blocks in an epoch.
///
/// Production systems should use a much larger value, as DKG/reshare safety depends on
/// synchrony during the epoch window.
pub const BLOCKS_PER_EPOCH: NonZeroU64 = commonware_utils::NZU64!(200_000);
});
