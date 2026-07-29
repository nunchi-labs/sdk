//! Reusable chain execution primitives for generated Nunchi runtimes.
//!
//! This crate provides the core building blocks that every Nunchi chain shares:
//! block construction, consensus-driven execution, event consumption, and state
//! synchronization. Chain integrators compose these pieces with a [`Runtime`]
//! implementation and optional module-specific extensions.
//!
//! # Key Types
//!
//! - [`Application`] -- implements the `commonware_glue::stateful::Application` trait.
//!   It drives the full block lifecycle: proposing blocks from the mempool, verifying
//!   untrusted blocks, applying transactions via the [`Runtime`] trait, and committing
//!   finalized state. It also manages DKG resharing through [`DkgMailbox`].
//!
//! - [`Block`] -- the on-wire block format carrying runtime transactions, an optional
//!   DKG resharing log slot, a consensus extension payload, and an authenticated state
//!   commitment (`state_root` + `state_range`). Its pre-computed `digest` field is used
//!   for all consensus identity comparisons.
//!
//! - [`ConsensusExtension`] / [`BlockExtension`] -- traits for installing custom
//!   per-block consensus payloads (e.g., bridge certificates, CLOB match batches)
//!   through the `propose` / `verify_payload` / `apply_payload` / `commit_payload`
//!   lifecycle. [`NoConsensusExtension`] is the zero-cost no-op implementation for
//!   chains that do not need a consensus extension.
//!
//! - [`EventConsumer`] -- trait for subscribing to per-transaction runtime events at
//!   finalization. Implementations receive callbacks via `begin_block`,
//!   `transaction_sink`, `transaction_applied`, and `finalized`.
//!   [`InMemoryEventConsumer`] buffers events in memory; [`NoopEventConsumer`] discards
//!   them.
//!
//! - [`state_sync`] module -- provides floor-probe discovery and QMDB state transfer
//!   support for peers catching up to the current chain tip.
//!
//! [`Runtime`]: nunchi_common::Runtime

commonware_macros::stability_scope!(ALPHA {
pub mod application;
pub mod block;
pub mod consensus;
pub mod engine;
pub mod events;
pub mod execution;
pub mod state_sync;
mod macros;
#[cfg(test)]
mod tests;

pub use application::{Application, SharedAppliedHeight};
pub use block::{Block, Finalized, Notarized, StateCommitment, MAX_TRANSACTIONS};
pub use consensus::{
    dkg_reporters, BlockExtension, Composite, ConsensusExtension, DkgActor, DkgMailbox,
    DkgReporters, NoConsensusExtension,
};
pub use events::{
    EventConsumer, FinalizedEvents, InMemoryEventConsumer, IndexedEvent, NoopEventConsumer,
    TransactionEventContext, TransactionEvents,
};
pub use execution::{NodeHandle, StatefulQuery};
});
