//! Reusable chain execution primitives for generated Nunchi runtimes.

/// Default minimum timestamp delta between a block and its parent.
pub const DEFAULT_MIN_BLOCK_INTERVAL_MS: std::num::NonZeroU64 = commonware_utils::NZU64!(1);

commonware_macros::stability_scope!(ALPHA {
pub mod application;
pub mod block;
pub mod consensus;
pub mod engine;
pub mod events;
pub mod execution;
pub mod state_sync;
pub mod startup;
mod macros;
#[cfg(test)]
mod tests;

pub use application::{Application, SharedAppliedHeight};
pub use block::{Block, Finalized, Notarized, StateCommitment, MAX_TRANSACTIONS};
pub use consensus::{
    dkg_reporters, BlockExtension, Composite, ConsensusExtension, DkgActor, DkgMailbox,
    DkgReporters, NoConsensusExtension,
};
pub use consensus::dkg_state::{DkgState, Error as DkgStateError};
pub use events::{
    EventConsumer, FinalizedEvents, InMemoryEventConsumer, IndexedEvent, NoopEventConsumer,
    TransactionEventContext, TransactionEvents,
};
pub use execution::{NodeHandle, StatefulQuery};
});
