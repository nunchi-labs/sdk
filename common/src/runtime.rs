//! Runtime execution contract for reusable chain applications.
//!
//! A runtime owns the top-level transaction enum and dispatches each transaction to the ledgers
//! selected by a chain. The reusable chain application only needs this narrow execution surface.

use std::future::Future;

use commonware_codec::{EncodeSize, Read, Write};

use crate::{EventSink, StateStore};

/// Deterministic execution context supplied by the chain application.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeContext {
    /// Consensus epoch for the block being proposed, verified, or applied.
    pub epoch: u64,
}

/// A complete chain runtime assembled from one or more module ledgers.
pub trait Runtime {
    /// Top-level transaction type accepted by the chain.
    type Transaction: Clone + EncodeSize + Read<Cfg = ()> + Write + Send + Sync + 'static;

    /// Runtime-level deterministic execution error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Validate a transaction against scratch state.
    fn validate<S>(
        state: &mut S,
        context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        S: StateStore + Send + Sync;

    /// Apply a transaction to real proposal/execution state.
    fn apply<S, Events>(
        state: &mut S,
        context: RuntimeContext,
        transaction: &Self::Transaction,
        events: &mut Events,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        S: StateStore + Send + Sync,
        Events: EventSink + Send;

    /// Whether an execution error indicates local storage failure instead of deterministic
    /// transaction invalidity.
    fn is_storage_error(error: &Self::Error) -> bool;
}
