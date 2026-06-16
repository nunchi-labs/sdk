//! Runtime composition contracts for SDK modules.
//!
//! These traits are intentionally small: modules own typed state access and operation execution,
//! while a generated or hand-written runtime can aggregate selected modules into one transaction
//! enum, one genesis config, one event stream, and one chain application.

use std::future::Future;

use commonware_codec::{EncodeSize, Read, Write};

use crate::{Namespace, PoolTransaction, StateDb, StateStore};

/// Deterministic execution context supplied by the chain application.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeContext {
    /// Consensus epoch for the block being proposed, verified, or applied.
    pub epoch: u64,
}

/// A stateful SDK module that can be selected into a chain runtime.
///
/// Implementations should keep all storage below [`Self::NAMESPACE`] and expose their signed
/// operation as [`Self::Transaction`]. A runtime generator can wrap each module's transaction type
/// in a top-level enum and dispatch into this trait.
pub trait ChainModule {
    /// Human-readable module name used by code generation, diagnostics, and RPC grouping.
    const NAME: &'static str;

    /// Stable module namespace used to derive disjoint keys in the shared state database.
    const NAMESPACE: Namespace;

    /// User-authorized transaction handled by this module.
    type Transaction: PoolTransaction + EncodeSize + Read<Cfg = ()> + Write + Send + Sync + 'static;

    /// Module-specific genesis configuration.
    type Config: Clone + Send + Sync + 'static;

    /// Module-specific event emitted during execution.
    type Event: Clone + Send + Sync + 'static;

    /// Deterministic module execution error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Initialize module state at genesis.
    fn genesis<S>(
        state: &mut S,
        config: Self::Config,
    ) -> impl Future<Output = Result<Vec<Self::Event>, Self::Error>> + Send
    where
        S: StateDb + Send + Sync;

    /// Validate a transaction against scratch state without committing changes to the caller's
    /// committed database.
    ///
    /// Modules such as coins need to execute against an overlay to validate nonce and balance
    /// effects. Runtime code should pass a discardable overlay here, then call [`Self::apply`] with
    /// the real batch when the transaction is selected.
    fn validate<S>(
        state: &mut S,
        context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        S: StateStore + Send + Sync;

    /// Apply a transaction to state.
    fn apply<S>(
        state: &mut S,
        context: RuntimeContext,
        transaction: Self::Transaction,
    ) -> impl Future<Output = Result<Vec<Self::Event>, Self::Error>> + Send
    where
        S: StateStore + Send + Sync;
}

/// A complete chain runtime assembled from one or more [`ChainModule`] implementations.
///
/// Runtime generators should produce a type implementing this trait plus a tagged transaction enum
/// for [`Self::Transaction`]. Chain applications can then be generic over the runtime instead of
/// naming individual modules.
pub trait Runtime {
    /// Top-level transaction type accepted by the chain.
    type Transaction: PoolTransaction + EncodeSize + Read<Cfg = ()> + Write + Send + Sync + 'static;

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
    fn apply<S>(
        state: &mut S,
        context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        S: StateStore + Send + Sync;

    /// Whether an execution error indicates local storage failure instead of deterministic
    /// transaction invalidity.
    fn is_storage_error(error: &Self::Error) -> bool;
}
