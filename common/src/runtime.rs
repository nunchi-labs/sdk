//! Runtime composition contracts for SDK modules.
//!
//! These traits are intentionally small: modules own typed state access and operation execution,
//! while a generated or hand-written runtime can aggregate selected modules into one transaction
//! enum, one genesis config, one event stream, and one chain application.

use std::future::Future;

use commonware_codec::{EncodeSize, Read, Write};

use crate::{Namespace, PoolTransaction, StateDb, StateStore};

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
        transaction: &Self::Transaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        S: StateStore + Send + Sync;

    /// Apply a transaction to state.
    fn apply<S>(
        state: &mut S,
        transaction: Self::Transaction,
    ) -> impl Future<Output = Result<Vec<Self::Event>, Self::Error>> + Send
    where
        S: StateStore + Send + Sync;
}

/// Optional consensus-side extension carried by blocks but driven outside ordinary transactions.
pub trait ConsensusExtension<Block> {
    /// Extension payload embedded in a proposed block.
    type Payload: Clone + Send + Sync + 'static;

    /// Produce an optional payload for the next proposal.
    fn propose(&mut self) -> impl Future<Output = Option<Self::Payload>> + Send;

    /// Verify the extension payload on a candidate block.
    fn verify(&mut self, block: &Block) -> impl Future<Output = bool> + Send;

    /// Observe a finalized block after it is applied.
    fn finalized(&mut self, block: &Block) -> impl Future<Output = ()> + Send;
}

/// Empty consensus extension for chains without DKG/authority payloads.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoConsensusExtension;

impl<Block> ConsensusExtension<Block> for NoConsensusExtension
where
    Block: Sync,
{
    type Payload = ();

    async fn propose(&mut self) -> Option<Self::Payload> {
        None
    }

    async fn verify(&mut self, _block: &Block) -> bool {
        true
    }

    async fn finalized(&mut self, _block: &Block) {}
}
