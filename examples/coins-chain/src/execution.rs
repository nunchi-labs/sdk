//! Execution of finalized blocks against the coins ledger.

use crate::block::Block;
use crate::txpool::Submitter;
use commonware_actor::{
    mailbox::{self, Policy},
    Feedback,
};
use commonware_consensus::{marshal::Update, types::Height, Heightable, Reporter};
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{Handle, Spawner};
use commonware_storage::Context;
use commonware_utils::{acknowledgement::Exact, Acknowledgement};
use futures::lock::Mutex as AsyncMutex;
use nunchi_coins::{Ledger, LedgerError};
use nunchi_common::QmdbState;
use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::debug;

/// A validator's committed coin ledger plus the height of the last finalized block applied to it.
pub struct ChainState<E: Context> {
    pub ledger: Ledger<QmdbState<E>>,
    pub applied_height: Height,
}

/// A coin ledger shared between the [`Executor`] (which writes) and clients/tests (which read).
pub type SharedLedger<E> = Arc<AsyncMutex<ChainState<E>>>;

/// A node's externally reachable handles, returned by [`Engine::new`](crate::engine::Engine::new):
/// submit transactions to this node, and read its committed coin ledger.
///
/// In production a node has exactly one of these. An in-process multi-node harness collects them
/// (e.g. into a map keyed by public key) to drive and observe multiple validators.
#[derive(Clone)]
pub struct NodeHandle<E: Context> {
    pub submitter: Submitter,
    pub ledger: SharedLedger<E>,
}

/// A finalized block delivered to the executor, with the acknowledgement the marshal awaits.
struct FinalizedBlock {
    block: Block,
    ack: Exact,
}

impl Policy for FinalizedBlock {
    type Overflow = VecDeque<Self>;

    // Finalized blocks must never be dropped: any block that doesn't fit the bounded ready queue is
    // retained in overflow and delivered later.
    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

/// The executor's report sink.
#[derive(Clone)]
pub struct Mailbox {
    sender: mailbox::Sender<FinalizedBlock>,
}

impl Reporter for Mailbox {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Update::Block(block, ack) => self.sender.enqueue(FinalizedBlock { block, ack }),
            Update::Tip(..) => Feedback::Ok,
        }
    }
}

/// Drives validator's coin ledger forward as blocks finalize.
pub struct Executor<E: Context> {
    ledger: SharedLedger<E>,
    receiver: mailbox::Receiver<FinalizedBlock>,
    submitter: Submitter,
}

impl<E: Context + Spawner + Send + 'static> Executor<E> {
    /// Create an executor and its [`Mailbox`] report sink.
    pub fn new(
        context: &E,
        capacity: NonZeroUsize,
        ledger: SharedLedger<E>,
        submitter: Submitter,
    ) -> (Self, Mailbox) {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), capacity);
        (
            Self {
                ledger,
                receiver,
                submitter,
            },
            Mailbox { sender },
        )
    }

    /// Spawn the execution loop.
    pub fn start(self, context: E) -> Handle<()> {
        context.spawn(|_| self.run())
    }

    async fn run(mut self) {
        while let Some(FinalizedBlock { block, ack }) = self.receiver.recv().await {
            match self.apply_block(&block).await {
                Ok(applied) => {
                    self.submitter.prune(applied);
                    ack.acknowledge();
                }
                Err(e) => {
                    // TODO: in this case, we should not panic but bubble the
                    // error up to gracefully shut down the application. Alas,
                    // we have no graceful shutdown yet.
                    panic!("failed to apply block: {e}")
                }
            }
        }
    }

    /// Apply a finalized block, returning the digests of transactions that took effect.
    async fn apply_block(&self, block: &Block) -> Result<Vec<Digest>, LedgerError> {
        let mut state = self.ledger.lock().await;
        let mut applied = Vec::new();
        for transaction in &block.transactions {
            // Operations that don't currently apply (e.g. a transaction whose ledger nonce hasn't
            // been reached yet, or whose token doesn't exist yet) are skipped rather than fatal.
            // Every node skips the same ones, so convergence is preserved and the chain never halts
            // on a transaction that isn't applicable in this position.
            match state.ledger.apply_transaction(transaction).await {
                Ok(()) => applied.push(transaction.digest()),
                Err(err @ LedgerError::Storage(_)) => {
                    return Err(err);
                }
                Err(error) => debug!(
                    height = %block.height(),
                    ?error,
                    "skipped coin transaction"
                ),
            }
        }

        // Only commit when the block actually mutated state.
        if !applied.is_empty() {
            if let Err(err @ LedgerError::Storage(_)) = state.ledger.commit().await {
                return Err(err);
            }
        }
        state.applied_height = block.height();
        Ok(applied)
    }
}
