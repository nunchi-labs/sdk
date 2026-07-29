//! Runtime event consumption boundary.
//!
//! # Status
//!
//! Runtime events are live execution output for external indexers. They are not consensus state
//! and are not committed to block digests.

use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex},
};

use commonware_consensus::types::Height;
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Event, EventSink, NoopEventSink, RuntimeContext};

/// Transaction metadata attached to emitted runtime events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionEventContext {
    /// Zero-based transaction index within the block.
    pub tx_index: u32,
    /// Transaction digest exposed by the mempool transaction type.
    pub tx_digest: Digest,
}

/// Events emitted while applying a finalized block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedEvents {
    /// Height of the finalized block.
    pub height: Height,
    /// Digest of the finalized block.
    pub block_digest: Digest,
    /// Block timestamp in milliseconds since the Unix epoch.
    pub block_timestamp: u64,
    /// Event batches grouped by transaction in block order.
    pub transactions: Vec<TransactionEvents>,
}

/// Events emitted by a transaction in a finalized block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionEvents {
    /// Zero-based transaction index within the block.
    pub tx_index: u32,
    /// Transaction digest exposed by the mempool transaction type.
    pub tx_digest: Digest,
    /// Events emitted by the transaction in emission order.
    pub events: Vec<IndexedEvent>,
}

/// Event with its zero-based index within a transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedEvent {
    /// Zero-based event index within the transaction.
    pub event_index: u32,
    /// Runtime event payload.
    pub event: Event,
}

/// Consumer for events emitted during block execution.
///
/// Implementations decide whether events are dropped, buffered until finalization, or forwarded
/// elsewhere. The chain application only supplies block and transaction context.
///
/// # Call ordering
///
/// The expected call sequence for a successfully executed block is:
///
/// ```text
/// begin_block -> (transaction_sink -> transaction_applied)* -> finalized
/// ```
///
/// If a transaction fails during execution, the block is discarded instead:
///
/// ```text
/// begin_block -> (transaction_sink -> transaction_applied)* -> discard_block
/// ```
///
/// `transaction_applied` is only called for transactions that succeed; failed transactions
/// cause the entire block to be discarded via `discard_block`.
///
/// # State sync
///
/// During state sync, `finalized` may be called **without** a preceding `begin_block`,
/// because the block was finalized without being applied locally. Implementations must
/// handle a missing pending entry gracefully (e.g., produce an empty event set).
///
/// # Concurrency
///
/// The trait requires `Clone + Send + Sync`. Multiple concurrent `begin_block` calls for
/// different blocks are expected (e.g., during `verify` and `apply` concurrently).
/// Implementations should use interior mutability (e.g., `Arc<Mutex<..>>`) to handle this.
///
/// `discard_block` may be called multiple times for the same digest and should be idempotent.
pub trait EventConsumer: Clone + Send + Sync + 'static {
    /// Sink used for a single transaction execution.
    type Sink: EventSink + Send;

    /// Prepare to receive events for a new block.
    ///
    /// Called once per block before any transactions are executed. After this call, the
    /// consumer should expect zero or more `transaction_sink`/`transaction_applied` pairs,
    /// followed by either `finalized` or `discard_block`.
    ///
    /// Note: `finalized` may also be called without a preceding `begin_block` during
    /// state sync -- see the trait-level documentation.
    fn begin_block(&self, context: RuntimeContext) -> impl Future<Output = ()> + Send;

    /// Return a fresh event sink for a transaction about to be executed.
    ///
    /// The returned sink collects events emitted by the runtime during transaction
    /// execution. If the transaction succeeds, the sink is passed to
    /// [`transaction_applied`](Self::transaction_applied). If the transaction fails,
    /// the sink is dropped and `discard_block` is called.
    fn transaction_sink(
        &self,
        context: RuntimeContext,
        transaction: TransactionEventContext,
    ) -> Self::Sink;

    /// Accept events from a successfully applied transaction.
    ///
    /// Only called for transactions that succeed. Never called for failed transactions.
    fn transaction_applied(&self, sink: Self::Sink) -> impl Future<Output = ()> + Send;

    /// Discard all events collected for the block identified by `block_digest`.
    ///
    /// Called when a block fails execution (e.g., a transaction error or extension
    /// verification failure). May be called multiple times for the same digest;
    /// implementations should handle this idempotently.
    fn discard_block(&self, block_digest: Digest) -> impl Future<Output = ()> + Send;

    /// Observe that the block described by `context` has been finalized.
    ///
    /// During normal operation, this follows a `begin_block` and zero or more
    /// `transaction_sink`/`transaction_applied` pairs. During state sync, this may
    /// be called without any preceding calls for the block; implementations should
    /// handle a missing pending entry gracefully.
    fn finalized(&self, context: RuntimeContext) -> impl Future<Output = ()> + Send;
}

/// Event consumer that drops all emitted events.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopEventConsumer;

impl EventConsumer for NoopEventConsumer {
    type Sink = NoopEventSink;

    fn begin_block(&self, _: RuntimeContext) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }

    fn transaction_sink(&self, _: RuntimeContext, _: TransactionEventContext) -> Self::Sink {
        NoopEventSink
    }

    fn transaction_applied(&self, _: Self::Sink) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }

    fn discard_block(&self, _: Digest) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }

    fn finalized(&self, _: RuntimeContext) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }
}

/// Transaction event sink used by [`InMemoryEventConsumer`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionEventSink {
    context: RuntimeContext,
    transaction: TransactionEventContext,
    events: Vec<Event>,
}

impl TransactionEventSink {
    fn new(context: RuntimeContext, transaction: TransactionEventContext) -> Self {
        Self {
            context,
            transaction,
            events: Vec::new(),
        }
    }
}

impl EventSink for TransactionEventSink {
    fn emit(&mut self, event: Event) {
        self.events.push(event);
    }
}

/// In-memory event consumer intended for tests.
#[derive(Debug)]
pub struct InMemoryEventConsumer {
    pending: Arc<Mutex<HashMap<Digest, FinalizedEvents>>>,
    reports: Arc<Mutex<Vec<FinalizedEvents>>>,
}

impl Clone for InMemoryEventConsumer {
    fn clone(&self) -> Self {
        Self {
            pending: self.pending.clone(),
            reports: self.reports.clone(),
        }
    }
}

impl InMemoryEventConsumer {
    /// Create an empty in-memory consumer.
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            reports: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Return a snapshot of all reports received so far.
    pub fn reports(&self) -> Vec<FinalizedEvents> {
        self.reports
            .lock()
            .expect("event consumer poisoned")
            .clone()
    }

    /// Return the number of reports received so far.
    pub fn len(&self) -> usize {
        self.reports.lock().expect("event consumer poisoned").len()
    }

    /// Return true when no reports have been received.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemoryEventConsumer {
    fn default() -> Self {
        Self::new()
    }
}

impl EventConsumer for InMemoryEventConsumer {
    type Sink = TransactionEventSink;

    fn begin_block(&self, context: RuntimeContext) -> impl Future<Output = ()> + Send {
        let pending = self.pending.clone();
        async move {
            let block_digest = context
                .block_digest
                .expect("event consumer received context without block digest");
            pending.lock().expect("event consumer poisoned").insert(
                block_digest,
                FinalizedEvents {
                    height: Height::new(context.height),
                    block_digest,
                    block_timestamp: context.timestamp_ms,
                    transactions: Vec::new(),
                },
            );
        }
    }

    fn transaction_sink(
        &self,
        context: RuntimeContext,
        transaction: TransactionEventContext,
    ) -> Self::Sink {
        TransactionEventSink::new(context, transaction)
    }

    fn transaction_applied(&self, sink: Self::Sink) -> impl Future<Output = ()> + Send {
        let pending = self.pending.clone();
        async move {
            let events = sink
                .events
                .into_iter()
                .enumerate()
                .map(|(event_index, event)| IndexedEvent {
                    event_index: u32::try_from(event_index)
                        .expect("transaction emitted more than u32::MAX events"),
                    event,
                })
                .collect();

            let block_digest = sink
                .context
                .block_digest
                .expect("event consumer received context without block digest");
            let mut pending = pending.lock().expect("event consumer poisoned");
            let events_for_block = pending
                .entry(block_digest)
                .or_insert_with(|| FinalizedEvents {
                    height: Height::new(sink.context.height),
                    block_digest,
                    block_timestamp: sink.context.timestamp_ms,
                    transactions: Vec::new(),
                });
            events_for_block.transactions.push(TransactionEvents {
                tx_index: sink.transaction.tx_index,
                tx_digest: sink.transaction.tx_digest,
                events,
            });
        }
    }

    fn discard_block(&self, block_digest: Digest) -> impl Future<Output = ()> + Send {
        let pending = self.pending.clone();
        async move {
            pending
                .lock()
                .expect("event consumer poisoned")
                .remove(&block_digest);
        }
    }

    fn finalized(&self, context: RuntimeContext) -> impl Future<Output = ()> + Send {
        let pending = self.pending.clone();
        let reports = self.reports.clone();
        async move {
            let block_digest = context
                .block_digest
                .expect("event consumer received context without block digest");
            let events = pending
                .lock()
                .expect("event consumer poisoned")
                .remove(&block_digest)
                .unwrap_or_else(|| FinalizedEvents {
                    height: Height::new(context.height),
                    block_digest,
                    block_timestamp: context.timestamp_ms,
                    transactions: Vec::new(),
                });
            reports
                .lock()
                .expect("event consumer poisoned")
                .push(events);
        }
    }
}
