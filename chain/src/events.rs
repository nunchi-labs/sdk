//! Finalized runtime event reporting boundary.
//!
//! # Status
//!
//! Finalized event batches are live execution output for external indexers. They are not
//! consensus state and are not committed to block digests.

use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use commonware_consensus::types::Height;
use commonware_cryptography::sha256::Digest;
use nunchi_common::Event;

/// Events emitted while applying a finalized block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedEvents<TxDigest = Digest> {
    /// Height of the finalized block.
    pub height: Height,
    /// Digest of the finalized block.
    pub block_digest: Digest,
    /// Block timestamp in milliseconds since the Unix epoch.
    pub block_timestamp: u64,
    /// Event batches grouped by transaction in block order.
    pub transactions: Vec<TransactionEvents<TxDigest>>,
}

/// Events emitted by a transaction in a finalized block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionEvents<TxDigest = Digest> {
    /// Zero-based transaction index within the block.
    pub tx_index: u32,
    /// Transaction digest exposed by the mempool transaction type.
    pub tx_digest: TxDigest,
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

/// Sink for finalized event batches.
pub trait EventReporter<TxDigest = Digest>: Clone + Send + Sync + 'static {
    /// Report a finalized event batch.
    fn finalized_events(
        &self,
        events: FinalizedEvents<TxDigest>,
    ) -> impl Future<Output = ()> + Send;
}

/// Event reporter that drops all finalized event batches.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopEventReporter;

impl<TxDigest> EventReporter<TxDigest> for NoopEventReporter {
    fn finalized_events(&self, _: FinalizedEvents<TxDigest>) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }
}

/// In-memory event reporter intended for tests.
#[derive(Debug)]
pub struct InMemoryEventReporter<TxDigest = Digest> {
    reports: Arc<Mutex<Vec<FinalizedEvents<TxDigest>>>>,
}

impl<TxDigest> Clone for InMemoryEventReporter<TxDigest> {
    fn clone(&self) -> Self {
        Self {
            reports: self.reports.clone(),
        }
    }
}

impl<TxDigest> InMemoryEventReporter<TxDigest> {
    /// Create an empty in-memory reporter.
    pub fn new() -> Self {
        Self {
            reports: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Return a snapshot of all reports received so far.
    pub fn reports(&self) -> Vec<FinalizedEvents<TxDigest>>
    where
        TxDigest: Clone,
    {
        self.reports
            .lock()
            .expect("event reporter poisoned")
            .clone()
    }

    /// Return the number of reports received so far.
    pub fn len(&self) -> usize {
        self.reports.lock().expect("event reporter poisoned").len()
    }

    /// Return true when no reports have been received.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<TxDigest> Default for InMemoryEventReporter<TxDigest> {
    fn default() -> Self {
        Self::new()
    }
}

impl<TxDigest> EventReporter<TxDigest> for InMemoryEventReporter<TxDigest>
where
    TxDigest: Send + 'static,
{
    fn finalized_events(
        &self,
        events: FinalizedEvents<TxDigest>,
    ) -> impl Future<Output = ()> + Send {
        let reports = self.reports.clone();
        async move {
            reports
                .lock()
                .expect("event reporter poisoned")
                .push(events);
        }
    }
}
