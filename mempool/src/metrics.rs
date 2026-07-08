use crate::error::{AdmissionError, DropReason};
use commonware_runtime::{
    telemetry::metrics::{
        histogram::Buckets, Counter, CounterFamily, EncodeLabelSet, EncodeLabelValue, Gauge,
        GaugeExt, Histogram, MetricsExt as _,
    },
    Metrics as RuntimeMetrics,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct AdmissionLabel {
    status: AdmissionStatus,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelValue)]
enum AdmissionStatus {
    Accepted,
    Duplicate,
    InvalidSignature,
    TooLarge,
    StaleNonce,
    AccountQueueFull,
    PoolFull,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct SourceLabel {
    source: SubmitSource,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelValue)]
pub(crate) enum SubmitSource {
    Rpc,
    RpcBatch,
    P2p,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct DropLabel {
    reason: DropStatus,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelValue)]
enum DropStatus {
    Evicted,
    Replaced,
    StaleNonce,
    Expired,
}

#[derive(Clone)]
pub(crate) struct MempoolMetrics {
    transactions: Gauge,
    lanes: Gauge,
    ready_lanes: Gauge,
    ready_transactions: Gauge,
    submissions: CounterFamily<AdmissionLabel>,
    submitted_transactions: CounterFamily<SourceLabel>,
    dropped_transactions: CounterFamily<DropLabel>,
    finalized_transactions: Counter,
    pending_requests: Counter,
    pending_returned_transactions: Counter,
    pub submit_duration: Histogram,
    pub pending_duration: Histogram,
    pub finalize_duration: Histogram,
}

impl MempoolMetrics {
    pub fn register<E: RuntimeMetrics>(context: &E) -> Self {
        Self {
            transactions: context.gauge("transactions", "current pooled transaction count"),
            lanes: context.gauge("lanes", "current nonce lane count"),
            ready_lanes: context.gauge("ready_lanes", "current executable nonce lane count"),
            ready_transactions: context.gauge(
                "ready_transactions",
                "current executable transaction count across ready lanes",
            ),
            submissions: context.family("submissions", "transaction admission outcomes by status"),
            submitted_transactions: context
                .family("submitted_transactions", "submitted transactions by source"),
            dropped_transactions: context.family(
                "dropped_transactions",
                "transactions dropped from the pool by reason",
            ),
            finalized_transactions: context.counter(
                "finalized_transactions",
                "pooled transactions removed after finalization",
            ),
            pending_requests: context.counter("pending_requests", "proposal candidate pulls"),
            pending_returned_transactions: context.counter(
                "pending_returned_transactions",
                "transactions returned to block builders",
            ),
            submit_duration: context.histogram(
                "submit_duration_seconds",
                "end-to-end transaction submission duration",
                Buckets::LOCAL,
            ),
            pending_duration: context.histogram(
                "pending_duration_seconds",
                "proposal candidate selection duration",
                Buckets::LOCAL,
            ),
            finalize_duration: context.histogram(
                "finalize_duration_seconds",
                "mempool finalization update duration",
                Buckets::LOCAL,
            ),
        }
    }

    pub fn set_pool_stats(
        &self,
        transactions: usize,
        lanes: usize,
        ready_lanes: usize,
        ready_transactions: usize,
    ) {
        let _ = self.transactions.try_set(transactions);
        let _ = self.lanes.try_set(lanes);
        let _ = self.ready_lanes.try_set(ready_lanes);
        let _ = self.ready_transactions.try_set(ready_transactions);
    }

    pub fn submitted(&self, source: SubmitSource, count: u64) {
        self.submitted_transactions
            .get_or_create(&SourceLabel { source })
            .inc_by(count);
    }

    pub fn submission_result(&self, result: &Result<impl Sized, AdmissionError>) {
        let status = match result {
            Ok(_) => AdmissionStatus::Accepted,
            Err(error) => AdmissionStatus::from(error),
        };
        self.submissions
            .get_or_create(&AdmissionLabel { status })
            .inc();
    }

    pub fn dropped(&self, reason: DropReason) {
        self.dropped_transactions
            .get_or_create(&DropLabel {
                reason: DropStatus::from(reason),
            })
            .inc();
    }

    pub fn finalized(&self, count: u64) {
        self.finalized_transactions.inc_by(count);
    }

    pub fn pending(&self, returned: u64) {
        self.pending_requests.inc();
        self.pending_returned_transactions.inc_by(returned);
    }
}

impl From<&AdmissionError> for AdmissionStatus {
    fn from(error: &AdmissionError) -> Self {
        match error {
            AdmissionError::InvalidSignature(_) => Self::InvalidSignature,
            AdmissionError::TxTooLarge { .. } => Self::TooLarge,
            AdmissionError::Duplicate => Self::Duplicate,
            AdmissionError::StaleNonce { .. } => Self::StaleNonce,
            AdmissionError::AccountQueueFull => Self::AccountQueueFull,
            AdmissionError::PoolFull => Self::PoolFull,
            AdmissionError::Shutdown => Self::Shutdown,
        }
    }
}

impl From<DropReason> for DropStatus {
    fn from(reason: DropReason) -> Self {
        match reason {
            DropReason::Evicted => Self::Evicted,
            DropReason::Replaced => Self::Replaced,
            DropReason::StaleNonce => Self::StaleNonce,
            DropReason::Expired => Self::Expired,
        }
    }
}
