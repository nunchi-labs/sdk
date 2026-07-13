use crate::{Block, Finalized};
use commonware_runtime::{
    telemetry::metrics::{
        encoding::EncodeLabelValue as EncodeLabelValueTrait, histogram::Buckets, raw,
        Counter, CounterFamily, EncodeLabelSet, Gauge, GaugeExt as _, GaugeFamily, GaugeValue,
        HistogramExt as _, MetricsExt as _, Registered,
    },
    Clock, Metrics,
};
use std::{
    fmt,
    time::{Duration, Instant, SystemTime},
};

type HistogramFamily<L> = Registered<raw::Family<L, raw::Histogram, fn() -> raw::Histogram>>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum LiveUploadArtifact {
    NotarizedSeed,
    FinalizedSeed,
    NotarizedBlock,
    FinalizedBlock,
}

impl LiveUploadArtifact {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NotarizedSeed => "notarized_seed",
            Self::FinalizedSeed => "finalized_seed",
            Self::NotarizedBlock => "notarized_block",
            Self::FinalizedBlock => "finalized_block",
        }
    }
}

impl EncodeLabelValueTrait for LiveUploadArtifact {
    fn encode(
        &self,
        encoder: &mut commonware_runtime::telemetry::metrics::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum LiveUploadStatus {
    Success,
    HttpError,
    MarshalCancelled,
}

impl LiveUploadStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::HttpError => "http_error",
            Self::MarshalCancelled => "marshal_cancelled",
        }
    }
}

impl EncodeLabelValueTrait for LiveUploadStatus {
    fn encode(
        &self,
        encoder: &mut commonware_runtime::telemetry::metrics::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum LiveMarshalWaitStatus {
    Found,
    Cancelled,
}

impl LiveMarshalWaitStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Found => "found",
            Self::Cancelled => "cancelled",
        }
    }
}

impl EncodeLabelValueTrait for LiveMarshalWaitStatus {
    fn encode(
        &self,
        encoder: &mut commonware_runtime::telemetry::metrics::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum HttpArtifact {
    DkgOutput,
    Seed,
    Notarization,
    Finalization,
}

impl HttpArtifact {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::DkgOutput => "dkg_output",
            Self::Seed => "seed",
            Self::Notarization => "notarization",
            Self::Finalization => "finalization",
        }
    }
}

impl EncodeLabelValueTrait for HttpArtifact {
    fn encode(
        &self,
        encoder: &mut commonware_runtime::telemetry::metrics::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum HttpRequestStatus {
    Success,
    HttpStatusError,
    TransportError,
}

impl HttpRequestStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::HttpStatusError => "http_status_error",
            Self::TransportError => "transport_error",
        }
    }
}

impl EncodeLabelValueTrait for HttpRequestStatus {
    fn encode(
        &self,
        encoder: &mut commonware_runtime::telemetry::metrics::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum BlockMetricSource {
    ProducerRecord,
    LiveCertificate,
    ConsumerCached,
    ConsumerMarshal,
}

impl BlockMetricSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ProducerRecord => "producer_record",
            Self::LiveCertificate => "live_certificate",
            Self::ConsumerCached => "consumer_cached",
            Self::ConsumerMarshal => "consumer_marshal",
        }
    }
}

impl EncodeLabelValueTrait for BlockMetricSource {
    fn encode(
        &self,
        encoder: &mut commonware_runtime::telemetry::metrics::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum SharedCacheSource {
    ProducerRecord,
    LiveCertificate,
    ConsumerMarshal,
}

impl SharedCacheSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ProducerRecord => "producer_record",
            Self::LiveCertificate => "live_certificate",
            Self::ConsumerMarshal => "consumer_marshal",
        }
    }
}

impl EncodeLabelValueTrait for SharedCacheSource {
    fn encode(
        &self,
        encoder: &mut commonware_runtime::telemetry::metrics::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum SharedRetentionReason {
    Uploaded,
    CertificateFinished,
    Pruned,
}

impl SharedRetentionReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Uploaded => "uploaded",
            Self::CertificateFinished => "certificate_finished",
            Self::Pruned => "pruned",
        }
    }
}

impl EncodeLabelValueTrait for SharedRetentionReason {
    fn encode(
        &self,
        encoder: &mut commonware_runtime::telemetry::metrics::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum BackfillStatus {
    Uploaded,
    Skipped,
}

impl BackfillStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Uploaded => "uploaded",
            Self::Skipped => "skipped",
        }
    }
}

impl EncodeLabelValueTrait for BackfillStatus {
    fn encode(
        &self,
        encoder: &mut commonware_runtime::telemetry::metrics::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum BackfillDecision {
    Skip,
    Wait,
    Proceed,
}

impl BackfillDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Wait => "wait",
            Self::Proceed => "proceed",
        }
    }
}

impl EncodeLabelValueTrait for BackfillDecision {
    fn encode(
        &self,
        encoder: &mut commonware_runtime::telemetry::metrics::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum BackfillPhase {
    Start,
    BeforeBlock,
    BeforeAttempt,
}

impl BackfillPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::BeforeBlock => "before_block",
            Self::BeforeAttempt => "before_attempt",
        }
    }
}

impl EncodeLabelValueTrait for BackfillPhase {
    fn encode(
        &self,
        encoder: &mut commonware_runtime::telemetry::metrics::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum BackfillWaitReason {
    CertificateUpload,
    MissingBlock,
    MissingFinalization,
    MismatchedFinalization,
    HttpError,
}

impl BackfillWaitReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CertificateUpload => "certificate_upload",
            Self::MissingBlock => "missing_block",
            Self::MissingFinalization => "missing_finalization",
            Self::MismatchedFinalization => "mismatched_finalization",
            Self::HttpError => "http_error",
        }
    }
}

impl EncodeLabelValueTrait for BackfillWaitReason {
    fn encode(
        &self,
        encoder: &mut commonware_runtime::telemetry::metrics::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        use fmt::Write as _;

        encoder.write_str(self.as_str())
    }
}

pub(crate) struct SharedStateSnapshot {
    pub(crate) cached_blocks: usize,
    pub(crate) cached_block_estimated_bytes: u64,
    pub(crate) certificate_upload_digests: usize,
    pub(crate) certificate_upload_refs: usize,
    pub(crate) uploaded_digests: usize,
    pub(crate) latest_finalized_height: u64,
    pub(crate) acked_through_height: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ArtifactLabel {
    artifact: LiveUploadArtifact,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct CompletionLabel {
    artifact: LiveUploadArtifact,
    status: LiveUploadStatus,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct MarshalWaitCompletionLabel {
    artifact: LiveUploadArtifact,
    status: LiveMarshalWaitStatus,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct HttpArtifactLabel {
    artifact: HttpArtifact,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct HttpCompletionLabel {
    artifact: HttpArtifact,
    status: HttpRequestStatus,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct BlockSourceLabel {
    source: BlockMetricSource,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct SharedCacheSourceLabel {
    source: SharedCacheSource,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct SharedRetentionReasonLabel {
    reason: SharedRetentionReason,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct BackfillCompletionLabel {
    status: BackfillStatus,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct BackfillDecisionLabel {
    decision: BackfillDecision,
    phase: BackfillPhase,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct BackfillWaitReasonLabel {
    reason: BackfillWaitReason,
}

#[derive(Clone)]
pub(crate) struct IndexerMetrics {
    live_upload_spawned: CounterFamily<ArtifactLabel>,
    live_upload_in_flight: GaugeFamily<ArtifactLabel>,
    live_upload_completed: CounterFamily<CompletionLabel>,
    live_upload_duration: HistogramFamily<CompletionLabel>,
    live_marshal_wait_in_flight: Gauge,
    live_marshal_wait_completed: CounterFamily<MarshalWaitCompletionLabel>,
    live_marshal_wait_duration: HistogramFamily<MarshalWaitCompletionLabel>,
    http_encode: CounterFamily<HttpArtifactLabel>,
    http_encode_bytes: HistogramFamily<HttpArtifactLabel>,
    http_encode_duration: HistogramFamily<HttpArtifactLabel>,
    http_request_body_in_flight_bytes: GaugeFamily<HttpArtifactLabel>,
    http_request_in_flight: GaugeFamily<HttpArtifactLabel>,
    http_request_completed: CounterFamily<HttpCompletionLabel>,
    http_request_duration: HistogramFamily<HttpCompletionLabel>,
    block_estimated_bytes: HistogramFamily<BlockSourceLabel>,
    block_transaction_count: HistogramFamily<BlockSourceLabel>,
    shared_cached_blocks: Gauge,
    shared_cached_block_estimated_bytes: Gauge,
    shared_certificate_upload_digests: Gauge,
    shared_certificate_upload_refs: Gauge,
    shared_uploaded_digests: Gauge,
    shared_latest_finalized_height: Gauge,
    shared_acked_through_height: Gauge,
    shared_pruned: CounterFamily<SharedRetentionReasonLabel>,
    shared_cache_inserted: CounterFamily<SharedCacheSourceLabel>,
    shared_cache_removed: CounterFamily<SharedRetentionReasonLabel>,
    backfill_active_uploads: Gauge,
    backfill_max_active: Gauge,
    backfill_started: Counter,
    backfill_completed: CounterFamily<BackfillCompletionLabel>,
    backfill_upload_duration: HistogramFamily<BackfillCompletionLabel>,
    backfill_decision: CounterFamily<BackfillDecisionLabel>,
    backfill_wait_duration: HistogramFamily<BackfillWaitReasonLabel>,
    backfill_retry: CounterFamily<BackfillWaitReasonLabel>,
    backfill_active_block_estimated_bytes: Gauge,
    backfill_active_body_estimated_bytes: Gauge,
}

impl IndexerMetrics {
    pub(crate) fn register<E: Metrics>(context: &E) -> Self {
        Self {
            live_upload_spawned: context.family(
                "live_upload_spawn",
                "Total number of live indexer upload tasks spawned by artifact",
            ),
            live_upload_in_flight: context.family(
                "live_upload_in_flight",
                "Current number of live indexer upload tasks by artifact",
            ),
            live_upload_completed: context.family(
                "live_upload_complete",
                "Total number of live indexer upload task outcomes by artifact and status",
            ),
            live_upload_duration: context.register(
                "live_upload_duration_seconds",
                "Duration of live indexer upload tasks by artifact and status",
                raw::Family::<CompletionLabel, raw::Histogram, fn() -> raw::Histogram>::new_with_constructor(
                    local_histogram,
                ),
            ),
            live_marshal_wait_in_flight: context.gauge(
                "live_marshal_wait_in_flight",
                "Current number of live indexer upload tasks waiting on marshal block lookup",
            ),
            live_marshal_wait_completed: context.family(
                "live_marshal_wait_complete",
                "Total number of live marshal wait outcomes by artifact and status",
            ),
            live_marshal_wait_duration: context.register(
                "live_marshal_wait_duration_seconds",
                "Duration of live indexer marshal waits by artifact and status",
                raw::Family::<MarshalWaitCompletionLabel, raw::Histogram, fn() -> raw::Histogram>::new_with_constructor(
                    local_histogram,
                ),
            ),
            http_encode: context.family(
                "http_encode",
                "Total number of indexer HTTP request body encodes by artifact",
            ),
            http_encode_bytes: context.register(
                "http_encode_bytes",
                "Encoded indexer HTTP request body size by artifact",
                raw::Family::<HttpArtifactLabel, raw::Histogram, fn() -> raw::Histogram>::new_with_constructor(
                    local_histogram,
                ),
            ),
            http_encode_duration: context.register(
                "http_encode_duration_seconds",
                "Duration of indexer HTTP request body encoding by artifact",
                raw::Family::<HttpArtifactLabel, raw::Histogram, fn() -> raw::Histogram>::new_with_constructor(
                    local_histogram,
                ),
            ),
            http_request_body_in_flight_bytes: context.family(
                "http_request_body_in_flight_bytes",
                "Current encoded indexer HTTP request body bytes in flight by artifact",
            ),
            http_request_in_flight: context.family(
                "http_request_in_flight",
                "Current indexer HTTP requests in flight by artifact",
            ),
            http_request_completed: context.family(
                "http_request_complete",
                "Total number of indexer HTTP request outcomes by artifact and status",
            ),
            http_request_duration: context.register(
                "http_request_duration_seconds",
                "Duration of indexer HTTP requests by artifact and status",
                raw::Family::<HttpCompletionLabel, raw::Histogram, fn() -> raw::Histogram>::new_with_constructor(
                    local_histogram,
                ),
            ),
            block_estimated_bytes: context.register(
                "block_estimated_bytes",
                "Estimated encoded block size by source",
                raw::Family::<BlockSourceLabel, raw::Histogram, fn() -> raw::Histogram>::new_with_constructor(
                    local_histogram,
                ),
            ),
            block_transaction_count: context.register(
                "block_transaction_count",
                "Block transaction count by source",
                raw::Family::<BlockSourceLabel, raw::Histogram, fn() -> raw::Histogram>::new_with_constructor(
                    local_histogram,
                ),
            ),
            shared_cached_blocks: context.gauge(
                "shared_cached_blocks",
                "Current number of full blocks retained by shared indexer state",
            ),
            shared_cached_block_estimated_bytes: context.gauge(
                "shared_cached_block_estimated_bytes",
                "Current estimated encoded bytes retained by shared indexer cached blocks",
            ),
            shared_certificate_upload_digests: context.gauge(
                "shared_certificate_upload_digests",
                "Current number of digests with live certificate uploads in shared indexer state",
            ),
            shared_certificate_upload_refs: context.gauge(
                "shared_certificate_upload_refs",
                "Current total live certificate upload references in shared indexer state",
            ),
            shared_uploaded_digests: context.gauge(
                "shared_uploaded_digests",
                "Current number of uploaded digest dedupe entries in shared indexer state",
            ),
            shared_latest_finalized_height: context.gauge(
                "shared_latest_finalized_height",
                "Latest finalized height observed by shared indexer state",
            ),
            shared_acked_through_height: context.gauge(
                "shared_acked_through_height",
                "Queue acknowledgement floor tracked by shared indexer state",
            ),
            shared_pruned: context.family(
                "shared_prune",
                "Total shared indexer state retention removals by reason",
            ),
            shared_cache_inserted: context.family(
                "shared_cache_insert",
                "Total shared indexer cached block insertions by source",
            ),
            shared_cache_removed: context.family(
                "shared_cache_remove",
                "Total shared indexer cached block removals by reason",
            ),
            backfill_active_uploads: context.gauge(
                "backfill_active_uploads",
                "Current number of durable backfill upload tasks",
            ),
            backfill_max_active: context.gauge(
                "backfill_max_active",
                "Configured maximum number of active durable backfill upload tasks",
            ),
            backfill_started: context.counter(
                "backfill_start",
                "Total durable backfill work items started",
            ),
            backfill_completed: context.family(
                "backfill_complete",
                "Total durable backfill work item outcomes by status",
            ),
            backfill_upload_duration: context.register(
                "backfill_upload_duration_seconds",
                "Duration of durable backfill work items by status",
                raw::Family::<BackfillCompletionLabel, raw::Histogram, fn() -> raw::Histogram>::new_with_constructor(
                    local_histogram,
                ),
            ),
            backfill_decision: context.family(
                "backfill_decision",
                "Total durable backfill upload decisions by decision and phase",
            ),
            backfill_wait_duration: context.register(
                "backfill_wait_duration_seconds",
                "Duration of durable backfill waits by reason",
                raw::Family::<BackfillWaitReasonLabel, raw::Histogram, fn() -> raw::Histogram>::new_with_constructor(
                    local_histogram,
                ),
            ),
            backfill_retry: context.family(
                "backfill_retry",
                "Total durable backfill retries by reason",
            ),
            backfill_active_block_estimated_bytes: context.gauge(
                "backfill_active_block_estimated_bytes",
                "Current estimated encoded block bytes held by durable backfill upload tasks",
            ),
            backfill_active_body_estimated_bytes: context.gauge(
                "backfill_active_body_estimated_bytes",
                "Current estimated encoded HTTP body bytes held by durable backfill upload tasks",
            ),
        }
    }

    pub(crate) fn live_upload_spawned(&self, artifact: LiveUploadArtifact) {
        self.live_upload_spawned
            .get_or_create(&ArtifactLabel { artifact })
            .inc();
    }

    pub(crate) fn start_live_upload<C: Clock>(
        &self,
        context: C,
        artifact: LiveUploadArtifact,
    ) -> LiveUploadGuard<C> {
        self.live_upload_in_flight
            .get_or_create(&ArtifactLabel { artifact })
            .inc();
        LiveUploadGuard {
            metrics: self.clone(),
            context,
            artifact,
            status: LiveUploadStatus::HttpError,
            started: None,
        }
        .start()
    }

    pub(crate) fn start_live_marshal_wait<'a, C: Clock>(
        &self,
        context: &'a C,
        artifact: LiveUploadArtifact,
    ) -> LiveMarshalWaitGuard<'a, C> {
        self.live_marshal_wait_in_flight.inc();
        LiveMarshalWaitGuard {
            metrics: self.clone(),
            context,
            artifact,
            status: LiveMarshalWaitStatus::Cancelled,
            started: Some(context.current()),
        }
    }

    pub(crate) fn http_encoded(
        &self,
        artifact: HttpArtifact,
        bytes: usize,
        duration: Duration,
    ) {
        let label = HttpArtifactLabel { artifact };
        self.http_encode.get_or_create(&label).inc();
        self.http_encode_bytes
            .get_or_create(&label)
            .observe(bytes as f64);
        self.http_encode_duration
            .get_or_create(&label)
            .observe(duration.as_secs_f64());
    }

    pub(crate) fn start_http_request(
        &self,
        artifact: HttpArtifact,
        body_bytes: usize,
    ) -> HttpRequestGuard {
        let label = HttpArtifactLabel { artifact };
        let body_bytes = gauge_bytes(body_bytes);
        self.http_request_body_in_flight_bytes
            .get_or_create(&label)
            .inc_by(body_bytes);
        self.http_request_in_flight.get_or_create(&label).inc();
        HttpRequestGuard {
            metrics: self.clone(),
            artifact,
            body_bytes,
            status: HttpRequestStatus::TransportError,
            started: Instant::now(),
        }
    }

    pub(crate) fn observe_block(&self, source: BlockMetricSource, block: &Block) {
        let label = BlockSourceLabel { source };
        self.block_estimated_bytes
            .get_or_create(&label)
            .observe(estimated_block_bytes(block) as f64);
        self.block_transaction_count
            .get_or_create(&label)
            .observe(block.transactions.len() as f64);
    }

    pub(crate) fn shared_state(&self, snapshot: SharedStateSnapshot) {
        let _ = self.shared_cached_blocks.try_set(snapshot.cached_blocks);
        let _ = self
            .shared_cached_block_estimated_bytes
            .try_set(snapshot.cached_block_estimated_bytes);
        let _ = self
            .shared_certificate_upload_digests
            .try_set(snapshot.certificate_upload_digests);
        let _ = self
            .shared_certificate_upload_refs
            .try_set(snapshot.certificate_upload_refs);
        let _ = self
            .shared_uploaded_digests
            .try_set(snapshot.uploaded_digests);
        let _ = self
            .shared_latest_finalized_height
            .try_set(snapshot.latest_finalized_height);
        let _ = self
            .shared_acked_through_height
            .try_set(snapshot.acked_through_height);
    }

    pub(crate) fn shared_cache_inserted(&self, source: SharedCacheSource) {
        self.shared_cache_inserted
            .get_or_create(&SharedCacheSourceLabel { source })
            .inc();
    }

    pub(crate) fn shared_cache_removed(&self, reason: SharedRetentionReason) {
        self.shared_cache_removed
            .get_or_create(&SharedRetentionReasonLabel { reason })
            .inc();
    }

    pub(crate) fn shared_pruned(&self, reason: SharedRetentionReason, count: u64) {
        self.shared_pruned
            .get_or_create(&SharedRetentionReasonLabel { reason })
            .inc_by(count);
    }

    pub(crate) fn backfill_configured(&self, max_active: usize) {
        let _ = self.backfill_max_active.try_set(max_active);
    }

    pub(crate) fn start_backfill_upload(&self) -> BackfillUploadGuard {
        self.backfill_started.inc();
        self.backfill_active_uploads.inc();
        BackfillUploadGuard {
            metrics: self.clone(),
            status: None,
            block_bytes: 0,
            started: Instant::now(),
        }
    }

    pub(crate) fn backfill_decision(
        &self,
        decision: BackfillDecision,
        phase: BackfillPhase,
    ) {
        self.backfill_decision
            .get_or_create(&BackfillDecisionLabel { decision, phase })
            .inc();
    }

    pub(crate) fn backfill_retry(&self, reason: BackfillWaitReason) {
        self.backfill_retry
            .get_or_create(&BackfillWaitReasonLabel { reason })
            .inc();
    }

    pub(crate) fn backfill_waited(&self, reason: BackfillWaitReason, duration: Duration) {
        self.backfill_wait_duration
            .get_or_create(&BackfillWaitReasonLabel { reason })
            .observe(duration.as_secs_f64());
    }

    pub(crate) fn start_backfill_body(&self, bytes: u64) -> BackfillBodyGuard {
        let bytes = gauge_u64(bytes);
        self.backfill_active_body_estimated_bytes.inc_by(bytes);
        BackfillBodyGuard {
            metrics: self.clone(),
            bytes,
        }
    }
}

pub(crate) struct LiveUploadGuard<C: Clock> {
    metrics: IndexerMetrics,
    context: C,
    artifact: LiveUploadArtifact,
    status: LiveUploadStatus,
    started: Option<SystemTime>,
}

impl<C: Clock> LiveUploadGuard<C> {
    fn start(mut self) -> Self {
        self.started = Some(self.context.current());
        self
    }

    pub(crate) fn start_marshal_wait(&self) -> LiveMarshalWaitGuard<'_, C> {
        self.metrics
            .start_live_marshal_wait(&self.context, self.artifact)
    }

    pub(crate) const fn succeed(&mut self) {
        self.status = LiveUploadStatus::Success;
    }

    pub(crate) const fn marshal_cancelled(&mut self) {
        self.status = LiveUploadStatus::MarshalCancelled;
    }
}

impl<C: Clock> Drop for LiveUploadGuard<C> {
    fn drop(&mut self) {
        self.metrics
            .live_upload_in_flight
            .get_or_create(&ArtifactLabel {
                artifact: self.artifact,
            })
            .dec();

        let label = CompletionLabel {
            artifact: self.artifact,
            status: self.status,
        };
        self.metrics
            .live_upload_completed
            .get_or_create(&label)
            .inc();

        if let Some(started) = self.started {
            self.metrics
                .live_upload_duration
                .get_or_create(&label)
                .observe_between(started, self.context.current());
        }
    }
}

pub(crate) struct LiveMarshalWaitGuard<'a, C: Clock> {
    metrics: IndexerMetrics,
    context: &'a C,
    artifact: LiveUploadArtifact,
    status: LiveMarshalWaitStatus,
    started: Option<SystemTime>,
}

impl<C: Clock> LiveMarshalWaitGuard<'_, C> {
    pub(crate) const fn found(&mut self) {
        self.status = LiveMarshalWaitStatus::Found;
    }
}

impl<C: Clock> Drop for LiveMarshalWaitGuard<'_, C> {
    fn drop(&mut self) {
        self.metrics.live_marshal_wait_in_flight.dec();

        let label = MarshalWaitCompletionLabel {
            artifact: self.artifact,
            status: self.status,
        };
        self.metrics
            .live_marshal_wait_completed
            .get_or_create(&label)
            .inc();

        if let Some(started) = self.started {
            self.metrics
                .live_marshal_wait_duration
                .get_or_create(&label)
                .observe_between(started, self.context.current());
        }
    }
}

pub(crate) struct HttpRequestGuard {
    metrics: IndexerMetrics,
    artifact: HttpArtifact,
    body_bytes: GaugeValue,
    status: HttpRequestStatus,
    started: Instant,
}

impl HttpRequestGuard {
    pub(crate) const fn succeed(&mut self) {
        self.status = HttpRequestStatus::Success;
    }

    pub(crate) const fn http_status_error(&mut self) {
        self.status = HttpRequestStatus::HttpStatusError;
    }
}

impl Drop for HttpRequestGuard {
    fn drop(&mut self) {
        let artifact_label = HttpArtifactLabel {
            artifact: self.artifact,
        };
        self.metrics
            .http_request_body_in_flight_bytes
            .get_or_create(&artifact_label)
            .dec_by(self.body_bytes);
        self.metrics
            .http_request_in_flight
            .get_or_create(&artifact_label)
            .dec();

        let completion_label = HttpCompletionLabel {
            artifact: self.artifact,
            status: self.status,
        };
        self.metrics
            .http_request_completed
            .get_or_create(&completion_label)
            .inc();
        self.metrics
            .http_request_duration
            .get_or_create(&completion_label)
            .observe(self.started.elapsed().as_secs_f64());
    }
}

pub(crate) struct BackfillUploadGuard {
    metrics: IndexerMetrics,
    status: Option<BackfillStatus>,
    block_bytes: GaugeValue,
    started: Instant,
}

impl BackfillUploadGuard {
    pub(crate) fn hold_block(&mut self, block: &Block) {
        let bytes = gauge_u64(estimated_block_bytes(block));
        if self.block_bytes != 0 {
            self.metrics
                .backfill_active_block_estimated_bytes
                .dec_by(self.block_bytes);
        }
        self.metrics
            .backfill_active_block_estimated_bytes
            .inc_by(bytes);
        self.block_bytes = bytes;
    }

    pub(crate) const fn uploaded(&mut self) {
        self.status = Some(BackfillStatus::Uploaded);
    }

    pub(crate) const fn skipped(&mut self) {
        self.status = Some(BackfillStatus::Skipped);
    }
}

impl Drop for BackfillUploadGuard {
    fn drop(&mut self) {
        self.metrics.backfill_active_uploads.dec();
        if self.block_bytes != 0 {
            self.metrics
                .backfill_active_block_estimated_bytes
                .dec_by(self.block_bytes);
        }

        let Some(status) = self.status else {
            return;
        };
        let label = BackfillCompletionLabel { status };
        self.metrics
            .backfill_completed
            .get_or_create(&label)
            .inc();
        self.metrics
            .backfill_upload_duration
            .get_or_create(&label)
            .observe(self.started.elapsed().as_secs_f64());
    }
}

pub(crate) struct BackfillBodyGuard {
    metrics: IndexerMetrics,
    bytes: GaugeValue,
}

impl Drop for BackfillBodyGuard {
    fn drop(&mut self) {
        self.metrics
            .backfill_active_body_estimated_bytes
            .dec_by(self.bytes);
    }
}

fn local_histogram() -> raw::Histogram {
    raw::Histogram::new(Buckets::LOCAL)
}

fn gauge_bytes(bytes: usize) -> GaugeValue {
    bytes.try_into().unwrap_or(GaugeValue::MAX)
}

fn gauge_u64(bytes: u64) -> GaugeValue {
    bytes.try_into().unwrap_or(GaugeValue::MAX)
}

pub(crate) fn estimated_block_bytes(block: &Block) -> u64 {
    commonware_codec::EncodeSize::encode_size(block) as u64
}

pub(crate) fn estimated_finalized_bytes(finalized: &Finalized) -> u64 {
    commonware_codec::EncodeSize::encode_size(finalized) as u64
}
