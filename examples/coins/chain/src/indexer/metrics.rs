use crate::Block;
use commonware_runtime::{
    telemetry::metrics::{
        encoding::EncodeLabelValue as EncodeLabelValueTrait, histogram::Buckets, raw,
        CounterFamily, EncodeLabelSet, Gauge, GaugeExt as _, GaugeFamily, GaugeValue,
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

    pub(crate) fn shared_state(
        &self,
        cached_blocks: usize,
        cached_block_estimated_bytes: u64,
        certificate_upload_digests: usize,
        certificate_upload_refs: usize,
        uploaded_digests: usize,
        latest_finalized_height: u64,
        acked_through_height: u64,
    ) {
        let _ = self.shared_cached_blocks.try_set(cached_blocks);
        let _ = self
            .shared_cached_block_estimated_bytes
            .try_set(cached_block_estimated_bytes);
        let _ = self
            .shared_certificate_upload_digests
            .try_set(certificate_upload_digests);
        let _ = self
            .shared_certificate_upload_refs
            .try_set(certificate_upload_refs);
        let _ = self.shared_uploaded_digests.try_set(uploaded_digests);
        let _ = self
            .shared_latest_finalized_height
            .try_set(latest_finalized_height);
        let _ = self
            .shared_acked_through_height
            .try_set(acked_through_height);
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

fn local_histogram() -> raw::Histogram {
    raw::Histogram::new(Buckets::LOCAL)
}

fn gauge_bytes(bytes: usize) -> GaugeValue {
    bytes.try_into().unwrap_or(GaugeValue::MAX)
}

pub(crate) fn estimated_block_bytes(block: &Block) -> u64 {
    commonware_codec::EncodeSize::encode_size(block) as u64
}
