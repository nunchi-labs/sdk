use commonware_runtime::{
    telemetry::metrics::{
        encoding::EncodeLabelValue as EncodeLabelValueTrait, histogram::Buckets, raw,
        CounterFamily, EncodeLabelSet, Gauge, GaugeFamily, HistogramExt as _, MetricsExt as _,
        Registered, GaugeValue,
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
