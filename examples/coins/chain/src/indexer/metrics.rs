use commonware_runtime::{
    telemetry::metrics::{
        encoding::EncodeLabelValue as EncodeLabelValueTrait, histogram::Buckets, raw,
        CounterFamily, EncodeLabelSet, GaugeFamily, HistogramExt as _, MetricsExt as _,
        Registered,
    },
    Clock, Metrics,
};
use std::{fmt, time::SystemTime};

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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ArtifactLabel {
    artifact: LiveUploadArtifact,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct CompletionLabel {
    artifact: LiveUploadArtifact,
    status: LiveUploadStatus,
}

#[derive(Clone)]
pub(crate) struct IndexerMetrics {
    live_upload_spawned: CounterFamily<ArtifactLabel>,
    live_upload_in_flight: GaugeFamily<ArtifactLabel>,
    live_upload_completed: CounterFamily<CompletionLabel>,
    live_upload_duration: HistogramFamily<CompletionLabel>,
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

fn local_histogram() -> raw::Histogram {
    raw::Histogram::new(Buckets::LOCAL)
}
