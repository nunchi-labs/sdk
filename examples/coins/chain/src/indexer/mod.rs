//! Indexer upload integration for coins-chain validators.

use crate::{Block, Finalized, Notarized, Seed};
use commonware_consensus::marshal::{core::Mailbox as MarshalMailbox, standard::Standard};
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::Output as DkgOutput, primitives::variant::MinSig,
};
use commonware_runtime::{BufferPooler, Clock, Handle, Metrics, Spawner, Storage};
use commonware_storage::queue;
use commonware_utils::{sync::Mutex, NZU64};
use std::{future::Future, num::NonZeroUsize, sync::Arc, time::Duration};
use thiserror::Error;

mod backfiller;
mod metrics;
mod pusher;

pub(crate) use backfiller::{Consumer, Entry, Producer};
use backfiller::{SharedState, State};
pub(crate) use metrics::{DkgUploadStatus, IndexerMetrics};
#[cfg(test)]
pub(crate) use metrics::{
    BackfillDecision, BackfillPhase, BackfillWaitReason, BlockMetricSource,
    HttpArtifact, LiveUploadArtifact, ProducerActivity, ProducerStatus, QueueReadSource,
    QueueStatus, SharedCacheSource, SharedRetentionReason, SharedStateSnapshot,
};
use metrics::HttpArtifact as UploadArtifact;
pub(crate) use pusher::Pusher;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MISSING_FINALIZATION_GRACE: Duration = Duration::from_secs(120);
const MISMATCHED_FINALIZATION_GRACE: Duration = Duration::from_secs(15);
pub(crate) const SPOOL_ITEMS_PER_SECTION: std::num::NonZeroU64 = NZU64!(128);

/// Availability window for durable finalized uploads while the external indexer is unavailable.
#[derive(Clone, Copy, Debug)]
pub struct SpoolLimits {
    pub max_entries: u64,
    pub max_bytes: u64,
    pub max_payload_bytes: u64,
    pub max_age: Duration,
}

impl Default for SpoolLimits {
    fn default() -> Self {
        Self {
            max_entries: crate::BLOCKS_PER_EPOCH.get(),
            max_bytes: 2 * 1024 * 1024 * 1024,
            max_payload_bytes: 16 * 1024 * 1024,
            max_age: Duration::from_secs(24 * 60 * 60),
        }
    }
}

impl SpoolLimits {
    fn validate(self) {
        assert!(self.max_entries > 0, "indexer spool max_entries must be non-zero");
        assert!(self.max_bytes > 0, "indexer spool max_bytes must be non-zero");
        assert!(
            self.max_payload_bytes > 0 && self.max_payload_bytes <= self.max_bytes,
            "indexer spool max_payload_bytes must be in 1..=max_bytes"
        );
        assert!(!self.max_age.is_zero(), "indexer spool max_age must be non-zero");
        self.max_encoded_payload_bytes()
            .expect("indexer spool encoded payload bound overflows u64");
    }

    pub fn max_encoded_payload_bytes(self) -> Option<u64> {
        (SPOOL_ITEMS_PER_SECTION.get() - 1)
            .checked_mul(self.max_payload_bytes)?
            .checked_add(self.max_bytes)
    }
}

#[cfg(test)]
mod spool_tests {
    use super::*;

    #[test]
    fn default_spool_bound_includes_section_slack() {
        let limits = SpoolLimits::default();
        assert_eq!(limits.max_entries, crate::BLOCKS_PER_EPOCH.get());
        assert_eq!(limits.max_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(limits.max_age, Duration::from_secs(24 * 60 * 60));
        assert_eq!(
            limits.max_encoded_payload_bytes(),
            Some(limits.max_bytes + 127 * limits.max_payload_bytes)
        );
    }
}

/// Errors returned by the HTTP indexer client.
#[derive(Debug, Error)]
pub enum Error {
    #[error("request failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("indexer returned {0}")]
    Failed(reqwest::StatusCode),
}

/// Trait for uploading coins-chain artifacts to an indexer backend.
pub trait Client: Clone + Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn dkg_output_upload(
        &self,
        epoch: Epoch,
        output: DkgOutput<MinSig, crate::PublicKey>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn seed_upload(&self, seed: Seed) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn notarized_upload(
        &self,
        notarized: Notarized,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn finalized_upload(
        &self,
        finalized: Finalized,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// HTTP client for an Alto-compatible coins-chain indexer API.
#[derive(Clone)]
pub struct HttpClient {
    uri: String,
    http: reqwest::Client,
    metrics: Option<IndexerMetrics>,
}

impl HttpClient {
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            http: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("valid indexer HTTP client configuration"),
            metrics: None,
        }
    }

    pub(crate) fn with_metrics(mut self, metrics: IndexerMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    fn path(&self, suffix: &str) -> String {
        format!("{}{}", self.uri.trim_end_matches('/'), suffix)
    }

    fn encode<T: commonware_codec::Encode>(&self, artifact: UploadArtifact, value: &T) -> Vec<u8> {
        let started = std::time::Instant::now();
        let body = value.encode().to_vec();
        if let Some(metrics) = &self.metrics {
            metrics.http_encoded(artifact, body.len(), started.elapsed());
        }
        body
    }

    async fn post(
        &self,
        artifact: UploadArtifact,
        suffix: &str,
        body: Vec<u8>,
    ) -> Result<(), Error> {
        let mut request = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.start_http_request(artifact, body.len()));

        let response = match self.http.post(self.path(suffix)).body(body).send().await {
            Ok(response) => response,
            Err(error) => return Err(Error::Reqwest(error)),
        };

        let status = response.status();
        if status.is_success() {
            if let Some(request) = request.as_mut() {
                request.succeed();
            }
            return Ok(());
        }

        if let Some(request) = request.as_mut() {
            request.http_status_error();
        }
        Err(Error::Failed(status))
    }
}

impl Client for HttpClient {
    type Error = Error;

    async fn dkg_output_upload(
        &self,
        epoch: Epoch,
        output: DkgOutput<MinSig, crate::PublicKey>,
    ) -> Result<(), Self::Error> {
        self.post(
            UploadArtifact::DkgOutput,
            &format!("/dkg-output/{}", epoch.get()),
            self.encode(UploadArtifact::DkgOutput, &output),
        )
        .await
    }

    async fn seed_upload(&self, seed: Seed) -> Result<(), Self::Error> {
        self.post(
            UploadArtifact::Seed,
            "/seed",
            self.encode(UploadArtifact::Seed, &seed),
        )
            .await
    }

    async fn notarized_upload(&self, notarized: Notarized) -> Result<(), Self::Error> {
        self.post(
            UploadArtifact::Notarization,
            "/notarization",
            self.encode(UploadArtifact::Notarization, &notarized),
        )
        .await
    }

    async fn finalized_upload(&self, finalized: Finalized) -> Result<(), Self::Error> {
        self.post(
            UploadArtifact::Finalization,
            "/finalization",
            self.encode(UploadArtifact::Finalization, &finalized),
        )
        .await
    }
}

/// Builds and owns the live and durable indexer upload actors.
pub(crate) struct Config {
    pub(crate) mailbox_size: NonZeroUsize,
    pub(crate) backfiller_max_active: NonZeroUsize,
    pub(crate) backfiller_retry: Duration,
    pub(crate) spool_limits: SpoolLimits,
    pub(crate) metrics: IndexerMetrics,
}

pub(crate) struct Indexer<E: BufferPooler + Spawner + Clock + Storage + Metrics, C: Client> {
    producer: Producer,
    producer_handle: Handle<()>,
    pusher: Pusher<E, C>,
    consumer: Consumer<E, C>,
}

impl<E: BufferPooler + Spawner + Clock + Storage + Metrics, C: Client> Indexer<E, C> {
    pub(crate) async fn new(
        context: E,
        client: C,
        marshal: MarshalMailbox<crate::Scheme, Standard<Block>>,
        backfiller: (queue::Writer<E, Entry>, queue::Reader<E, Entry>),
        config: Config,
    ) -> Self {
        let Config {
            mailbox_size,
            backfiller_max_active,
            backfiller_retry,
            spool_limits,
            metrics,
        } = config;
        spool_limits.validate();
        let uploads: SharedState = Arc::new(Mutex::new(State::with_metrics(metrics.clone())));
        let pusher = Pusher::new(
            context.child("pusher"),
            client.clone(),
            marshal.clone(),
            uploads.clone(),
            metrics.clone(),
        );
        let (writer, mut reader) = backfiller;
        loop {
            let Some((position, entry)) = reader
                .try_recv()
                .await
                .expect("failed to reconstruct durable indexer spool")
            else {
                break;
            };
            uploads.lock().recover_queued(position, &entry);
        }
        reader.reset().await;
        let (admission_sender, admission_receiver) = commonware_actor::mailbox::new(
            context.child("admission_mailbox"),
            mailbox_size,
        );
        let (producer, producer_handle) = backfiller::producer::init(
            context.child("producer"),
            uploads.clone(),
            metrics.clone(),
            marshal.clone(),
            admission_sender,
            backfiller::producer::Config {
                mailbox_size,
                retry: backfiller_retry,
                missing_finalization_grace: MISSING_FINALIZATION_GRACE,
                mismatched_finalization_grace: MISMATCHED_FINALIZATION_GRACE,
                spool_limits,
            },
        );
        let consumer = Consumer::new(
            context.child("consumer"),
            client,
            metrics,
            uploads,
            (writer, reader),
            admission_receiver,
            backfiller::consumer::Config {
                max_active: backfiller_max_active,
                retry: backfiller_retry,
                spool_limits,
            },
        );

        Self {
            producer,
            producer_handle,
            pusher,
            consumer,
        }
    }

    pub(crate) fn split(self) -> (Producer, Handle<()>, Pusher<E, C>, Consumer<E, C>) {
        let Self {
            producer,
            producer_handle,
            pusher,
            consumer,
        } = self;
        (producer, producer_handle, pusher, consumer)
    }
}
