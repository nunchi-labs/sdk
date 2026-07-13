//! Indexer upload integration for coins-chain validators.

use crate::{Block, Finalized, Notarized, Seed};
use commonware_consensus::marshal::{core::Mailbox as MarshalMailbox, standard::Standard};
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::Output as DkgOutput, primitives::variant::MinSig,
};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::queue;
use commonware_utils::sync::Mutex;
use std::{future::Future, num::NonZeroUsize, sync::Arc, time::Duration};
use thiserror::Error;

mod backfiller;
mod metrics;
mod pusher;

pub(crate) use backfiller::{Consumer, Entry, Producer};
use backfiller::{SharedState, State};
pub(crate) use metrics::IndexerMetrics;
#[cfg(test)]
pub(crate) use metrics::{HttpArtifact, LiveUploadArtifact};
use metrics::HttpArtifact as UploadArtifact;
pub(crate) use pusher::Pusher;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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
    pub(crate) metrics: IndexerMetrics,
}

pub(crate) struct Indexer<E: Spawner + Clock + Storage + Metrics, C: Client> {
    producer: Producer,
    pusher: Pusher<E, C>,
    consumer: Consumer<E, C>,
}

impl<E: Spawner + Clock + Storage + Metrics, C: Client> Indexer<E, C> {
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
            metrics,
        } = config;
        let uploads: SharedState = Arc::new(Mutex::new(State::new()));
        let pusher = Pusher::new(
            context.child("pusher"),
            client.clone(),
            marshal.clone(),
            uploads.clone(),
            metrics.clone(),
        );
        let (writer, reader) = backfiller;
        let producer = backfiller::producer::init(
            context.child("producer"),
            uploads.clone(),
            writer.clone(),
            mailbox_size,
        );
        let consumer = Consumer::new(
            context.child("consumer"),
            client,
            marshal,
            uploads,
            (writer, reader),
            backfiller_max_active,
            backfiller_retry,
        );

        Self {
            producer,
            pusher,
            consumer,
        }
    }

    pub(crate) fn split(self) -> (Producer, Pusher<E, C>, Consumer<E, C>) {
        let Self {
            producer,
            pusher,
            consumer,
        } = self;
        (producer, pusher, consumer)
    }
}
