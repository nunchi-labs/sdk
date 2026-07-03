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
use nunchi_dkg::{PostUpdate, Update, UpdateCallBack};
use std::{future::Future, num::NonZeroUsize, pin::Pin, sync::Arc, time::Duration};
use thiserror::Error;
use tracing::{info, warn};

mod backfiller;
mod pusher;

pub(crate) use backfiller::{Consumer, Entry, Producer};
use backfiller::{SharedState, State};
pub(crate) use pusher::Pusher;

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

    fn block_upload(&self, block: Block) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// HTTP client for an Alto-compatible coins-chain indexer API.
#[derive(Clone)]
pub struct HttpClient {
    uri: String,
    http: reqwest::Client,
}

impl HttpClient {
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            http: reqwest::Client::new(),
        }
    }

    fn path(&self, suffix: &str) -> String {
        format!("{}{}", self.uri.trim_end_matches('/'), suffix)
    }

    async fn post(&self, suffix: &str, body: Vec<u8>) -> Result<(), Error> {
        let response = self.http.post(self.path(suffix)).body(body).send().await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::Failed(response.status()))
        }
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
            &format!("/dkg-output/{}", epoch.get()),
            commonware_codec::Encode::encode(&output).to_vec(),
        )
        .await
    }

    async fn seed_upload(&self, seed: Seed) -> Result<(), Self::Error> {
        self.post("/seed", commonware_codec::Encode::encode(&seed).to_vec())
            .await
    }

    async fn notarized_upload(&self, notarized: Notarized) -> Result<(), Self::Error> {
        self.post(
            "/notarization",
            commonware_codec::Encode::encode(&notarized).to_vec(),
        )
        .await
    }

    async fn finalized_upload(&self, finalized: Finalized) -> Result<(), Self::Error> {
        self.post(
            "/finalization",
            commonware_codec::Encode::encode(&finalized).to_vec(),
        )
        .await
    }

    async fn block_upload(&self, block: Block) -> Result<(), Self::Error> {
        self.post("/block", commonware_codec::Encode::encode(&block).to_vec())
            .await
    }
}

pub(crate) struct DkgOutputPusher<C> {
    client: C,
}

impl<C: Client> DkgOutputPusher<C> {
    pub(crate) fn boxed(client: C) -> Box<Self> {
        Box::new(Self { client })
    }
}

impl<C: Client> UpdateCallBack<MinSig, crate::PublicKey> for DkgOutputPusher<C> {
    fn on_update(
        &mut self,
        update: Update<MinSig, crate::PublicKey>,
    ) -> Pin<Box<dyn Future<Output = PostUpdate> + Send>> {
        let client = self.client.clone();
        Box::pin(async move {
            if let Update::Success { epoch, output, .. } = update {
                let next_epoch = epoch.next();
                match client.dkg_output_upload(next_epoch, output).await {
                    Ok(()) => {
                        info!(%next_epoch, "uploaded DKG output to indexer");
                    }
                    Err(error) => {
                        warn!(%next_epoch, %error, "failed to upload DKG output to indexer");
                    }
                }
            }
            PostUpdate::Continue
        })
    }
}

/// Builds and owns the live and durable indexer upload actors.
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
        mailbox_size: NonZeroUsize,
        backfiller_max_active: NonZeroUsize,
        backfiller_retry: Duration,
    ) -> Self {
        let uploads: SharedState = Arc::new(Mutex::new(State::new()));
        let pusher = Pusher::new(
            context.child("pusher"),
            client.clone(),
            marshal.clone(),
            uploads.clone(),
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
