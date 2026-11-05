use super::{
    metrics::{BlockMetricSource, LiveUploadArtifact, SharedCacheSource},
    Client, IndexerMetrics, SharedState,
};
use crate::{Activity, Block, Finalized, Notarized, Scheme, Seed, Seedable};
use commonware_actor::Feedback;
use commonware_consensus::{
    marshal::{core::DigestFallback, core::Mailbox as MarshalMailbox},
    types::{Round, View},
    Reporter, Viewable,
};
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{Clock, Metrics, Spawner};
use std::{future::Future, sync::Arc, time::Duration};
use tracing::{debug, warn};

const UPLOAD_ATTEMPTS: u32 = 8;

/// Uploads live seeds and certificate-bearing objects to the indexer.
pub(crate) struct Pusher<E: Spawner + Metrics + Clock, C: Client> {
    context: Arc<E>,
    client: C,
    marshal: MarshalMailbox<Scheme, crate::EngineVariant>,
    uploads: SharedState,
    metrics: IndexerMetrics,
}

impl<E: Spawner + Metrics + Clock, C: Client> Clone for Pusher<E, C> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            client: self.client.clone(),
            marshal: self.marshal.clone(),
            uploads: self.uploads.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl<E: Spawner + Metrics + Clock, C: Client> Pusher<E, C> {
    pub(crate) fn new(
        context: E,
        client: C,
        marshal: MarshalMailbox<Scheme, crate::EngineVariant>,
        uploads: SharedState,
        metrics: IndexerMetrics,
    ) -> Self {
        Self {
            context: Arc::new(context),
            client,
            marshal,
            uploads,
            metrics,
        }
    }
}

struct CertificateUploadGuard {
    uploads: SharedState,
    digest: Digest,
    uploaded_height: Option<u64>,
}

impl CertificateUploadGuard {
    fn new(uploads: SharedState, digest: Digest) -> Self {
        uploads.lock().start_certificate_upload(digest);
        Self {
            uploads,
            digest,
            uploaded_height: None,
        }
    }

    fn cache_block(&self, block: Block) {
        self.uploads
            .lock()
            .cache_block(block, SharedCacheSource::LiveCertificate);
    }

    fn mark_uploaded(&mut self, height: u64) {
        self.uploaded_height = Some(height);
    }
}

impl Drop for CertificateUploadGuard {
    fn drop(&mut self) {
        self.uploads
            .lock()
            .finish_certificate_upload(&self.digest, self.uploaded_height);
    }
}

impl<E: Spawner + Metrics + Clock, C: Client> Pusher<E, C> {
    fn spawn_seed_upload(&self, artifact: LiveUploadArtifact, seed: Seed, view: View) {
        self.metrics.live_upload_spawned(artifact);
        self.context.child(artifact.as_str()).spawn({
            let client = self.client.clone();
            let metrics = self.metrics.clone();
            move |context| async move {
                let mut upload = metrics.start_live_upload(context, artifact);
                let mut delay = Duration::from_millis(100);
                for attempt in 1..=UPLOAD_ATTEMPTS {
                    match client.seed_upload(seed.clone()).await {
                        Ok(()) => {
                            upload.succeed();
                            debug!(%view, "seed uploaded to indexer");
                            return;
                        }
                        Err(e) if attempt < UPLOAD_ATTEMPTS => {
                            warn!(?e, attempt, "failed to upload seed; retrying");
                            upload.sleep(delay).await;
                            delay = delay.saturating_mul(2).min(Duration::from_secs(2));
                        }
                        Err(e) => {
                            warn!(?e, "failed to upload seed");
                            return;
                        }
                    }
                }
            }
        });
    }

    fn spawn_certificate_upload<F, Fut>(
        &self,
        artifact: LiveUploadArtifact,
        view: View,
        round: Round,
        digest: Digest,
        mark_finalized: bool,
        upload_fn: F,
    ) where
        F: Fn(C, Block) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), C::Error>> + Send,
    {
        self.metrics.live_upload_spawned(artifact);
        self.context.child(artifact.as_str()).spawn({
            let client = self.client.clone();
            let marshal = self.marshal.clone();
            let uploads = self.uploads.clone();
            let metrics = self.metrics.clone();
            move |context| async move {
                let mut upload = metrics.start_live_upload(context, artifact);
                let mut guard = CertificateUploadGuard::new(uploads, digest);

                let mut wait = upload.start_marshal_wait();
                let coded = marshal
                    .subscribe_by_digest(digest, DigestFallback::FetchByRound { round })
                    .await;
                let Ok(coded) = coded else {
                    drop(wait);
                    upload.marshal_cancelled();
                    warn!(%view, "subscription for block cancelled");
                    return;
                };
                wait.found();
                drop(wait);

                let block = coded.inner().clone();
                let height = block.header.height.get();
                metrics.observe_block(BlockMetricSource::LiveCertificate, &block);
                guard.cache_block(block.clone());
                let mut delay = Duration::from_millis(100);
                let mut uploaded = false;
                for attempt in 1..=UPLOAD_ATTEMPTS {
                    match upload_fn(client.clone(), block.clone()).await {
                        Ok(()) => {
                            uploaded = true;
                            break;
                        }
                        Err(e) if attempt < UPLOAD_ATTEMPTS => {
                            warn!(
                                ?e,
                                %view,
                                attempt,
                                label = artifact.as_str(),
                                "failed to upload certificate; retrying"
                            );
                            upload.sleep(delay).await;
                            delay = delay.saturating_mul(2).min(Duration::from_secs(2));
                        }
                        Err(e) => {
                            warn!(
                                ?e,
                                %view,
                                label = artifact.as_str(),
                                "failed to upload certificate"
                            );
                            break;
                        }
                    }
                }
                if !uploaded {
                    return;
                }

                if mark_finalized {
                    guard.mark_uploaded(height);
                }
                upload.succeed();
                debug!(%view, label = artifact.as_str(), "certificate uploaded to indexer");
            }
        });
    }
}

impl<E: Spawner + Metrics + Clock, C: Client> Reporter for Pusher<E, C> {
    type Activity = Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Activity::Notarization(notarization) | Activity::Certification(notarization) => {
                let view = notarization.view();
                self.spawn_seed_upload(
                    LiveUploadArtifact::NotarizedSeed,
                    notarization.seed(),
                    view,
                );
                self.spawn_certificate_upload(
                    LiveUploadArtifact::NotarizedBlock,
                    view,
                    notarization.round(),
                    notarization.proposal.payload.block(),
                    false,
                    move |indexer, block| {
                        let notarization = notarization.clone();
                        async move {
                            indexer
                                .notarized_upload(Notarized::new(notarization, block))
                                .await
                        }
                    },
                );
            }
            Activity::Finalization(finalization) => {
                let view = finalization.view();
                self.spawn_seed_upload(
                    LiveUploadArtifact::FinalizedSeed,
                    finalization.seed(),
                    view,
                );
                self.spawn_certificate_upload(
                    LiveUploadArtifact::FinalizedBlock,
                    view,
                    finalization.round(),
                    finalization.proposal.payload.block(),
                    true,
                    move |indexer, block| {
                        let finalization = finalization.clone();
                        async move {
                            indexer
                                .finalized_upload(Finalized::new(finalization, block))
                                .await
                        }
                    },
                );
            }
            _ => {}
        }
        Feedback::Ok
    }
}
