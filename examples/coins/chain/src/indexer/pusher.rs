use super::{Client, SharedState};
use crate::{Activity, Block, Finalized, Notarized, Scheme, Seed, Seedable};
use commonware_actor::Feedback;
use commonware_consensus::{
    marshal::{core::DigestFallback, core::Mailbox as MarshalMailbox, standard::Standard},
    types::{Round, View},
    Reporter, Viewable,
};
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{Metrics, Spawner};
use std::{future::Future, sync::Arc};
use tracing::{debug, warn};

/// Uploads live seeds and certificate-bearing objects to the indexer.
pub(crate) struct Pusher<E: Spawner + Metrics, C: Client> {
    context: Arc<E>,
    client: C,
    marshal: MarshalMailbox<Scheme, Standard<Block>>,
    uploads: SharedState,
}

impl<E: Spawner + Metrics, C: Client> Clone for Pusher<E, C> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            client: self.client.clone(),
            marshal: self.marshal.clone(),
            uploads: self.uploads.clone(),
        }
    }
}

impl<E: Spawner + Metrics, C: Client> Pusher<E, C> {
    pub(crate) fn new(
        context: E,
        client: C,
        marshal: MarshalMailbox<Scheme, Standard<Block>>,
        uploads: SharedState,
    ) -> Self {
        Self {
            context: Arc::new(context),
            client,
            marshal,
            uploads,
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
        self.uploads.lock().cache_block(block);
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

impl<E: Spawner + Metrics, C: Client> Pusher<E, C> {
    fn spawn_seed_upload(&self, label: &'static str, seed: Seed, view: View) {
        self.context.child(label).spawn({
            let client = self.client.clone();
            move |_| async move {
                if let Err(e) = client.seed_upload(seed).await {
                    warn!(?e, "failed to upload seed");
                    return;
                }
                debug!(%view, "seed uploaded to indexer");
            }
        });
    }

    fn spawn_certificate_upload<F, Fut>(
        &self,
        label: &'static str,
        view: View,
        round: Round,
        digest: Digest,
        upload_fn: F,
    ) where
        F: FnOnce(C, Block) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), C::Error>> + Send,
    {
        self.context.child(label).spawn({
            let client = self.client.clone();
            let marshal = self.marshal.clone();
            let uploads = self.uploads.clone();
            move |_| async move {
                let mut guard = CertificateUploadGuard::new(uploads, digest);

                let block = marshal
                    .subscribe_by_digest(digest, DigestFallback::FetchByRound { round })
                    .await;
                let Ok(block) = block else {
                    warn!(%view, "subscription for block cancelled");
                    return;
                };

                let height = block.height.get();
                guard.cache_block(block.clone());
                if let Err(e) = upload_fn(client, block).await {
                    warn!(?e, %view, label, "failed to upload certificate");
                    return;
                }

                guard.mark_uploaded(height);
                debug!(%view, label, "certificate uploaded to indexer");
            }
        });
    }
}

impl<E: Spawner + Metrics, C: Client> Reporter for Pusher<E, C> {
    type Activity = Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Activity::Notarization(notarization) | Activity::Certification(notarization) => {
                let view = notarization.view();
                self.spawn_seed_upload("notarized_seed", notarization.seed(), view);
                self.spawn_certificate_upload(
                    "notarized_block",
                    view,
                    notarization.round(),
                    notarization.proposal.payload,
                    |indexer, block| async move {
                        indexer
                            .notarized_upload(Notarized::new(notarization, block))
                            .await
                    },
                );
            }
            Activity::Finalization(finalization) => {
                let view = finalization.view();
                self.spawn_seed_upload("finalized_seed", finalization.seed(), view);
                self.spawn_certificate_upload(
                    "finalized_block",
                    view,
                    finalization.round(),
                    finalization.proposal.payload,
                    |indexer, block| async move {
                        indexer
                            .finalized_upload(Finalized::new(finalization, block))
                            .await
                    },
                );
            }
            _ => {}
        }
        Feedback::Ok
    }
}
