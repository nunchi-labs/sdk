use super::{Decision, Entry, SharedState};
use crate::indexer::{
    metrics::{
        estimated_finalized_bytes, BackfillDecision, BackfillPhase, BackfillUploadGuard,
        BackfillWaitReason, BlockMetricSource, SharedCacheSource,
    },
    Client, IndexerMetrics,
};
use crate::{Block, Finalized, Scheme};
use commonware_consensus::marshal::{
    core::Mailbox as MarshalMailbox, standard::Standard, Identifier,
};
use commonware_consensus::types::Height;
use commonware_cryptography::sha256::Digest;
use commonware_macros::select_loop;
use commonware_runtime::{
    spawn_cell, telemetry::metrics::status, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::queue;
use commonware_utils::futures::{OptionFuture, Pool};
use std::{num::NonZeroUsize, time::Duration};
use tracing::{debug, warn};

impl From<&Decision> for BackfillDecision {
    fn from(decision: &Decision) -> Self {
        match decision {
            Decision::Skip => Self::Skip,
            Decision::Wait => Self::Wait,
            Decision::Proceed => Self::Proceed,
        }
    }
}

enum Completion {
    Uploaded {
        position: u64,
        height: u64,
        digest: Digest,
    },
    Skipped {
        position: u64,
        height: u64,
    },
}

pub(crate) struct Config {
    pub(crate) max_active: NonZeroUsize,
    pub(crate) retry: Duration,
}

pub struct Consumer<E: Spawner + Clock + Storage + Metrics, C: Client> {
    context: ContextCell<E>,
    client: C,
    marshal: MarshalMailbox<Scheme, Standard<Block>>,
    metrics: IndexerMetrics,
    upload_results: status::Counter,
    uploads: SharedState,
    writer: queue::Writer<E, Entry>,
    reader: queue::Reader<E, Entry>,
    active: Pool<Completion>,
    max_active: NonZeroUsize,
    retry: Duration,
}

impl<E: Spawner + Clock + Storage + Metrics, C: Client> Consumer<E, C> {
    pub fn new(
        context: E,
        client: C,
        marshal: MarshalMailbox<Scheme, Standard<Block>>,
        metrics: IndexerMetrics,
        uploads: SharedState,
        backfiller: (queue::Writer<E, Entry>, queue::Reader<E, Entry>),
        config: Config,
    ) -> Self {
        let upload_results = context.register(
            "uploads",
            "Total number of finalized block upload attempt outcomes by status",
            status::Raw::default(),
        );
        let Config { max_active, retry } = config;
        metrics.backfill_configured(max_active.get());
        let (writer, reader) = backfiller;
        Self {
            context: ContextCell::new(context),
            client,
            marshal,
            metrics,
            upload_results,
            uploads,
            writer,
            reader,
            active: Pool::default(),
            max_active,
            retry,
        }
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_start => {
                self.fill_slots().await;
                if self.active.is_empty() {
                    let item = self
                        .reader
                        .recv()
                        .await
                        .expect("failed to recv from finalized queue");
                    let Some((position, entry)) = item else {
                        warn!("consumer queue closed");
                        break;
                    };
                    self.start_upload(position, entry).await;
                    continue;
                }
                let item = OptionFuture::from(
                    (self.active.len() < self.max_active.get()).then(|| self.reader.recv()),
                );
            },
            on_stopped => {},
            completion = self.active.next_completed() => {
                self.complete(completion).await;
            },
            item = item => {
                match item.expect("failed to recv from finalized queue") {
                    Some((position, entry)) => {
                        self.start_upload(position, entry).await;
                    }
                    None => {
                        warn!("consumer queue closed");
                        break;
                    }
                }
            },
        }
    }

    async fn fill_slots(&mut self) {
        while self.active.len() < self.max_active.get() {
            let item = self
                .reader
                .try_recv()
                .await
                .expect("failed to recv from finalized queue");
            let Some((position, entry)) = item else {
                break;
            };
            self.start_upload(position, entry).await;
        }
    }

    async fn start_upload(&mut self, position: u64, entry: Entry) {
        let Entry { height, digest } = entry;
        let decision = self.uploads.lock().should_upload(&digest);
        self.metrics
            .backfill_decision((&decision).into(), BackfillPhase::Start);
        if matches!(decision, Decision::Skip) {
            {
                let mut upload = self.metrics.start_backfill_upload();
                upload.skipped();
            }
            self.complete(Completion::Skipped { position, height })
                .await;
            debug!(?digest, "consumer skipping already-uploaded block");
            return;
        }

        self.active.push({
            let context = self
                .context
                .child("upload")
                .with_attribute("digest", digest)
                .with_attribute("height", height);
            let client = self.client.clone();
            let marshal = self.marshal.clone();
            let metrics = self.metrics.clone();
            let upload_results = self.upload_results.clone();
            let uploads = self.uploads.clone();
            let retry = self.retry;
            async move {
                let mut upload = metrics.start_backfill_upload();
                let Some(block) =
                    Self::wait_for_uploadable_block(
                        &context, &marshal, &metrics, &uploads, &mut upload, digest, retry,
                    )
                    .await
                else {
                    upload.skipped();
                    debug!(?digest, "skipping previously uploaded block");
                    return Completion::Skipped { position, height };
                };

                let finalized = loop {
                    let Some(proof) = marshal.get_finalization(Height::new(height)).await else {
                        warn!(
                            height,
                            ?digest,
                            "consumer could not find finalization, retrying"
                        );
                        Self::wait(
                            &context,
                            &metrics,
                            BackfillWaitReason::MissingFinalization,
                            retry,
                        )
                        .await;
                        continue;
                    };
                    if proof.proposal.payload != digest {
                        warn!(
                            height,
                            ?digest,
                            "consumer found mismatched finalization, retrying"
                        );
                        Self::wait(
                            &context,
                            &metrics,
                            BackfillWaitReason::MismatchedFinalization,
                            retry,
                        )
                        .await;
                        continue;
                    }
                    break Finalized::new(proof, block.clone());
                };

                loop {
                    let decision = {
                        let uploads = uploads.lock();
                        uploads.should_upload(&digest)
                    };
                    metrics.backfill_decision((&decision).into(), BackfillPhase::BeforeAttempt);
                    match decision {
                        Decision::Skip => {
                            upload.skipped();
                            debug!(?digest, "skipping previously uploaded block");
                            return Completion::Skipped { position, height };
                        }
                        Decision::Wait => {
                            Self::wait(
                                &context,
                                &metrics,
                                BackfillWaitReason::CertificateUpload,
                                retry,
                            )
                            .await;
                            continue;
                        }
                        Decision::Proceed => {}
                    }

                    let result = {
                        let _body =
                            metrics.start_backfill_body(estimated_finalized_bytes(&finalized));
                        client.finalized_upload(finalized.clone()).await
                    };
                    match result {
                        Ok(()) => {
                            upload_results.inc(status::Status::Success);
                            upload.uploaded();
                            debug!(?digest, "uploaded finalized block by digest");
                            return Completion::Uploaded {
                                position,
                                height,
                                digest,
                            };
                        }
                        Err(e) => {
                            upload_results.inc(status::Status::Failure);
                            warn!(?e, ?digest, "retrying finalized block upload by digest");
                            Self::wait(&context, &metrics, BackfillWaitReason::HttpError, retry)
                                .await;
                        }
                    }
                }
            }
        });
    }

    async fn wait_for_uploadable_block(
        context: &E,
        marshal: &MarshalMailbox<Scheme, Standard<Block>>,
        metrics: &IndexerMetrics,
        uploads: &SharedState,
        upload: &mut BackfillUploadGuard,
        digest: Digest,
        retry: Duration,
    ) -> Option<Block> {
        enum NextBlock {
            AlreadyUploaded,
            WaitForCertificate,
            Ready(Box<Block>),
            FetchFromMarshal,
        }

        loop {
            let next = {
                let uploads = uploads.lock();
                match uploads.should_upload(&digest) {
                    Decision::Skip => {
                        metrics.backfill_decision(
                            BackfillDecision::Skip,
                            BackfillPhase::BeforeBlock,
                        );
                        NextBlock::AlreadyUploaded
                    }
                    Decision::Wait => {
                        metrics.backfill_decision(
                            BackfillDecision::Wait,
                            BackfillPhase::BeforeBlock,
                        );
                        NextBlock::WaitForCertificate
                    }
                    Decision::Proceed => {
                        metrics.backfill_decision(
                            BackfillDecision::Proceed,
                            BackfillPhase::BeforeBlock,
                        );
                        uploads
                            .cached_block(&digest)
                            .map(|block| NextBlock::Ready(Box::new(block)))
                            .unwrap_or(NextBlock::FetchFromMarshal)
                    }
                }
            };

            match next {
                NextBlock::AlreadyUploaded => return None,
                NextBlock::WaitForCertificate => {
                    Self::wait(
                        context,
                        metrics,
                        BackfillWaitReason::CertificateUpload,
                        retry,
                    )
                    .await;
                }
                NextBlock::Ready(block) => {
                    metrics.observe_block(BlockMetricSource::ConsumerCached, &block);
                    upload.hold_block(&block);
                    return Some(*block);
                }
                NextBlock::FetchFromMarshal => {
                    if let Some(block) = marshal.get_block(Identifier::Digest(digest)).await {
                        metrics.observe_block(BlockMetricSource::ConsumerMarshal, &block);
                        uploads
                            .lock()
                            .cache_block(block.clone(), SharedCacheSource::ConsumerMarshal);
                        upload.hold_block(&block);
                        return Some(block);
                    }
                    warn!(
                        ?digest,
                        "consumer could not find block in marshal, retrying"
                    );
                    Self::wait(context, metrics, BackfillWaitReason::MissingBlock, retry).await;
                }
            }
        }
    }

    async fn wait(
        context: &E,
        metrics: &IndexerMetrics,
        reason: BackfillWaitReason,
        retry: Duration,
    ) {
        metrics.backfill_retry(reason);
        let started = context.current();
        context.sleep(retry).await;
        let duration = context
            .current()
            .duration_since(started)
            .unwrap_or_default();
        metrics.backfill_waited(reason, duration);
    }

    async fn complete(&mut self, completion: Completion) {
        let (position, height) = match completion {
            Completion::Uploaded {
                position,
                height,
                digest,
            } => {
                self.uploads.lock().mark_uploaded(digest, height);
                (position, height)
            }
            Completion::Skipped { position, height } => (position, height),
        };

        let floor = self.reader.ack_floor().await;
        self.reader.ack(position).await.expect("failed to ack");
        let floor_advanced = self.reader.ack_floor().await > floor;
        self.writer.sync().await.expect("failed to sync after ack");
        if floor_advanced {
            self.uploads.lock().advance_queue_floor(height);
        }
    }
}
