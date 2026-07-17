use super::{Decision, Entry, SharedState};
use crate::indexer::{
    metrics::{
        estimated_finalized_bytes, BackfillDecision, BackfillPhase, BackfillResetReason,
        BackfillUploadGuard, BackfillWaitReason, BlockMetricSource, QueueReadSource, QueueStatus,
        SharedCacheSource,
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
    spawn_cell, telemetry::metrics::status, BufferPooler, Clock, ContextCell, Handle, Metrics,
    Spawner, Storage,
};
use commonware_storage::queue;
use commonware_utils::futures::{OptionFuture, Pool};
use std::{
    num::NonZeroUsize,
    time::{Duration, Instant},
};
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
    Stale {
        reason: BackfillResetReason,
        first_height: u64,
        first_digest: Digest,
        attempts: u64,
        elapsed: Duration,
    },
}

pub(crate) struct Config {
    pub(crate) max_active: NonZeroUsize,
    pub(crate) retry: Duration,
    pub(crate) missing_finalization_grace: Duration,
    pub(crate) mismatched_finalization_grace: Duration,
}

pub struct Consumer<E: BufferPooler + Spawner + Clock + Storage + Metrics, C: Client> {
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
    missing_finalization_grace: Duration,
    mismatched_finalization_grace: Duration,
}

impl<E: BufferPooler + Spawner + Clock + Storage + Metrics, C: Client> Consumer<E, C> {
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
        let Config {
            max_active,
            retry,
            missing_finalization_grace,
            mismatched_finalization_grace,
        } = config;
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
            missing_finalization_grace,
            mismatched_finalization_grace,
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
                    let item = Self::recv_queue(&mut self.reader, self.metrics.clone()).await;
                    let Some((position, entry)) = item else {
                        warn!("consumer queue closed");
                        break;
                    };
                    self.start_upload(position, entry).await;
                    continue;
                }
                let item = OptionFuture::from(
                    (self.active.len() < self.max_active.get()).then(|| {
                        Self::recv_queue(&mut self.reader, self.metrics.clone())
                    }),
                );
            },
            on_stopped => {},
            completion = self.active.next_completed() => {
                self.complete(completion).await;
            },
            item = item => {
                match item {
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
            let item = Self::try_recv_queue(&mut self.reader, self.metrics.clone()).await;
            let Some((position, entry)) = item else {
                break;
            };
            self.start_upload(position, entry).await;
        }
    }

    async fn recv_queue(
        reader: &mut queue::Reader<E, Entry>,
        metrics: IndexerMetrics,
    ) -> Option<(u64, Entry)> {
        match reader.recv().await {
            Ok(Some((position, entry))) => {
                metrics.queue_read(QueueReadSource::Recv, QueueStatus::Success);
                metrics.queue_entry(entry.height);
                Some((position, entry))
            }
            Ok(None) => {
                metrics.queue_read(QueueReadSource::Recv, QueueStatus::Closed);
                None
            }
            Err(err) => {
                metrics.queue_read(QueueReadSource::Recv, QueueStatus::Failure);
                panic!("failed to recv from finalized queue: {err:?}");
            }
        }
    }

    async fn try_recv_queue(
        reader: &mut queue::Reader<E, Entry>,
        metrics: IndexerMetrics,
    ) -> Option<(u64, Entry)> {
        match reader.try_recv().await {
            Ok(Some((position, entry))) => {
                metrics.queue_read(QueueReadSource::TryRecv, QueueStatus::Success);
                metrics.queue_entry(entry.height);
                Some((position, entry))
            }
            Ok(None) => {
                metrics.queue_read(QueueReadSource::TryRecv, QueueStatus::Empty);
                None
            }
            Err(err) => {
                metrics.queue_read(QueueReadSource::TryRecv, QueueStatus::Failure);
                panic!("failed to recv from finalized queue: {err:?}");
            }
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
            let missing_finalization_grace = self.missing_finalization_grace;
            let mismatched_finalization_grace = self.mismatched_finalization_grace;
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

                let mut proof_failure = ProofFailure::default();
                let finalized = loop {
                    let Some(proof) = marshal.get_finalization(Height::new(height)).await else {
                        if let Some(stale) = proof_failure.observe(
                            &context,
                            BackfillResetReason::MissingFinalization,
                            missing_finalization_grace,
                            height,
                            digest,
                        ) {
                            upload.abandoned();
                            return stale;
                        }
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
                        if let Some(stale) = proof_failure.observe(
                            &context,
                            BackfillResetReason::MismatchedFinalization,
                            mismatched_finalization_grace,
                            height,
                            digest,
                        ) {
                            upload.abandoned();
                            return stale;
                        }
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
            Completion::Stale {
                reason,
                first_height,
                first_digest,
                attempts,
                elapsed,
            } => {
                self.reset_stale_queue(reason, first_height, first_digest, attempts, elapsed)
                    .await;
                return;
            }
        };

        let floor = self.reader.ack_floor().await;
        match self.reader.ack(position).await {
            Ok(()) => self.metrics.queue_acked(QueueStatus::Success),
            Err(err) => {
                self.metrics.queue_acked(QueueStatus::Failure);
                panic!("failed to ack: {err:?}");
            }
        }
        let floor_advanced = self.reader.ack_floor().await > floor;
        let sync_started = Instant::now();
        match self.writer.sync().await {
            Ok(()) => self
                .metrics
                .queue_synced(QueueStatus::Success, sync_started.elapsed()),
            Err(err) => {
                self.metrics
                    .queue_synced(QueueStatus::Failure, sync_started.elapsed());
                panic!("failed to sync after ack: {err:?}");
            }
        }
        if floor_advanced {
            self.metrics.queue_ack_floor(height);
            self.uploads.lock().advance_queue_floor(height);
        }
    }

    async fn reset_stale_queue(
        &mut self,
        reason: BackfillResetReason,
        first_height: u64,
        first_digest: Digest,
        attempts: u64,
        elapsed: Duration,
    ) {
        let queue_size = self.writer.size().await;
        let ack_floor = self.reader.ack_floor().await;
        let abandoned_entries = queue_size.saturating_sub(ack_floor);
        let tip = Self::latest_proof_bearing_tip(self.marshal.clone()).await;
        let (tip_height, tip_digest) = tip.unwrap_or((0, first_digest));
        let abandoned_height_span = tip_height.saturating_sub(first_height);

        warn!(
            ?reason,
            first_height,
            ?first_digest,
            tip_height,
            ?tip_digest,
            attempts,
            ?elapsed,
            abandoned_entries,
            abandoned_height_span,
            "resetting stale durable backfill queue"
        );

        self.active.cancel_all();
        match self.reader.ack_up_to(queue_size).await {
            Ok(()) => self.metrics.queue_acked(QueueStatus::Success),
            Err(err) => {
                self.metrics.queue_acked(QueueStatus::Failure);
                panic!("failed to ack stale finalized queue: {err:?}");
            }
        }
        let sync_started = Instant::now();
        match self.writer.sync().await {
            Ok(()) => self
                .metrics
                .queue_synced(QueueStatus::Success, sync_started.elapsed()),
            Err(err) => {
                self.metrics
                    .queue_synced(QueueStatus::Failure, sync_started.elapsed());
                panic!("failed to sync stale finalized queue reset: {err:?}");
            }
        }
        self.reader.reset().await;
        self.metrics.queue_ack_floor(tip_height);
        self.metrics.backfill_queue_reset(
            reason,
            abandoned_entries,
            abandoned_height_span,
        );
        self.uploads.lock().advance_queue_floor(tip_height);
        self.uploads.lock().restart_above(tip_height);
    }

    async fn latest_proof_bearing_tip(
        marshal: MarshalMailbox<Scheme, Standard<Block>>,
    ) -> Option<(u64, Digest)> {
        let (height, _) = marshal.get_info(Identifier::Latest).await?;
        for height in (0..=height.get()).rev() {
            if let Some(proof) = marshal.get_finalization(Height::new(height)).await {
                return Some((height, proof.proposal.payload));
            }
        }
        None
    }
}

#[derive(Default)]
struct ProofFailure {
    reason: Option<BackfillResetReason>,
    first_seen: Option<std::time::SystemTime>,
    attempts: u64,
}

impl ProofFailure {
    fn observe<E: Clock>(
        &mut self,
        context: &E,
        reason: BackfillResetReason,
        grace: Duration,
        height: u64,
        digest: Digest,
    ) -> Option<Completion> {
        if self.reason != Some(reason) {
            self.reason = Some(reason);
            self.first_seen = Some(context.current());
            self.attempts = 0;
        }
        self.attempts = self.attempts.saturating_add(1);
        let elapsed = context
            .current()
            .duration_since(self.first_seen.expect("proof failure start"))
            .unwrap_or_default();
        (elapsed >= grace).then_some(Completion::Stale {
            reason,
            first_height: height,
            first_digest: digest,
            attempts: self.attempts,
            elapsed,
        })
    }
}
