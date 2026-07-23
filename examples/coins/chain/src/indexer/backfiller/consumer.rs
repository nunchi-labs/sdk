use super::{
    producer::{Admission, AdmissionReceiver},
    Decision, Entry, SharedState,
};
use crate::indexer::{
    metrics::{
        estimated_finalized_bytes, BackfillDecision, BackfillPhase, BackfillWaitReason,
        BlockMetricSource, ProducerStatus, QueueReadSource, QueueStatus,
    },
    Client, IndexerMetrics, SpoolLimits,
};
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
    time::{Duration, Instant, UNIX_EPOCH},
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
        digest: Digest,
    },
}

pub(crate) struct Config {
    pub(crate) max_active: NonZeroUsize,
    pub(crate) retry: Duration,
    pub(crate) spool_limits: SpoolLimits,
}

pub struct Consumer<E: BufferPooler + Spawner + Clock + Storage + Metrics, C: Client> {
    context: ContextCell<E>,
    client: C,
    metrics: IndexerMetrics,
    upload_results: status::Counter,
    uploads: SharedState,
    writer: queue::Writer<E, Entry>,
    reader: queue::Reader<E, Entry>,
    admission: AdmissionReceiver,
    active: Pool<Completion>,
    max_active: NonZeroUsize,
    retry: Duration,
    spool_limits: SpoolLimits,
}

impl<E: BufferPooler + Spawner + Clock + Storage + Metrics, C: Client> Consumer<E, C> {
    pub fn new(
        context: E,
        client: C,
        metrics: IndexerMetrics,
        uploads: SharedState,
        backfiller: (queue::Writer<E, Entry>, queue::Reader<E, Entry>),
        admission: AdmissionReceiver,
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
            spool_limits,
        } = config;
        metrics.backfill_configured(max_active.get());
        let (writer, reader) = backfiller;
        Self {
            context: ContextCell::new(context),
            client,
            metrics,
            upload_results,
            uploads,
            writer,
            reader,
            admission,
            active: Pool::default(),
            max_active,
            retry,
            spool_limits,
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
                let item = OptionFuture::from(
                    (self.active.len() < self.max_active.get()).then(|| {
                        Self::recv_queue(&mut self.reader, self.metrics.clone())
                    }),
                );
                let admission = self.admission.recv();
            },
            on_stopped => {},
            completion = self.active.next_completed() => {
                self.complete(completion).await;
            },
            request = admission => {
                let Some(request) = request else {
                    warn!("indexer spool admission coordinator closed");
                    break;
                };
                self.admit(request).await;
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

    async fn admit(&mut self, admission: Admission) {
        let Admission { entry, response } = admission;
        loop {
            let now_millis: u64 = self
                .context
                .current()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            let next = {
                let uploads = self.uploads.lock();
                let (entries, bytes) = uploads.spool_usage();
                uploads.oldest_queued().and_then(
                    |(digest, position, height, old_bytes, enqueued_at)| {
                        let age = Duration::from_millis(
                            now_millis.saturating_sub(enqueued_at),
                        );
                        let status = if age >= self.spool_limits.max_age {
                            Some(ProducerStatus::ExpiredAge)
                        } else if entries >= self.spool_limits.max_entries {
                            Some(ProducerStatus::ExpiredEntries)
                        } else if bytes.saturating_add(entry.encoded_len)
                            > self.spool_limits.max_bytes
                        {
                            Some(ProducerStatus::ExpiredBytes)
                        } else {
                            None
                        };
                        status.map(|status| {
                            (digest, position, height, old_bytes, age, status)
                        })
                    },
                )
            };
            let Some((digest, position, height, encoded_len, age, status)) = next else {
                break;
            };

            // Advancing the floor invalidates positions held by upload tasks. Cancel all of them
            // and replay the still-live suffix so a stale completion cannot be applied twice.
            self.active.cancel_all();
            self.reader
                .ack_up_to(position.saturating_add(1))
                .await
                .unwrap_or_else(|error| panic!("failed to expire indexer spool floor: {error:?}"));
            let sync_started = Instant::now();
            self.writer.sync().await.unwrap_or_else(|error| {
                panic!("failed to durably sync expired indexer spool floor: {error:?}")
            });
            self.metrics
                .queue_synced(QueueStatus::Success, sync_started.elapsed());
            self.reader.reset().await;
            let expired = self.uploads.lock().expire_through(position);
            for (_, _, _) in &expired {
                self.metrics.producer_recorded(status, Duration::ZERO);
            }
            warn!(
                height,
                ?digest,
                encoded_len,
                ?age,
                ?status,
                expired_entries = expired.len(),
                "terminally expired oldest finalized indexer payload before admission"
            );
        }

        self.metrics.queue_entry(entry.height());
        let position = self.writer.enqueue(entry.clone()).await.unwrap_or_else(|error| {
            self.metrics.queue_enqueued(QueueStatus::Failure);
            panic!("failed to enqueue finalized indexer payload: {error:?}")
        });
        self.uploads.lock().mark_queued(position, &entry);
        self.metrics.queue_enqueued(QueueStatus::Success);
        response
            .send(())
            .expect("indexer spool producer stopped before admission completed");
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
                metrics.queue_entry(entry.height());
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
                metrics.queue_entry(entry.height());
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
        let height = entry.height();
        let digest = entry.digest();
        let enqueued_at_millis = entry.enqueued_at_millis;
        let finalized = entry.finalized;
        if self.payload_age(enqueued_at_millis) >= self.spool_limits.max_age {
            self.metrics
                .producer_recorded(ProducerStatus::ExpiredAge, Duration::ZERO);
            warn!(
                height,
                ?digest,
                "terminally expiring finalized indexer payload at configured age bound"
            );
            self.complete(Completion::Skipped {
                position,
                height,
                digest,
            })
            .await;
            return;
        }
        let decision = self.uploads.lock().should_upload(&digest);
        self.metrics
            .backfill_decision((&decision).into(), BackfillPhase::Start);
        if matches!(decision, Decision::Skip) {
            {
                let mut upload = self.metrics.start_backfill_upload();
                upload.skipped();
            }
            self.complete(Completion::Skipped {
                position,
                height,
                digest,
            })
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
            let metrics = self.metrics.clone();
            let upload_results = self.upload_results.clone();
            let uploads = self.uploads.clone();
            let retry = self.retry;
            let max_age = self.spool_limits.max_age;
            async move {
                let mut upload = metrics.start_backfill_upload();
                metrics.observe_block(BlockMetricSource::ConsumerCached, &finalized.block);
                upload.hold_block(&finalized.block);

                loop {
                    let now_millis: u64 = context
                        .current()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX);
                    // Backward wall-clock movement produces age zero until the clock catches up.
                    let age = Duration::from_millis(now_millis.saturating_sub(enqueued_at_millis));
                    if age >= max_age {
                        metrics.producer_recorded(ProducerStatus::ExpiredAge, Duration::ZERO);
                        warn!(height, ?digest, ?age, "terminally expiring active finalized indexer upload at configured age bound");
                        return Completion::Skipped {
                            position,
                            height,
                            digest,
                        };
                    }
                    let decision = {
                        let uploads = uploads.lock();
                        uploads.should_upload(&digest)
                    };
                    metrics.backfill_decision((&decision).into(), BackfillPhase::BeforeAttempt);
                    match decision {
                        Decision::Skip => {
                            upload.skipped();
                            debug!(?digest, "skipping previously uploaded block");
                            return Completion::Skipped {
                                position,
                                height,
                                digest,
                            };
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

    fn payload_age(&self, enqueued_at_millis: u64) -> Duration {
        let now_millis: u64 = self
            .context
            .current()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        // Backward wall-clock movement produces age zero until the clock catches up.
        Duration::from_millis(now_millis.saturating_sub(enqueued_at_millis))
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
        let (position, height, digest) = match completion {
            Completion::Uploaded {
                position,
                height,
                digest,
            } => {
                self.uploads.lock().mark_uploaded(digest, height);
                (position, height, digest)
            }
            Completion::Skipped {
                position,
                height,
                digest,
            } => (position, height, digest),
        };
        self.uploads.lock().finish_queued(&digest);

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

}
