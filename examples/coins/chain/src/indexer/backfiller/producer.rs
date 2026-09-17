use super::{Entry, SharedState};
use crate::{
    indexer::{
        metrics::{
            estimated_block_bytes, BlockMetricSource, ProducerActivity, ProducerStatus,
        },
        IndexerMetrics, SpoolLimits,
    },
    Block, Finalized, Scheme,
};
use commonware_actor::{
    mailbox::{self, Overflow, Policy},
    Feedback,
};
use commonware_consensus::{
    marshal::{core::Mailbox as MarshalMailbox, standard::Standard, Update},
    types::Height,
    Reporter,
};
use commonware_runtime::{
    spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_utils::{acknowledgement::Exact, Acknowledgement};
use commonware_utils::channel::oneshot;
use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant, UNIX_EPOCH},
};
use tracing::warn;

#[derive(Clone)]
pub struct Producer {
    sender: mailbox::Sender<Message>,
    metrics: IndexerMetrics,
}

pub(crate) struct Admission {
    pub(crate) entry: Entry,
    pub(crate) response: oneshot::Sender<()>,
}

impl Policy for Admission {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

pub(crate) type AdmissionSender = mailbox::Sender<Admission>;
pub(crate) type AdmissionReceiver = mailbox::Receiver<Admission>;

struct Message {
    block: Arc<Block>,
    block_estimated_bytes: u64,
    ack: Exact,
    metrics: IndexerMetrics,
}

impl Message {
    fn new(block: Arc<Block>, ack: Exact, metrics: IndexerMetrics) -> Self {
        let block_estimated_bytes = estimated_block_bytes(&block);
        Self {
            block,
            block_estimated_bytes,
            ack,
            metrics,
        }
    }
}

enum RecordOutcome {
    Complete,
    ResetMailbox,
}

#[derive(Default)]
struct OverflowMessages {
    messages: VecDeque<Message>,
}

impl Overflow<Message> for OverflowMessages {
    fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message) -> Option<Message>,
    {
        while let Some(message) = self.messages.pop_front() {
            let metrics = message.metrics.clone();
            let block_estimated_bytes = message.block_estimated_bytes;
            if let Some(message) = push(message) {
                self.messages.push_front(message);
                break;
            }
            metrics.producer_mailbox_overflow_drained(block_estimated_bytes);
        }
    }
}

impl Policy for Message {
    type Overflow = OverflowMessages;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        message
            .metrics
            .producer_mailbox_overflowed(message.block_estimated_bytes);
        overflow.messages.push_back(message);
    }
}

fn drain_to_latest(receiver: &mut mailbox::Receiver<Message>) -> Option<Message> {
    let mut latest: Option<Message> = None;
    while let Ok(message) = receiver.try_recv() {
        if let Some(stale) = latest.replace(message) {
            stale
                .metrics
                .producer_recorded(ProducerStatus::Ignored, Duration::ZERO);
            stale.ack.acknowledge();
        }
    }
    latest
}

struct Actor<E: BufferPooler + Clock + Storage + Metrics> {
    context: ContextCell<E>,
    uploads: SharedState,
    metrics: IndexerMetrics,
    marshal: MarshalMailbox<Scheme, Standard<Block>>,
    admission: AdmissionSender,
    receiver: mailbox::Receiver<Message>,
    retry: Duration,
    missing_finalization_grace: Duration,
    mismatched_finalization_grace: Duration,
    spool_limits: SpoolLimits,
}

pub(crate) struct Config {
    pub(crate) mailbox_size: NonZeroUsize,
    pub(crate) retry: Duration,
    pub(crate) missing_finalization_grace: Duration,
    pub(crate) mismatched_finalization_grace: Duration,
    pub(crate) spool_limits: SpoolLimits,
}

impl Reporter for Producer {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Update::Block(block, ack) => {
                let feedback =
                    self.sender
                        .enqueue(Message::new(block, ack, self.metrics.clone()));
                let status = if feedback.accepted() {
                    ProducerStatus::Enqueued
                } else {
                    ProducerStatus::Dropped
                };
                self.metrics
                    .producer_reported(ProducerActivity::Block, status);
                feedback
            }
            Update::Tip(_, _, _) => {
                self.metrics
                    .producer_reported(ProducerActivity::Tip, ProducerStatus::Ignored);
                Feedback::Ok
            }
        }
    }
}

impl<E: BufferPooler + Clock + Storage + Metrics + Spawner> Actor<E> {
    fn new(
        context: E,
        uploads: SharedState,
        metrics: IndexerMetrics,
        marshal: MarshalMailbox<Scheme, Standard<Block>>,
        admission: AdmissionSender,
        config: Config,
    ) -> (Self, Producer) {
        let Config {
            mailbox_size,
            retry,
            missing_finalization_grace,
            mismatched_finalization_grace,
            spool_limits,
        } = config;
        let (sender, receiver) = mailbox::new(context.child("mailbox"), mailbox_size);
        let actor = Self {
            context: ContextCell::new(context),
            uploads,
            metrics: metrics.clone(),
            marshal,
            admission,
            receiver,
            retry,
            missing_finalization_grace,
            mismatched_finalization_grace,
            spool_limits,
        };
        (
            actor,
            Producer {
                sender,
                metrics,
            },
        )
    }

    fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        let mut pending = None;
        loop {
            let message = match pending.take() {
                Some(message) => message,
                None => {
                    let Some(message) = self.receiver.recv().await else {
                        break;
                    };
                    message
                }
            };
            let Message { block, ack, .. } = message;
            let outcome = self.record(&block).await;
            ack.acknowledge();
            if matches!(outcome, RecordOutcome::ResetMailbox) {
                pending = drain_to_latest(&mut self.receiver);
            }
        }
    }

    async fn record(&mut self, block: &Block) -> RecordOutcome {
        let started = Instant::now();
        self.metrics
            .observe_block(BlockMetricSource::ProducerRecord, block);
        let Some(candidate) = self.uploads.lock().record(block) else {
            self.metrics.producer_recorded(
                ProducerStatus::AlreadyUploaded,
                started.elapsed(),
            );
            return RecordOutcome::Complete;
        };
        let first_seen = self.context.current();
        self.metrics.certificate_request_started();
        let proof = loop {
            let Some(proof) = self
                .marshal
                .get_finalization(Height::new(candidate.height))
                .await
            else {
                let elapsed = self
                    .context
                    .current()
                    .duration_since(first_seen)
                    .unwrap_or_default();
                if elapsed >= self.missing_finalization_grace {
                    self.metrics.certificate_request_finished();
                    self.metrics.producer_recorded(
                        ProducerStatus::MissingFinalization,
                        started.elapsed(),
                    );
                    warn!(
                        height = candidate.height,
                        ?elapsed,
                        "skipping uncertified indexer payload and resetting producer backlog"
                    );
                    return RecordOutcome::ResetMailbox;
                }
                warn!(height = candidate.height, ?elapsed, "waiting for finalized certificate before spooling indexer payload");
                self.context.sleep(self.retry).await;
                continue;
            };
            if proof.proposal.payload != candidate.digest
                || proof.proposal.round.epoch() != block.header.context.round.epoch()
            {
                let elapsed = self
                    .context
                    .current()
                    .duration_since(first_seen)
                    .unwrap_or_default();
                assert!(
                    elapsed < self.mismatched_finalization_grace,
                    "marshal finalization certificate conflicts with block at height {} after {:?}",
                    candidate.height,
                    elapsed,
                );
                warn!(height = candidate.height, ?elapsed, "waiting for matching finalized certificate before spooling indexer payload");
                self.context.sleep(self.retry).await;
                continue;
            }
            break proof;
        };
        self.metrics.certificate_request_finished();
        let enqueued_at_millis = self
            .context
            .current()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let entry = Entry::new(enqueued_at_millis, Finalized::new(proof, block.clone()));
        let expiry = if entry.encoded_len > self.spool_limits.max_payload_bytes
            || entry.encoded_len > self.spool_limits.max_bytes
        {
            Some(ProducerStatus::ExpiredOversized)
        } else {
            None
        };
        if let Some(status) = expiry {
            self.metrics.producer_recorded(status, started.elapsed());
            warn!(
                height = entry.height(),
                digest = ?entry.digest(),
                encoded_len = entry.encoded_len,
                ?status,
                "terminally expiring finalized indexer payload to preserve spool availability bound"
            );
            return RecordOutcome::Complete;
        }
        let (response, completed) = oneshot::channel();
        let _ = self.admission.enqueue(Admission { entry, response });
        completed
            .await
            .expect("indexer spool admission coordinator stopped");
        self.metrics
            .producer_recorded(ProducerStatus::Recorded, started.elapsed());
        RecordOutcome::Complete
    }
}

pub fn init<E>(
    context: E,
    uploads: SharedState,
    metrics: IndexerMetrics,
    marshal: MarshalMailbox<Scheme, Standard<Block>>,
    admission: AdmissionSender,
    config: Config,
) -> (Producer, Handle<()>)
where
    E: BufferPooler + Clock + Storage + Metrics + Spawner,
{
    let (actor, producer) = Actor::new(
        context,
        uploads,
        metrics,
        marshal,
        admission,
        config,
    );
    let handle = actor.start();
    (producer, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StateCommitment, Transaction, EPOCH};
    use commonware_consensus::types::{Height, Round, View};
    use commonware_cryptography::{ed25519, Hasher, Sha256, Signer};
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
    use commonware_storage::mmr::Location;
    use commonware_utils::{
        acknowledgement::Exact, range::NonEmptyRange, NZUsize,
    };
    use futures::FutureExt as _;

    fn state(height: u64) -> StateCommitment {
        StateCommitment {
            root: Sha256::hash(&height.to_be_bytes()),
            range: NonEmptyRange::new(Location::new(height)..Location::new(height + 1))
                .expect("non-empty range"),
        }
    }

    fn block(view: u64, height: u64, label: &[u8]) -> Block {
        Block::new(
            crate::Context {
                round: Round::new(EPOCH, View::new(view)),
                leader: ed25519::PrivateKey::from_seed(view).public_key(),
                parent: (
                    View::new(view.saturating_sub(1)),
                    Sha256::hash(format!("parent-{view}").as_bytes()),
                ),
            },
            Sha256::hash(label),
            Height::new(height),
            height,
            Vec::<Transaction>::new(),
            None,
            Default::default(),
            state(height),
        )
    }

    #[test]
    fn mailbox_overflow_tracks_retained_block_pressure() {
        deterministic::Runner::default().start(|context| async move {
            let metrics = IndexerMetrics::register(&context.child("indexer"));
            let (sender, mut receiver) = mailbox::new(context.child("mailbox"), NZUsize!(1));
            let (ack_1, _waiter_1) = Exact::handle();
            let (ack_2, _waiter_2) = Exact::handle();

            let first = block(1, 1, b"first");
            let second = block(2, 2, b"second");
            let second_bytes = estimated_block_bytes(&second);

            assert_eq!(
                sender.enqueue(Message::new(first.into(), ack_1, metrics.clone())),
                Feedback::Ok
            );
            assert_eq!(
                sender.enqueue(Message::new(second.into(), ack_2, metrics.clone())),
                Feedback::Backoff
            );

            let encoded = context.encode();
            assert!(encoded.contains("indexer_producer_mailbox_overflow_total 1"));
            assert!(encoded.contains("indexer_producer_mailbox_overflow_entries 1"));
            assert!(encoded.contains(&format!(
                "indexer_producer_mailbox_overflow_block_estimated_bytes {second_bytes}"
            )));

            receiver.try_recv().expect("ready message");

            let encoded = context.encode();
            assert!(encoded.contains("indexer_producer_mailbox_overflow_entries 0"));
            assert!(encoded.contains("indexer_producer_mailbox_overflow_block_estimated_bytes 0"));
        });
    }

    #[test]
    fn reset_acknowledges_backlog_and_retains_latest_block() {
        deterministic::Runner::default().start(|context| async move {
            let metrics = IndexerMetrics::register(&context.child("indexer"));
            let (sender, mut receiver) = mailbox::new(context.child("mailbox"), NZUsize!(1));
            let (ack_1, mut waiter_1) = Exact::handle();
            let (ack_2, mut waiter_2) = Exact::handle();
            let (ack_3, mut waiter_3) = Exact::handle();

            assert_eq!(
                sender.enqueue(Message::new(
                    block(1, 1, b"first").into(),
                    ack_1,
                    metrics.clone(),
                )),
                Feedback::Ok
            );
            assert_eq!(
                sender.enqueue(Message::new(
                    block(2, 2, b"second").into(),
                    ack_2,
                    metrics.clone(),
                )),
                Feedback::Backoff
            );
            assert_eq!(
                sender.enqueue(Message::new(
                    block(3, 3, b"third").into(),
                    ack_3,
                    metrics,
                )),
                Feedback::Backoff
            );

            let latest = drain_to_latest(&mut receiver).expect("latest block");
            assert_eq!(latest.block.header.height, Height::new(3));
            assert!(matches!((&mut waiter_1).now_or_never(), Some(Ok(()))));
            assert!(matches!((&mut waiter_2).now_or_never(), Some(Ok(()))));
            assert!((&mut waiter_3).now_or_never().is_none());

            latest.ack.acknowledge();
            assert!(waiter_3.await.is_ok());

            let encoded = context.encode();
            assert!(encoded.contains(
                "indexer_producer_report_total{activity=\"block\",status=\"ignored\"} 2"
            ));
        });
    }
}
