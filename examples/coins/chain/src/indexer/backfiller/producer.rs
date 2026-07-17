use super::{Entry, SharedState};
use crate::{
    indexer::{
        metrics::{
            estimated_block_bytes, BlockMetricSource, ProducerActivity, ProducerStatus,
            QueueStatus,
        },
        IndexerMetrics,
    },
    Block,
};
use commonware_actor::{
    mailbox::{self, Overflow, Policy},
    Feedback,
};
use commonware_consensus::{marshal::Update, Reporter};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_storage::queue;
use commonware_utils::{acknowledgement::Exact, Acknowledgement};
use std::{collections::VecDeque, num::NonZeroUsize, time::Instant};

#[derive(Clone)]
pub struct Producer {
    sender: mailbox::Sender<Message>,
    metrics: IndexerMetrics,
}

struct Message {
    block: Block,
    block_estimated_bytes: u64,
    ack: Exact,
    metrics: IndexerMetrics,
}

impl Message {
    fn new(block: Block, ack: Exact, metrics: IndexerMetrics) -> Self {
        let block_estimated_bytes = estimated_block_bytes(&block);
        Self {
            block,
            block_estimated_bytes,
            ack,
            metrics,
        }
    }
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

struct Actor<E: Clock + Storage + Metrics> {
    context: ContextCell<E>,
    uploads: SharedState,
    metrics: IndexerMetrics,
    writer: queue::Writer<E, Entry>,
    receiver: mailbox::Receiver<Message>,
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

impl<E: Clock + Storage + Metrics + Spawner> Actor<E> {
    fn new(
        context: E,
        uploads: SharedState,
        metrics: IndexerMetrics,
        writer: queue::Writer<E, Entry>,
        mailbox_size: NonZeroUsize,
    ) -> (Self, Producer) {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), mailbox_size);
        let actor = Self {
            context: ContextCell::new(context),
            uploads,
            metrics: metrics.clone(),
            writer,
            receiver,
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
        while let Some(Message { block, ack, .. }) = self.receiver.recv().await {
            self.record(&block).await;
            ack.acknowledge();
        }
    }

    async fn record(&mut self, block: &Block) {
        let started = Instant::now();
        self.metrics
            .observe_block(BlockMetricSource::ProducerRecord, block);
        let Some(entry) = self.uploads.lock().record(block) else {
            self.metrics.producer_recorded(
                ProducerStatus::AlreadyUploaded,
                started.elapsed(),
            );
            return;
        };
        self.metrics.queue_entry(entry.height);
        match self.writer.enqueue(entry).await {
            Ok(_) => {
                self.metrics.queue_enqueued(QueueStatus::Success);
                self.metrics
                    .producer_recorded(ProducerStatus::Recorded, started.elapsed());
            }
            Err(err) => {
                self.metrics.queue_enqueued(QueueStatus::Failure);
                panic!("failed to enqueue finalized digest: {err:?}");
            }
        }
    }
}

pub fn init<E>(
    context: E,
    uploads: SharedState,
    metrics: IndexerMetrics,
    writer: queue::Writer<E, Entry>,
    mailbox_size: NonZeroUsize,
) -> Producer
where
    E: Clock + Storage + Metrics + Spawner,
{
    let (actor, producer) = Actor::new(context, uploads, metrics, writer, mailbox_size);
    actor.start();
    producer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StateCommitment, Transaction, EPOCH};
    use commonware_consensus::types::{Height, Round, View};
    use commonware_cryptography::{ed25519, Digestible, Hasher, Sha256, Signer};
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Runner as _, Supervisor as _,
    };
    use commonware_storage::mmr::Location;
    use commonware_utils::{
        acknowledgement::Exact, range::NonEmptyRange, sync::Mutex, NZUsize, NZU16, NZU64,
    };
    use futures::FutureExt;
    use std::{sync::Arc, time::Duration};

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
    fn queues_finalized_block_before_acknowledging() {
        deterministic::Runner::default().start(|context| async move {
            let page_cache = CacheRef::from_pooler(&context, NZU16!(4_096), NZUsize!(128));
            let (writer, mut reader) = queue::shared::init(
                context.child("queue"),
                queue::Config {
                    partition: "indexer-producer-test".to_string(),
                    items_per_section: NZU64!(16),
                    compression: None,
                    codec_config: (),
                    page_cache,
                    write_buffer: NZUsize!(1024),
                },
            )
            .await
            .expect("init queue");
            let uploads = Arc::new(Mutex::new(crate::indexer::backfiller::State::new()));
            let metrics = IndexerMetrics::register(&context.child("indexer"));
            let mut producer = init(context.child("producer"), uploads, metrics, writer, NZUsize!(4));
            let block = block(2, 2, b"block");
            let digest = block.digest();
            let (ack, waiter) = Exact::handle();

            assert!(producer
                .report(commonware_consensus::marshal::Update::Block(block, ack))
                .accepted());
            commonware_macros::select! {
                result = waiter.fuse() => result.expect("acknowledged"),
                _ = context.sleep(Duration::from_secs(1)) => panic!("ack timed out"),
            }

            let (_, entry) = reader
                .recv()
                .await
                .expect("read queue")
                .expect("queued entry");
            assert_eq!(entry.height, 2);
            assert_eq!(entry.digest, digest);

            let encoded = context.encode();
            assert!(encoded.contains(
                "indexer_producer_report_total{activity=\"block\",status=\"enqueued\"} 1",
            ));
            assert!(encoded.contains(
                "indexer_producer_report_total{activity=\"block\",status=\"recorded\"} 1",
            ));
            assert!(encoded.contains("indexer_producer_record_duration_seconds_bucket"));
        });
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
                sender.enqueue(Message::new(first, ack_1, metrics.clone())),
                Feedback::Ok
            );
            assert_eq!(
                sender.enqueue(Message::new(second, ack_2, metrics.clone())),
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
}
