use super::{Entry, SharedState};
use crate::{
    indexer::{metrics::BlockMetricSource, IndexerMetrics},
    Block,
};
use commonware_actor::{
    mailbox::{self, Policy},
    Feedback,
};
use commonware_consensus::{marshal::Update, Reporter};
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_storage::queue;
use commonware_utils::{acknowledgement::Exact, Acknowledgement};
use std::{collections::VecDeque, num::NonZeroUsize};

#[derive(Clone)]
pub struct Producer {
    sender: mailbox::Sender<Message>,
}

struct Message {
    block: Block,
    ack: Exact,
}

impl Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
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
            Update::Block(block, ack) => self.sender.enqueue(Message { block, ack }),
            Update::Tip(_, _, _) => Feedback::Ok,
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
            metrics,
            writer,
            receiver,
        };
        (actor, Producer { sender })
    }

    fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        while let Some(Message { block, ack }) = self.receiver.recv().await {
            self.record(&block).await;
            ack.acknowledge();
        }
    }

    async fn record(&mut self, block: &Block) {
        self.metrics
            .observe_block(BlockMetricSource::ProducerRecord, block);
        let Some(entry) = self.uploads.lock().record(block) else {
            return;
        };
        self.writer
            .enqueue(entry)
            .await
            .expect("failed to enqueue finalized digest");
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
            (),
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
        });
    }
}
