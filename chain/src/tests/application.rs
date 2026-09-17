use std::{
    future::Future as _,
    num::NonZeroU64,
    panic::AssertUnwindSafe,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::types::{Epoch, Height, Round, View};
use commonware_cryptography::{ed25519, sha256::Digest, Digestible as _, Hasher, Sha256, Signer};
use commonware_glue::stateful::{
    db::{DatabaseSet as _, Merkleized as _},
    Application as StatefulApplication,
};
use commonware_runtime::{deterministic, Clock as _, Runner as _, Supervisor as _};
use commonware_storage::mmr::Location;
use commonware_utils::{non_empty_range, SystemTimeExt as _, NZU64};
use nunchi_common::shared_database;
use futures::{lock::Mutex as AsyncMutex, FutureExt};
use nunchi_common::{
    Event, EventSink, NoopEventSink, QmdbBackend, QmdbBatch, QmdbDatabaseSet, QmdbMerkleized,
    QmdbState, Runtime, RuntimeContext, StateError, StateStore,
};
use nunchi_dkg::Context;
use nunchi_mempool::{Mempool, PoolConfig, PoolTransaction};
use thiserror::Error;

use crate::{
    Application, Block, EventConsumer, InMemoryEventConsumer, NoConsensusExtension,
    NoopEventConsumer, StateCommitment,
};

// Keep this test runtime local to nunchi-chain so event reporting tests do not depend on
// module-specific transaction setup or coins ledger state.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TestTx {
    account: u8,
    nonce: u64,
    id: u64,
    value: u8,
}

impl Write for TestTx {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.nonce.write(buf);
        self.id.write(buf);
        self.value.write(buf);
    }
}

impl Read for TestTx {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            account: u8::read(buf)?,
            nonce: u64::read(buf)?,
            id: u64::read(buf)?,
            value: u8::read(buf)?,
        })
    }
}

impl EncodeSize for TestTx {
    fn encode_size(&self) -> usize {
        self.account.encode_size()
            + self.nonce.encode_size()
            + self.id.encode_size()
            + self.value.encode_size()
    }
}

#[derive(Debug, Error)]
#[error("bad signature")]
struct BadSignature;

impl PoolTransaction for TestTx {
    type NonceKey = u8;
    type VerifyError = BadSignature;

    fn digest(&self) -> Digest {
        Sha256::hash(&self.id.to_be_bytes())
    }

    fn nonce_key(&self) -> Self::NonceKey {
        self.account
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn encoded_size(&self) -> usize {
        EncodeSize::encode_size(self)
    }

    fn verify(&self) -> Result<(), Self::VerifyError> {
        assert_ne!(
            self.id,
            u64::MAX,
            "timestamp-invalid transaction reached signature verification"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct TestRuntime;

#[derive(Debug, Error)]
enum TestError {
    #[error("state error: {0}")]
    State(#[from] StateError),
    #[error("rejected")]
    Rejected,
}

impl Runtime for TestRuntime {
    type Transaction = TestTx;
    type Error = TestError;

    async fn validate<S>(
        state: &mut S,
        _context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
    {
        write_transaction(state, transaction);
        Ok(())
    }

    async fn apply<S, Events>(
        state: &mut S,
        _context: RuntimeContext,
        transaction: &Self::Transaction,
        events: &mut Events,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
        Events: EventSink + Send,
    {
        assert_ne!(
            transaction.id,
            u64::MAX,
            "timestamp-invalid transaction reached state execution"
        );
        if transaction.value == 7 {
            assert_eq!(
                std::any::type_name::<Events>(),
                std::any::type_name::<NoopEventSink>()
            );
        }
        events.emit(Event::new(
            Bytes::from_static(b"test.applied.v1"),
            Bytes::copy_from_slice(&transaction.id.to_be_bytes()),
        ));
        events.emit(Event::new(
            Bytes::from_static(b"test.value.v1"),
            Bytes::copy_from_slice(&[transaction.value]),
        ));
        if transaction.value == u8::MAX {
            return Err(TestError::Rejected);
        }
        write_transaction(state, transaction);
        Ok(())
    }

    fn is_storage_error(error: &Self::Error) -> bool {
        matches!(error, TestError::State(_))
    }
}

fn write_transaction<S: StateStore>(state: &mut S, transaction: &TestTx) {
    state.set(
        Sha256::hash(&transaction.id.to_be_bytes()),
        vec![transaction.value],
    );
}

fn state_range<E: commonware_storage::Context>(
    merkleized: &QmdbMerkleized<E>,
) -> commonware_utils::range::NonEmptyRange<Location> {
    let bounds = merkleized.bounds();
    non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size))
}

fn test_context(view: u64, parent: &Block<TestTx>) -> Context {
    Context {
        round: Round::new(Epoch::zero(), View::new(view)),
        leader: ed25519::PrivateKey::from_seed(view).public_key(),
        parent: (View::new(view - 1), parent.digest()),
    }
}

async fn committed_state<E>(
    databases: &QmdbDatabaseSet<E>,
    transactions: &[TestTx],
) -> StateCommitment
where
    E: commonware_storage::Context,
{
    merkleized_state(databases, transactions).await.0
}

async fn merkleized_state<E>(
    databases: &QmdbDatabaseSet<E>,
    transactions: &[TestTx],
) -> (StateCommitment, QmdbMerkleized<E>)
where
    E: commonware_storage::Context,
{
    let mut batch = QmdbBatch::new(databases.new_batches().await);
    let mut events = NoopEventSink;
    for transaction in transactions {
        TestRuntime::apply(
            &mut batch,
            RuntimeContext::default(),
            transaction,
            &mut events,
        )
        .await
        .expect("apply transaction");
    }
    let merkleized = batch.merkleize().await.expect("merkleize transactions");
    let state = StateCommitment {
        root: merkleized.root(),
        range: state_range(&merkleized),
    };
    (state, merkleized)
}

fn block(
    parent: &Block<TestTx>,
    transactions: Vec<TestTx>,
    state: StateCommitment,
) -> Block<TestTx> {
    Block::new(
        test_context(parent.header.height.get() + 1, parent),
        parent.digest(),
        parent.header.height.next(),
        parent.header.timestamp + 1,
        transactions,
        None,
        (),
        state,
    )
}

fn block_at(
    parent: &Block<TestTx>,
    timestamp: u64,
    transactions: Vec<TestTx>,
    state: StateCommitment,
) -> Block<TestTx> {
    Block::new(
        test_context(parent.header.height.get() + 1, parent),
        parent.digest(),
        parent.header.height.next(),
        timestamp,
        transactions,
        None,
        (),
        state,
    )
}

async fn application(
    context: deterministic::Context,
) -> (
    Application<TestRuntime>,
    QmdbDatabaseSet<deterministic::Context>,
    Block<TestTx>,
) {
    application_with_interval(context, NZU64!(1)).await
}

async fn application_with_interval(
    context: deterministic::Context,
    min_block_interval_ms: NonZeroU64,
) -> (
    Application<TestRuntime>,
    QmdbDatabaseSet<deterministic::Context>,
    Block<TestTx>,
) {
    application_with_events_and_interval(context, NoopEventConsumer, min_block_interval_ms).await
}

async fn application_with_events<Events>(
    context: deterministic::Context,
    events: Events,
) -> (
    Application<TestRuntime, NoConsensusExtension, Events>,
    QmdbDatabaseSet<deterministic::Context>,
    Block<TestTx>,
)
where
    Events: EventConsumer,
{
    application_with_events_and_interval(context, events, NZU64!(1)).await
}

async fn application_with_events_and_interval<Events>(
    context: deterministic::Context,
    events: Events,
    min_block_interval_ms: NonZeroU64,
) -> (
    Application<TestRuntime, NoConsensusExtension, Events>,
    QmdbDatabaseSet<deterministic::Context>,
    Block<TestTx>,
)
where
    Events: EventConsumer,
{
    let (_mempool, submitter) = Mempool::new(PoolConfig::default());
    let config = QmdbState::<deterministic::Context>::config(&context, "event-sink-test");
    let db = QmdbBackend::init(context, config)
        .await
        .expect("init state db");
    let databases: QmdbDatabaseSet<deterministic::Context> = shared_database(db);
    let genesis_target = databases.committed_targets().await;
    let genesis_state = StateCommitment {
        root: genesis_target.root,
        range: genesis_target.range,
    };
    let app = Application::new_with_events(
        submitter,
        16,
        min_block_interval_ms,
        events,
        Arc::new(AsyncMutex::new(Height::zero())),
        genesis_state,
        Sha256::hash(b"test genesis"),
    );
    let parent = app.genesis_block();
    (app, databases, parent)
}

async fn propose(
    app: &mut Application<TestRuntime>,
    databases: &QmdbDatabaseSet<deterministic::Context>,
    context: deterministic::Context,
    parent: Block<TestTx>,
) -> Option<commonware_glue::stateful::Proposed<Application<TestRuntime>, deterministic::Context>> {
    let (mempool, mut input) = Mempool::new(PoolConfig::default());
    mempool.start(context.child("proposal_mempool"));
    <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::propose(
        app,
        (context, test_context(parent.header.height.get() + 1, &parent)),
        futures::stream::iter([Arc::new(parent)]),
        databases.new_batches().await,
        &mut input,
    )
    .await
}

async fn verify(
    app: &mut Application<TestRuntime>,
    databases: &QmdbDatabaseSet<deterministic::Context>,
    context: deterministic::Context,
    block: Block<TestTx>,
    parent: Block<TestTx>,
) -> bool {
    <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::verify(
        app,
        (context, block.header.context.clone()),
        futures::stream::iter([Arc::new(block), Arc::new(parent)]),
        databases.new_batches().await,
    )
    .await
    .is_some()
}

fn state_of(block: &Block<TestTx>) -> StateCommitment {
    StateCommitment {
        root: block.header.state_root,
        range: block.header.state_range.clone(),
    }
}

fn with_timestamp(block: &Block<TestTx>, timestamp: u64) -> Block<TestTx> {
    Block::new(
        block.header.context.clone(),
        block.header.parent,
        block.header.height,
        timestamp,
        block.transactions.clone(),
        block.header.reshare_log.clone(),
        (),
        state_of(block),
    )
}

#[test]
fn enforces_configured_minimum_block_interval() {
    deterministic::Runner::default().start(|context| async move {
        let (mut app, databases, parent) =
            application_with_interval(context.child("app"), NZU64!(500)).await;
        let state = merkleized_state(&databases, &[]).await.0;

        let too_early = block_at(&parent, parent.header.timestamp + 499, Vec::new(), state.clone());
        assert!(
            !verify(
                &mut app,
                &databases,
                context.child("reject_499"),
                too_early,
                parent.clone(),
            )
            .await
        );

        let exact = block_at(&parent, parent.header.timestamp + 500, Vec::new(), state.clone());
        assert!(
            verify(
                &mut app,
                &databases,
                context.child("accept_500"),
                exact,
                parent.clone(),
            )
            .await
        );

        let later = block_at(&parent, parent.header.timestamp + 750, Vec::new(), state);
        assert!(
            verify(
                &mut app,
                &databases,
                context.child("accept_later"),
                later,
                parent,
            )
            .await
        );
    });
}

#[test]
fn timestamp_rejection_precedes_transaction_work() {
    deterministic::Runner::default().start(|context| async move {
        let (mut app, databases, parent) =
            application_with_interval(context.child("app"), NZU64!(500)).await;
        let block = block_at(
            &parent,
            parent.header.timestamp + 499,
            vec![TestTx {
                account: 1,
                nonce: 0,
                id: u64::MAX,
                value: 1,
            }],
            state_of(&parent),
        );

        assert!(
            !verify(
                &mut app,
                &databases,
                context.child("verify"),
                block,
                parent,
            )
            .await
        );
    });
}

#[test]
fn proposes_at_minimum_or_runtime_clock() {
    deterministic::Runner::default().start(|context| async move {
        let (mut app, databases, genesis) =
            application_with_interval(context.child("app"), NZU64!(500)).await;
        let current = context.current().epoch_millis();
        let parent = with_timestamp(&genesis, current + 10_000);
        let proposed = propose(
            &mut app,
            &databases,
            context.child("clock_behind"),
            parent.clone(),
        )
        .await
        .expect("proposal at minimum");
        assert_eq!(proposed.block.header.timestamp, parent.header.timestamp + 500);

        context.sleep(Duration::from_secs(1)).await;
        let current = context.current().epoch_millis();
        let proposed = propose(
            &mut app,
            &databases,
            context.child("clock_ahead"),
            genesis,
        )
        .await
        .expect("proposal at runtime clock");
        assert_eq!(proposed.block.header.timestamp, current);
    });
}

#[test]
fn handles_timestamp_overflow_and_cutoff_without_panicking() {
    deterministic::Runner::default().start(|context| async move {
        let (mut app, databases, genesis) =
            application_with_interval(context.child("app"), NZU64!(500)).await;
        let parent = with_timestamp(&genesis, u64::MAX - 499);

        assert!(
            propose(
                &mut app,
                &databases,
                context.child("propose_overflow"),
                parent.clone(),
            )
            .await
            .is_none()
        );

        let overflow_child = block_at(&parent, u64::MAX, Vec::new(), state_of(&parent));
        assert!(
            !verify(
                &mut app,
                &databases,
                context.child("verify_overflow"),
                overflow_child,
                parent,
            )
            .await
        );

        let parent = genesis;
        let above_cutoff = block_at(&parent, u64::MAX, Vec::new(), state_of(&parent));
        assert!(
            !verify(
                &mut app,
                &databases,
                context.child("above_cutoff"),
                above_cutoff,
                parent,
            )
            .await
        );
    });
}

#[test]
fn one_millisecond_interval_remains_available_for_focused_tests() {
    deterministic::Runner::default().start(|context| async move {
        let (mut app, databases, genesis) =
            application_with_interval(context.child("app"), NZU64!(1)).await;
        let current = context.current().epoch_millis();
        let parent = with_timestamp(&genesis, current + 10_000);
        let state = merkleized_state(&databases, &[]).await.0;
        let exact = block_at(&parent, parent.header.timestamp + 1, Vec::new(), state);
        assert!(
            verify(
                &mut app,
                &databases,
                context.child("verify"),
                exact,
                parent.clone(),
            )
            .await
        );

        let proposed = propose(&mut app, &databases, context.child("propose"), parent)
            .await
            .expect("proposal at one millisecond minimum");
        assert_eq!(proposed.block.header.timestamp, current + 10_001);
    });
}

#[test]
fn timestamp_wait_is_cancellation_safe() {
    deterministic::Runner::default().start(|context| async move {
        let (mut app, databases, parent) =
            application_with_interval(context.child("app"), NZU64!(500)).await;
        let timestamp = context.current().epoch_millis() + 60_000;
        let block = block_at(&parent, timestamp, Vec::new(), state_of(&parent));
        let batches = databases.new_batches().await;
        {
            let verify =
                <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::verify(
                    &mut app,
                    (context.child("verify"), block.header.context.clone()),
                    futures::stream::iter([Arc::new(block), Arc::new(parent)]),
                    batches,
                );
            futures::pin_mut!(verify);
            let waker = futures::task::noop_waker();
            let mut task_context = TaskContext::from_waker(&waker);
            assert!(matches!(
                verify.as_mut().poll(&mut task_context),
                Poll::Pending
            ));
        }
    });
}

#[test]
fn verification_uses_noop_event_sink() {
    deterministic::Runner::default().start(|context| async move {
        let (mut app, databases, parent) = application(context.child("app")).await;
        let transactions = vec![TestTx {
            account: 1,
            nonce: 0,
            id: 10,
            value: 7,
        }];
        let state = committed_state(&databases, &transactions).await;
        let block = block(&parent, transactions, state);

        let verified =
            <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::verify(
                &mut app,
                (context.child("verify"), block.header.context.clone()),
                futures::stream::iter([Arc::new(block), Arc::new(parent)]),
                databases.new_batches().await,
            )
            .await;

        assert!(verified.is_some());
    });
}

type ReportingApplication = Application<TestRuntime, NoConsensusExtension, InMemoryEventConsumer>;

#[test]
fn certified_apply_uses_default_noop_consumer() {
    deterministic::Runner::default().start(|context| async move {
        let (mut app, databases, parent) = application(context.child("app")).await;
        let transactions = vec![TestTx {
            account: 1,
            nonce: 0,
            id: 11,
            value: 7,
        }];
        let state = committed_state(&databases, &transactions).await;
        let block = block(&parent, transactions, state);

        let merkleized =
            <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::apply(
                &mut app,
                (context.child("apply"), block.header.context.clone()),
                &block,
                databases.new_batches().await,
            )
            .await;

        assert_eq!(merkleized.root(), block.header.state_root);
        assert_eq!(state_range(&merkleized), block.header.state_range);
    });
}

#[test]
fn certified_apply_discards_events_from_failed_transaction() {
    deterministic::Runner::default().start(|context| async move {
        let consumer = InMemoryEventConsumer::new();
        let (mut app, databases, parent) =
            application_with_events(context.child("app"), consumer.clone()).await;
        let applied = TestTx {
            account: 1,
            nonce: 0,
            id: 12,
            value: 9,
        };
        let failing = TestTx {
            account: 1,
            nonce: 1,
            id: 13,
            value: u8::MAX,
        };
        let state = committed_state(&databases, std::slice::from_ref(&applied)).await;
        let block = block(&parent, vec![applied, failing], state);

        let apply = <ReportingApplication as StatefulApplication<deterministic::Context>>::apply(
            &mut app,
            (context.child("apply"), block.header.context.clone()),
            &block,
            databases.new_batches().await,
        );
        assert!(AssertUnwindSafe(apply).catch_unwind().await.is_err());
        assert!(consumer.is_empty());

        <ReportingApplication as StatefulApplication<deterministic::Context>>::finalized(
            &mut app,
            (context.child("finalized"), block.header.context.clone()),
            &block,
            &databases,
        )
        .await;

        let reports = consumer.reports();
        assert_eq!(reports.len(), 1);
        let report = &reports[0];
        assert_eq!(report.height, block.header.height);
        assert_eq!(report.block_digest, block.digest());
        assert_eq!(report.block_timestamp, block.header.timestamp);
        assert!(report.transactions.is_empty());
    });
}

#[test]
fn finalized_reports_collected_events_after_database_finalize() {
    deterministic::Runner::default().start(|context| async move {
        let consumer = InMemoryEventConsumer::new();
        let (mut app, databases, parent) =
            application_with_events(context.child("app"), consumer.clone()).await;
        let transactions = vec![
            TestTx {
                account: 1,
                nonce: 0,
                id: 20,
                value: 3,
            },
            TestTx {
                account: 1,
                nonce: 1,
                id: 21,
                value: 4,
            },
        ];
        let state = committed_state(&databases, &transactions).await;
        let block = block(&parent, transactions, state);

        let merkleized =
            <ReportingApplication as StatefulApplication<deterministic::Context>>::apply(
                &mut app,
                (context.child("apply"), block.header.context.clone()),
                &block,
                databases.new_batches().await,
            )
            .await;

        assert!(consumer.is_empty());
        databases.finalize(merkleized).await;
        assert!(consumer.is_empty());

        <ReportingApplication as StatefulApplication<deterministic::Context>>::finalized(
            &mut app,
            (context.child("finalized"), block.header.context.clone()),
            &block,
            &databases,
        )
        .await;

        let reports = consumer.reports();
        assert_eq!(reports.len(), 1);
        let report = &reports[0];
        assert_eq!(report.height, block.header.height);
        assert_eq!(report.block_digest, block.digest());
        assert_eq!(report.block_timestamp, block.header.timestamp);
        assert_eq!(report.transactions.len(), 2);

        let first = &report.transactions[0];
        assert_eq!(first.tx_index, 0);
        assert_eq!(first.tx_digest, Sha256::hash(&20u64.to_be_bytes()));
        assert_eq!(first.events.len(), 2);
        assert_eq!(first.events[0].event_index, 0);
        assert_eq!(
            first.events[0].event.name,
            Bytes::from_static(b"test.applied.v1")
        );
        assert_eq!(
            first.events[0].event.value,
            Bytes::copy_from_slice(&20u64.to_be_bytes())
        );
        assert_eq!(first.events[1].event_index, 1);
        assert_eq!(
            first.events[1].event.name,
            Bytes::from_static(b"test.value.v1")
        );
        assert_eq!(first.events[1].event.value, Bytes::copy_from_slice(&[3]));

        let second = &report.transactions[1];
        assert_eq!(second.tx_index, 1);
        assert_eq!(second.tx_digest, Sha256::hash(&21u64.to_be_bytes()));
        assert_eq!(second.events[0].event_index, 0);
        assert_eq!(second.events[1].event_index, 1);
    });
}

#[test]
fn finalized_reports_empty_events_when_handoff_is_missing() {
    deterministic::Runner::default().start(|context| async move {
        let consumer = InMemoryEventConsumer::new();
        let (mut app, databases, parent) =
            application_with_events(context.child("app"), consumer.clone()).await;
        let transactions = vec![TestTx {
            account: 1,
            nonce: 0,
            id: 30,
            value: 5,
        }];
        let (state, merkleized) = merkleized_state(&databases, &transactions).await;
        let block = block(&parent, transactions, state);

        databases.finalize(merkleized).await;
        <ReportingApplication as StatefulApplication<deterministic::Context>>::finalized(
            &mut app,
            (context.child("finalized"), block.header.context.clone()),
            &block,
            &databases,
        )
        .await;

        let reports = consumer.reports();
        assert_eq!(reports.len(), 1);
        let report = &reports[0];
        assert_eq!(report.height, block.header.height);
        assert_eq!(report.block_digest, block.digest());
        assert_eq!(report.block_timestamp, block.header.timestamp);
        assert!(report.transactions.is_empty());
    });
}
