use std::{panic::AssertUnwindSafe, sync::Arc};

use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::types::{Epoch, Height, Round, View};
use commonware_cryptography::{ed25519, Digestible as _, Hasher, Sha256, Signer};
use commonware_glue::stateful::{
    db::{DatabaseSet as _, Merkleized as _},
    Application as StatefulApplication,
};
use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use commonware_storage::mmr::Location;
use commonware_utils::{non_empty_range, sync::AsyncRwLock};
use futures::{lock::Mutex as AsyncMutex, FutureExt};
use nunchi_common::{
    Event, EventSink, NoopEventSink, QmdbBackend, QmdbBatch, QmdbDatabaseSet, QmdbMerkleized,
    QmdbState, Runtime, RuntimeContext, StateError, StateStore,
};
use nunchi_dkg::Context;
use nunchi_mempool::{Mempool, PoolConfig, PoolTransaction};
use thiserror::Error;

use crate::{
    Application, Block, EventReporter, InMemoryEventReporter, NoConsensusExtension,
    NoopEventReporter, StateCommitment,
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
    type Digest = u64;
    type NonceKey = u8;
    type VerifyError = BadSignature;

    fn digest(&self) -> Self::Digest {
        self.id
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
        test_context(parent.height.get() + 1, parent),
        parent.digest(),
        parent.height.next(),
        parent.timestamp + 1,
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
    application_with_reporter(context, NoopEventReporter).await
}

async fn application_with_reporter<Reporter>(
    context: deterministic::Context,
    event_reporter: Reporter,
) -> (
    Application<TestRuntime, NoConsensusExtension, Reporter>,
    QmdbDatabaseSet<deterministic::Context>,
    Block<TestTx>,
)
where
    Reporter: EventReporter<u64>,
{
    let (_mempool, submitter) = Mempool::new(PoolConfig::default());
    let config = QmdbState::<deterministic::Context>::config(&context, "event-sink-test");
    let db = QmdbBackend::init(context, config)
        .await
        .expect("init state db");
    let databases: QmdbDatabaseSet<deterministic::Context> = Arc::new(AsyncRwLock::new(db));
    let genesis_target = databases.committed_targets().await;
    let genesis_state = StateCommitment {
        root: genesis_target.root,
        range: genesis_target.range,
    };
    let app = Application::new_with_event_reporter(
        submitter,
        16,
        event_reporter,
        Arc::new(AsyncMutex::new(Height::zero())),
        genesis_state,
        Sha256::hash(b"test genesis"),
    );
    let parent = app.genesis_block();
    (app, databases, parent)
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
                (context.child("verify"), block.context.clone()),
                futures::stream::iter([block, parent]),
                databases.new_batches().await,
            )
            .await;

        assert!(verified.is_some());
    });
}

type ReportingApplication =
    Application<TestRuntime, NoConsensusExtension, InMemoryEventReporter<u64>>;

#[test]
fn certified_apply_collects_events_without_reporting() {
    deterministic::Runner::default().start(|context| async move {
        let (mut app, databases, parent) = application(context.child("app")).await;
        let transactions = vec![TestTx {
            account: 1,
            nonce: 0,
            id: 11,
            value: 9,
        }];
        let state = committed_state(&databases, &transactions).await;
        let block = block(&parent, transactions, state);

        let merkleized =
            <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::apply(
                &mut app,
                (context.child("apply"), block.context.clone()),
                &block,
                databases.new_batches().await,
            )
            .await;

        assert_eq!(merkleized.root(), block.state_root);
        assert_eq!(state_range(&merkleized), block.state_range);
    });
}

#[test]
fn certified_apply_discards_events_from_failed_transaction() {
    deterministic::Runner::default().start(|context| async move {
        let reporter = InMemoryEventReporter::<u64>::new();
        let (mut app, databases, parent) =
            application_with_reporter(context.child("app"), reporter.clone()).await;
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
            (context.child("apply"), block.context.clone()),
            &block,
            databases.new_batches().await,
        );
        assert!(AssertUnwindSafe(apply).catch_unwind().await.is_err());
        assert!(reporter.is_empty());

        <ReportingApplication as StatefulApplication<deterministic::Context>>::finalized(
            &mut app,
            (context.child("finalized"), block.context.clone()),
            &block,
            &databases,
        )
        .await;

        let reports = reporter.reports();
        assert_eq!(reports.len(), 1);
        let report = &reports[0];
        assert_eq!(report.height, block.height);
        assert_eq!(report.block_digest, block.digest());
        assert_eq!(report.block_timestamp, block.timestamp);
        assert!(report.transactions.is_empty());
    });
}

#[test]
fn finalized_reports_collected_events_after_database_finalize() {
    deterministic::Runner::default().start(|context| async move {
        let reporter = InMemoryEventReporter::<u64>::new();
        let (mut app, databases, parent) =
            application_with_reporter(context.child("app"), reporter.clone()).await;
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
                (context.child("apply"), block.context.clone()),
                &block,
                databases.new_batches().await,
            )
            .await;

        assert!(reporter.is_empty());
        databases.finalize(merkleized).await;
        assert!(reporter.is_empty());

        <ReportingApplication as StatefulApplication<deterministic::Context>>::finalized(
            &mut app,
            (context.child("finalized"), block.context.clone()),
            &block,
            &databases,
        )
        .await;

        let reports = reporter.reports();
        assert_eq!(reports.len(), 1);
        let report = &reports[0];
        assert_eq!(report.height, block.height);
        assert_eq!(report.block_digest, block.digest());
        assert_eq!(report.block_timestamp, block.timestamp);
        assert_eq!(report.transactions.len(), 2);

        let first = &report.transactions[0];
        assert_eq!(first.tx_index, 0);
        assert_eq!(first.tx_digest, 20);
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
        assert_eq!(second.tx_digest, 21);
        assert_eq!(second.events[0].event_index, 0);
        assert_eq!(second.events[1].event_index, 1);
    });
}

#[test]
fn finalized_reports_empty_events_when_handoff_is_missing() {
    deterministic::Runner::default().start(|context| async move {
        let reporter = InMemoryEventReporter::<u64>::new();
        let (mut app, databases, parent) =
            application_with_reporter(context.child("app"), reporter.clone()).await;
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
            (context.child("finalized"), block.context.clone()),
            &block,
            &databases,
        )
        .await;

        let reports = reporter.reports();
        assert_eq!(reports.len(), 1);
        let report = &reports[0];
        assert_eq!(report.height, block.height);
        assert_eq!(report.block_digest, block.digest());
        assert_eq!(report.block_timestamp, block.timestamp);
        assert!(report.transactions.is_empty());
    });
}
