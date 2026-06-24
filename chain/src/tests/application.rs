use bytes::Bytes;
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::types::{Epoch, Height, Round, View};
use commonware_cryptography::{ed25519, sha256, Digestible as _, Hasher, Sha256, Signer};
use commonware_glue::stateful::{
    db::{DatabaseSet, Merkleized as _},
    Application as StatefulApplication,
};
use commonware_runtime::{deterministic, Clock, Metrics, Runner as _, Storage, Supervisor as _};
use commonware_storage::mmr::Location;
use commonware_utils::{non_empty_range, range::NonEmptyRange, sync::AsyncRwLock};
use futures::future::BoxFuture;
use futures::lock::Mutex as AsyncMutex;
use nunchi_common::{
    empty_receipts_root, BlockExecutionOutput, Event, EventAttribute, EventError, EventSink,
    QmdbBackend, QmdbDatabaseSet, QmdbMerkleized, QmdbState, Runtime, RuntimeContext, StateStore,
};
use nunchi_dkg::Context;
use nunchi_mempool::{Mempool, MempoolHandle, PoolConfig, PoolTransaction};
use std::{
    convert::Infallible,
    sync::{Arc, Mutex as StdMutex},
};

use crate::{
    Application, Block, FinalizedEventReportError, FinalizedEventReporter,
    FinalizedEventReporterHandle, FinalizedEvents, SharedAppliedHeight, StateCommitment,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct TestTransaction {
    id: u8,
    fail: bool,
}

impl Write for TestTransaction {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.fail.write(buf);
    }
}

impl Read for TestTransaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            id: u8::read(buf)?,
            fail: bool::read(buf)?,
        })
    }
}

impl EncodeSize for TestTransaction {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.fail.encode_size()
    }
}

impl PoolTransaction for TestTransaction {
    type Digest = sha256::Digest;
    type NonceKey = u8;
    type VerifyError = Infallible;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&self.encode())
    }

    fn nonce_key(&self) -> Self::NonceKey {
        self.id
    }

    fn nonce(&self) -> u64 {
        self.id as u64
    }

    fn encoded_size(&self) -> usize {
        self.encode_size()
    }

    fn verify(&self) -> Result<(), Self::VerifyError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct TestRuntime;

#[derive(Debug, thiserror::Error)]
enum TestRuntimeError {
    #[error("invalid transaction")]
    Invalid,
    #[error("event error: {0}")]
    Event(#[from] EventError),
}

impl Runtime for TestRuntime {
    type Transaction = TestTransaction;
    type Error = TestRuntimeError;

    async fn validate<S, Events>(
        _state: &mut S,
        events: &mut Events,
        _context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
        Events: EventSink + Send,
    {
        emit_test_event(events, transaction.id)?;
        if transaction.fail {
            return Err(TestRuntimeError::Invalid);
        }
        Ok(())
    }

    async fn apply<S, Events>(
        _state: &mut S,
        events: &mut Events,
        _context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
        Events: EventSink + Send,
    {
        emit_test_event(events, transaction.id)?;
        if transaction.fail {
            return Err(TestRuntimeError::Invalid);
        }
        Ok(())
    }

    fn is_storage_error(_error: &Self::Error) -> bool {
        false
    }
}

fn emit_test_event(events: &mut impl EventSink, id: u8) -> Result<(), EventError> {
    events.emit(Event::new(
        Bytes::from_static(b"test"),
        Bytes::from_static(b"accepted"),
        1,
        vec![EventAttribute::new(
            Bytes::from_static(b"id"),
            Bytes::copy_from_slice(&[id]),
        )],
    ))
}

#[derive(Clone, Default)]
struct RecordingFinalizedEventReporter {
    batches: Arc<StdMutex<Vec<FinalizedEvents>>>,
}

impl RecordingFinalizedEventReporter {
    fn batches(&self) -> Vec<FinalizedEvents> {
        self.batches.lock().expect("reporter mutex").clone()
    }
}

impl FinalizedEventReporter for RecordingFinalizedEventReporter {
    fn report(
        &self,
        events: FinalizedEvents,
    ) -> BoxFuture<'static, Result<(), FinalizedEventReportError>> {
        let batches = self.batches.clone();
        Box::pin(async move {
            batches.lock().expect("reporter mutex").push(events);
            Ok(())
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct FailingFinalizedEventReporter;

impl FinalizedEventReporter for FailingFinalizedEventReporter {
    fn report(
        &self,
        _events: FinalizedEvents,
    ) -> BoxFuture<'static, Result<(), FinalizedEventReportError>> {
        Box::pin(async { Err(FinalizedEventReportError::new("report failed")) })
    }
}

async fn test_app(
    context: deterministic::Context,
) -> (
    Application<TestRuntime>,
    QmdbDatabaseSet<deterministic::Context>,
) {
    let (app, databases, _) =
        test_app_with_event_reporter(context, FinalizedEventReporterHandle::default()).await;
    (app, databases)
}

async fn test_app_with_event_reporter(
    context: deterministic::Context,
    finalized_event_reporter: FinalizedEventReporterHandle,
) -> (
    Application<TestRuntime>,
    QmdbDatabaseSet<deterministic::Context>,
    SharedAppliedHeight,
) {
    let (_mempool, submitter) = Mempool::new(PoolConfig::default());
    test_app_with_submitter(
        context,
        "chain-application",
        submitter,
        finalized_event_reporter,
    )
    .await
}

async fn test_app_with_submitter(
    context: deterministic::Context,
    partition: &str,
    submitter: MempoolHandle<TestTransaction>,
    finalized_event_reporter: FinalizedEventReporterHandle,
) -> (
    Application<TestRuntime>,
    QmdbDatabaseSet<deterministic::Context>,
    SharedAppliedHeight,
) {
    let config = QmdbState::<deterministic::Context>::config(&context, partition);
    let db = QmdbBackend::init(context, config)
        .await
        .expect("init state db");
    let databases: QmdbDatabaseSet<deterministic::Context> = Arc::new(AsyncRwLock::new(db));
    let genesis_target = databases.committed_targets().await;
    let genesis_state = StateCommitment {
        root: genesis_target.root,
        range: genesis_target.range,
    };
    let applied_height = Arc::new(AsyncMutex::new(Height::zero()));
    let app = Application::<TestRuntime>::new_with_event_reporter(
        submitter,
        16,
        applied_height.clone(),
        genesis_state,
        Sha256::hash(b"test-genesis"),
        finalized_event_reporter,
    );
    (app, databases, applied_height)
}

async fn test_app_with_partition(
    context: deterministic::Context,
    partition: &str,
    finalized_event_reporter: FinalizedEventReporterHandle,
) -> (
    Application<TestRuntime>,
    QmdbDatabaseSet<deterministic::Context>,
    SharedAppliedHeight,
) {
    let (_mempool, submitter) = Mempool::new(PoolConfig::default());
    test_app_with_submitter(context, partition, submitter, finalized_event_reporter).await
}

fn state_range<E: Storage + Clock + Metrics>(
    merkleized: &QmdbMerkleized<E>,
) -> NonEmptyRange<Location> {
    let bounds = merkleized.bounds();
    non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size))
}

async fn verified_test_block(
    app: &mut Application<TestRuntime>,
    context: deterministic::Context,
    databases: &QmdbDatabaseSet<deterministic::Context>,
) -> (Block<TestTransaction>, BlockExecutionOutput) {
    let parent =
        <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::genesis(app)
            .await;
    let tx = TestTransaction { id: 1, fail: false };
    let (transactions, merkleized, output) = app
        .build_valid_transactions(
            databases.new_batches().await,
            RuntimeContext::default(),
            vec![tx],
        )
        .await
        .expect("build transactions");
    let state_range = state_range(&merkleized);
    let consensus_context = Context {
        round: Round::new(Epoch::zero(), View::new(1)),
        leader: ed25519::PrivateKey::from_seed(1).public_key(),
        parent: (View::zero(), parent.digest()),
    };
    let block = Block::new(
        consensus_context,
        parent.digest(),
        parent.height.next(),
        parent.timestamp + 1,
        transactions,
        None,
        (),
        StateCommitment {
            root: merkleized.root(),
            range: state_range,
        },
        output.receipts_root,
    );

    let verified =
        <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::verify(
            app,
            (context.child("verify"), block.context.clone()),
            futures::stream::iter([block.clone(), parent]),
            databases.new_batches().await,
        )
        .await;
    assert!(verified.is_some());

    (block, output)
}

#[test]
fn genesis_block_uses_empty_receipts_root() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (app, _databases) = test_app(context).await;
        let block = app.genesis_block();

        assert!(block.transactions.is_empty());
        assert_eq!(block.receipts_root, empty_receipts_root());
    });
}

#[test]
fn proposed_block_includes_expected_receipts_root() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (mempool, mut submitter) = Mempool::new(PoolConfig::default());
        mempool.start(context.child("mempool"));
        let (mut app, databases, _) = test_app_with_submitter(
            context.child("setup"),
            "chain-application-propose",
            submitter.clone(),
            FinalizedEventReporterHandle::default(),
        )
        .await;
        let parent =
            <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::genesis(
                &mut app,
            )
            .await;
        let tx = TestTransaction { id: 0, fail: false };
        submitter.submit(tx.clone()).await.expect("submit tx");

        let (_transactions, _merkleized, expected_output) = app
            .build_valid_transactions(
                databases.new_batches().await,
                RuntimeContext {
                    epoch: Epoch::zero().get(),
                },
                vec![tx.clone()],
            )
            .await
            .expect("build expected output");
        let consensus_context = Context {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: ed25519::PrivateKey::from_seed(1).public_key(),
            parent: (View::zero(), parent.digest()),
        };

        let proposed =
            <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::propose(
                &mut app,
                (context.child("propose"), consensus_context),
                futures::stream::iter([parent]),
                databases.new_batches().await,
                &mut submitter,
            )
            .await
            .expect("propose block");
        let block = proposed.block;

        assert_eq!(block.transactions, vec![tx]);
        assert_eq!(block.receipts_root, expected_output.receipts_root);
        assert_eq!(
            app.cached_execution_output(block.digest())
                .await
                .expect("cached output")
                .receipts_root,
            expected_output.receipts_root
        );
    });
}

#[test]
fn build_valid_transactions_discards_failed_candidate_events() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (app, databases) = test_app(context).await;
        let batches = databases.new_batches().await;
        let accepted = TestTransaction { id: 2, fail: false };

        let (included, _merkleized, output) = app
            .build_valid_transactions(
                batches,
                RuntimeContext::default(),
                vec![TestTransaction { id: 1, fail: true }, accepted.clone()],
            )
            .await
            .expect("build transactions");

        assert_eq!(included, vec![accepted]);
        assert_eq!(output.transactions.len(), 1);
        assert_eq!(output.transactions[0].receipt.tx_index, 0);
        assert_eq!(output.transactions[0].events.len(), 1);
        assert_eq!(
            output.transactions[0].events[0].attributes[0].value,
            Bytes::from_static(&[2])
        );
    });
}

#[test]
fn verify_rejects_receipts_root_mismatch_and_caches_valid_output() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (mut app, databases) = test_app(context.child("setup")).await;
        let parent =
            <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::genesis(
                &mut app,
            )
            .await;
        let tx = TestTransaction { id: 1, fail: false };
        let (transactions, merkleized, output) = app
            .build_valid_transactions(
                databases.new_batches().await,
                RuntimeContext::default(),
                vec![tx],
            )
            .await
            .expect("build transactions");
        let state_range = state_range(&merkleized);
        let consensus_context = Context {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: ed25519::PrivateKey::from_seed(1).public_key(),
            parent: (View::zero(), parent.digest()),
        };
        let wrong = Block::new(
            consensus_context.clone(),
            parent.digest(),
            parent.height.next(),
            parent.timestamp + 1,
            transactions.clone(),
            None,
            (),
            StateCommitment {
                root: merkleized.root(),
                range: state_range.clone(),
            },
            empty_receipts_root(),
        );
        let block = Block::new(
            consensus_context,
            parent.digest(),
            parent.height.next(),
            parent.timestamp + 1,
            transactions,
            None,
            (),
            StateCommitment {
                root: merkleized.root(),
                range: state_range,
            },
            output.receipts_root,
        );

        let rejected =
            <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::verify(
                &mut app,
                (context.child("verify_wrong"), wrong.context.clone()),
                futures::stream::iter([wrong, parent.clone()]),
                databases.new_batches().await,
            )
            .await;
        assert!(rejected.is_none());

        let digest = block.digest();
        let verified =
            <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::verify(
                &mut app,
                (context.child("verify"), block.context.clone()),
                futures::stream::iter([block, parent]),
                databases.new_batches().await,
            )
            .await;
        assert!(verified.is_some());
        assert_eq!(
            app.cached_execution_output(digest)
                .await
                .expect("cached output")
                .receipts_root,
            output.receipts_root
        );
    });
}

#[test]
fn apply_reexecution_produces_same_receipts_root() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (mut producer, producer_databases, _) = test_app_with_partition(
            context.child("producer"),
            "chain-application-reexecute-producer",
            FinalizedEventReporterHandle::default(),
        )
        .await;
        let (block, output) =
            verified_test_block(&mut producer, context.child("build"), &producer_databases).await;
        let (mut reexecutor, reexecutor_databases, _) = test_app_with_partition(
            context.child("reexecutor"),
            "chain-application-reexecute-consumer",
            FinalizedEventReporterHandle::default(),
        )
        .await;

        <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::apply(
            &mut reexecutor,
            (context.child("apply"), block.context.clone()),
            &block,
            reexecutor_databases.new_batches().await,
        )
        .await;

        let cached = reexecutor
            .cached_execution_output(block.digest())
            .await
            .expect("cached output");
        assert_eq!(cached.receipts_root, output.receipts_root);
        assert_eq!(cached.transactions, output.transactions);
    });
}

#[test]
fn finalized_reports_cached_event_batch_once_after_finalization() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let reporter = RecordingFinalizedEventReporter::default();
        let (mut app, databases, _) = test_app_with_event_reporter(
            context.child("setup"),
            FinalizedEventReporterHandle::new(reporter.clone()),
        )
        .await;
        let (block, output) =
            verified_test_block(&mut app, context.child("build"), &databases).await;

        assert!(reporter.batches().is_empty());

        <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::finalized(
            &mut app,
            (context.child("finalized"), block.context.clone()),
            &block,
            &databases,
        )
        .await;

        let batches = reporter.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].height, block.height);
        assert_eq!(batches[0].block_digest, block.digest());
        assert_eq!(batches[0].block_timestamp, block.timestamp);
        assert_eq!(batches[0].receipts_root, block.receipts_root);
        assert_eq!(batches[0].transactions, output.transactions);
        assert!(app.cached_execution_output(block.digest()).await.is_none());
    });
}

#[test]
fn recovered_apply_preserves_finalized_event_output() {
    let ((block, output), checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let (mut app, databases, _) = test_app_with_partition(
                context.child("before_recovery"),
                "chain-application-recovery",
                FinalizedEventReporterHandle::default(),
            )
            .await;
            verified_test_block(&mut app, context.child("build"), &databases).await
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        let reporter = RecordingFinalizedEventReporter::default();
        let (mut app, databases, _) = test_app_with_partition(
            context.child("after_recovery"),
            "chain-application-recovery",
            FinalizedEventReporterHandle::new(reporter.clone()),
        )
        .await;

        <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::apply(
            &mut app,
            (context.child("apply"), block.context.clone()),
            &block,
            databases.new_batches().await,
        )
        .await;

        let cached = app
            .cached_execution_output(block.digest())
            .await
            .expect("cached output");
        assert_eq!(cached.receipts_root, output.receipts_root);
        assert_eq!(cached.transactions, output.transactions);

        <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::finalized(
            &mut app,
            (context.child("finalized"), block.context.clone()),
            &block,
            &databases,
        )
        .await;

        let batches = reporter.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].block_digest, block.digest());
        assert_eq!(batches[0].receipts_root, output.receipts_root);
        assert_eq!(batches[0].transactions, output.transactions);
    });
}

#[test]
fn finalized_reporter_failure_does_not_stop_finalization_bookkeeping() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (mut app, databases, applied_height) = test_app_with_event_reporter(
            context.child("setup"),
            FinalizedEventReporterHandle::new(FailingFinalizedEventReporter),
        )
        .await;
        let (block, _) = verified_test_block(&mut app, context.child("build"), &databases).await;

        <Application<TestRuntime> as StatefulApplication<deterministic::Context>>::finalized(
            &mut app,
            (context.child("finalized"), block.context.clone()),
            &block,
            &databases,
        )
        .await;

        assert_eq!(*applied_height.lock().await, block.height);
        assert!(app.cached_execution_output(block.digest()).await.is_none());
    });
}
