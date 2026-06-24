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
use futures::lock::Mutex as AsyncMutex;
use nunchi_common::{
    empty_receipts_root, Event, EventAttribute, EventError, EventSink, QmdbBackend,
    QmdbDatabaseSet, QmdbMerkleized, QmdbState, Runtime, RuntimeContext, StateStore,
};
use nunchi_dkg::Context;
use nunchi_mempool::{Mempool, PoolConfig, PoolTransaction};
use std::{convert::Infallible, sync::Arc};

use crate::{Application, Block, StateCommitment};

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

async fn test_app(
    context: deterministic::Context,
) -> (
    Application<TestRuntime>,
    QmdbDatabaseSet<deterministic::Context>,
) {
    let (_mempool, submitter) = Mempool::new(PoolConfig::default());
    let config = QmdbState::<deterministic::Context>::config(&context, "chain-application");
    let db = QmdbBackend::init(context, config)
        .await
        .expect("init state db");
    let databases: QmdbDatabaseSet<deterministic::Context> = Arc::new(AsyncRwLock::new(db));
    let genesis_target = databases.committed_targets().await;
    let genesis_state = StateCommitment {
        root: genesis_target.root,
        range: genesis_target.range,
    };
    let app = Application::<TestRuntime>::new(
        submitter,
        16,
        Arc::new(AsyncMutex::new(Height::zero())),
        genesis_state,
        Sha256::hash(b"test-genesis"),
    );
    (app, databases)
}

fn state_range<E: Storage + Clock + Metrics>(
    merkleized: &QmdbMerkleized<E>,
) -> NonEmptyRange<Location> {
    let bounds = merkleized.bounds();
    non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size))
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
