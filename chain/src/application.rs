use commonware_consensus::{
    types::{Epoch, Height, Round, View},
    Heightable,
};
use commonware_cryptography::{ed25519, sha256, Digest as _, Digestible, Signer};
use commonware_glue::stateful::{
    db::{DatabaseSet, Merkleized as _},
    Application as StatefulApplication, Proposed,
};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::{mmr::Location, qmdb::sync::Target};
use commonware_utils::{non_empty_range, range::NonEmptyRange, SystemTimeExt};
use futures::{lock::Mutex as AsyncMutex, StreamExt};
use nunchi_common::{
    Overlay, PoolTransaction, QmdbBatch, QmdbDatabaseSet, QmdbMerkleized, Runtime,
};
use nunchi_dkg::{self as dkg, Context, Scheme};
use rand::Rng;
use std::{
    marker::PhantomData,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::debug;

use crate::{Block, RuntimeSubmitter, StateCommitment};

/// The height of the last finalized block applied to a node's ledger.
pub type SharedAppliedHeight = Arc<AsyncMutex<Height>>;

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// The stateful consensus application for a generated runtime.
#[derive(Clone)]
pub struct Application<R: Runtime> {
    submitter: RuntimeSubmitter<R>,
    max_block_transactions: usize,
    dkg: Option<dkg::Mailbox<Block<R::Transaction>>>,
    applied_height: SharedAppliedHeight,
    genesis_state: StateCommitment,
    genesis_payload: sha256::Digest,
    _runtime: PhantomData<R>,
}

impl<R: Runtime> Application<R> {
    /// The genesis block, committing to `genesis_state`.
    pub fn genesis_block(&self) -> Block<R::Transaction> {
        let genesis_context = Context {
            round: Round::new(Epoch::zero(), View::zero()),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (View::zero(), sha256::Digest::EMPTY),
        };
        Block::new(
            genesis_context,
            self.genesis_payload,
            Height::zero(),
            0,
            Vec::new(),
            None,
            self.genesis_state.clone(),
        )
    }

    pub fn new(
        submitter: RuntimeSubmitter<R>,
        max_block_transactions: usize,
        applied_height: SharedAppliedHeight,
        genesis_state: StateCommitment,
        genesis_payload: sha256::Digest,
    ) -> Self {
        Self {
            submitter,
            max_block_transactions,
            dkg: None,
            applied_height,
            genesis_state,
            genesis_payload,
            _runtime: PhantomData,
        }
    }

    pub fn with_dkg(
        submitter: RuntimeSubmitter<R>,
        max_block_transactions: usize,
        dkg: dkg::Mailbox<Block<R::Transaction>>,
        applied_height: SharedAppliedHeight,
        genesis_state: StateCommitment,
        genesis_payload: sha256::Digest,
    ) -> Self {
        Self {
            submitter,
            max_block_transactions,
            dkg: Some(dkg),
            applied_height,
            genesis_state,
            genesis_payload,
            _runtime: PhantomData,
        }
    }

    fn timestamp<E: Clock>(runtime_context: &E, parent: &Block<R::Transaction>) -> Option<u64> {
        let mut current = runtime_context.current().epoch_millis();
        if current <= parent.timestamp {
            current = parent.timestamp.checked_add(1)?;
        }
        (current <= MAX_BLOCK_TIMESTAMP_MS).then_some(current)
    }

    /// Execute txpool candidates in order, including the first `max_block_transactions` that
    /// apply cleanly against the parent state.
    pub async fn build_valid_transactions<E: Storage + Clock + Metrics>(
        &self,
        batches: <QmdbDatabaseSet<E> as DatabaseSet<E>>::Unmerkleized,
        candidates: Vec<R::Transaction>,
    ) -> (Vec<R::Transaction>, QmdbMerkleized<E>) {
        let mut batch = QmdbBatch::new(batches);
        let mut included = Vec::new();

        for transaction in candidates {
            if included.len() == self.max_block_transactions {
                break;
            }
            let mut overlay = Overlay::new(&mut batch);
            match R::validate(&mut overlay, &transaction).await {
                Ok(()) => {
                    overlay.commit();
                    included.push(transaction);
                }
                Err(error) if R::is_storage_error(&error) => {
                    panic!("storage failure while building block: {error}");
                }
                Err(error) => {
                    debug!(?error, "skipping non-executable txpool transaction");
                }
            }
        }

        let merkleized = batch
            .merkleize()
            .await
            .expect("merkleization failed while building block");
        (included, merkleized)
    }

    async fn execute_block<E: Storage + Clock + Metrics>(
        batches: <QmdbDatabaseSet<E> as DatabaseSet<E>>::Unmerkleized,
        transactions: &[R::Transaction],
    ) -> Option<QmdbMerkleized<E>> {
        let mut batch = QmdbBatch::new(batches);
        for transaction in transactions {
            match R::apply(&mut batch, transaction).await {
                Ok(()) => {}
                Err(error) if R::is_storage_error(&error) => {
                    panic!("storage failure while executing block: {error}");
                }
                Err(_) => return None,
            }
        }
        Some(
            batch
                .merkleize()
                .await
                .expect("merkleization failed while executing block"),
        )
    }

    fn state_range<E: Storage + Clock + Metrics>(
        merkleized: &QmdbMerkleized<E>,
    ) -> NonEmptyRange<Location> {
        let bounds = merkleized.bounds();
        non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size))
    }

    async fn verify_timestamp<E: Clock>(
        runtime_context: &E,
        block: &Block<R::Transaction>,
        parent: &Block<R::Transaction>,
    ) -> bool {
        if block.timestamp <= parent.timestamp || block.timestamp > MAX_BLOCK_TIMESTAMP_MS {
            return false;
        }

        let deadline = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(block.timestamp))
            .expect("block timestamp exceeded maximum");
        runtime_context.sleep_until(deadline).await;
        true
    }
}

impl<E, R> StatefulApplication<E> for Application<R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    R: Runtime + Clone + Send + Sync + 'static,
{
    type SigningScheme = Scheme;
    type Context = Context;
    type Block = Block<R::Transaction>;
    type Databases = QmdbDatabaseSet<E>;
    type InputProvider = RuntimeSubmitter<R>;

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        Target::new(block.state_root, block.state_range.clone())
    }

    async fn genesis(&mut self) -> Self::Block {
        self.genesis_block()
    }

    async fn propose(
        &mut self,
        (runtime_context, context): (E, Self::Context),
        ancestry: impl futures::Stream<Item = Self::Block> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, E>> {
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let timestamp = Self::timestamp(&runtime_context, &parent)?;
        let candidates = input.pending(usize::MAX).await;
        let (transactions, merkleized) = self.build_valid_transactions(batches, candidates).await;
        let state_range = Self::state_range(&merkleized);
        let reshare_log = match &mut self.dkg {
            Some(dkg) => dkg.act().await,
            None => None,
        };
        let block = Block::new(
            context,
            parent.digest(),
            parent.height.next(),
            timestamp,
            transactions,
            reshare_log,
            StateCommitment {
                root: merkleized.root(),
                range: state_range,
            },
        );
        Some(Proposed { block, merkleized })
    }

    async fn verify(
        &mut self,
        (runtime_context, _): (E, Self::Context),
        ancestry: impl futures::Stream<Item = Self::Block> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let mut ancestry = Box::pin(ancestry);
        let block = ancestry.next().await?;
        let parent = ancestry.next().await?;

        if !Self::verify_timestamp(&runtime_context, &block, &parent).await {
            return None;
        }

        if block.transactions.len() > self.max_block_transactions {
            return None;
        }

        if block.transactions.iter().any(|tx| tx.verify().is_err()) {
            return None;
        }

        let merkleized = Self::execute_block(batches, &block.transactions).await?;
        let state_range = Self::state_range(&merkleized);
        if merkleized.root() != block.state_root || state_range != block.state_range {
            return None;
        }
        Some(merkleized)
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        let merkleized = Self::execute_block(batches, &block.transactions)
            .await
            .expect("certified block failed deterministic execution");
        let state_range = Self::state_range(&merkleized);
        assert_eq!(
            merkleized.root(),
            block.state_root,
            "certified block state root mismatch"
        );
        assert_eq!(
            state_range, block.state_range,
            "certified block state range mismatch"
        );
        merkleized
    }

    async fn finalized(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        _databases: &Self::Databases,
    ) {
        let applied = block.transactions.iter().map(|tx| tx.digest()).collect();
        debug!(
            height = %block.height(),
            digest = ?block.digest(),
            transactions = block.transactions.len(),
            has_reshare_log = block.reshare_log.is_some(),
            "finalized block"
        );
        *self.applied_height.lock().await = block.height();
        self.submitter.prune(applied);
    }
}
