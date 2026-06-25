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
use nunchi_common::{Overlay, QmdbBatch, QmdbDatabaseSet, QmdbMerkleized, Runtime, RuntimeContext};
use nunchi_dkg::{Context, Scheme};
use nunchi_mempool::{MempoolHandle, PoolTransaction};
use rand::Rng;
use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{debug, error};

use crate::{
    Block, ConsensusExtension, DkgMailbox, EventConsumer, NoConsensusExtension, NoopEventConsumer,
    StateCommitment, TransactionEventContext,
};

/// The height of the last finalized block applied to a node's ledger.
pub type SharedAppliedHeight = Arc<AsyncMutex<Height>>;

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// Configuration for an application with explicit consensus and event reporting.
pub struct ApplicationConfig<Tx, Ext, Events>
where
    Tx: PoolTransaction,
    Ext: ConsensusExtension + Sync,
    Events: EventConsumer,
{
    pub submitter: MempoolHandle<Tx>,
    pub max_block_transactions: usize,
    pub consensus: Ext,
    pub events: Events,
    pub applied_height: SharedAppliedHeight,
    pub genesis_state: StateCommitment,
    pub genesis_payload: sha256::Digest,
}

/// The stateful consensus application for a generated runtime.
#[derive(Clone)]
pub struct Application<R, Ext = NoConsensusExtension, Events = NoopEventConsumer>
where
    R: Runtime,
    R::Transaction: PoolTransaction,
    Ext: ConsensusExtension + Sync,
    Events: EventConsumer,
{
    submitter: MempoolHandle<R::Transaction>,
    max_block_transactions: usize,
    dkg: Option<DkgMailbox<R::Transaction, Ext>>,
    consensus: Ext,
    events: Events,
    applied_height: SharedAppliedHeight,
    genesis_state: StateCommitment,
    genesis_payload: sha256::Digest,
    _runtime: PhantomData<R>,
}

impl<R, Ext, Events> Application<R, Ext, Events>
where
    R: Runtime,
    R::Transaction: PoolTransaction<Digest = sha256::Digest>,
    Ext: ConsensusExtension + Sync,
    Events: EventConsumer,
{
    /// The genesis block, committing to `genesis_state`.
    pub fn genesis_block(&self) -> Block<R::Transaction, Ext> {
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
            Ext::genesis_payload(),
            self.genesis_state.clone(),
        )
    }

    pub fn with_consensus_and_events(
        config: ApplicationConfig<R::Transaction, Ext, Events>,
        dkg: Option<DkgMailbox<R::Transaction, Ext>>,
    ) -> Self {
        let ApplicationConfig {
            submitter,
            max_block_transactions,
            consensus,
            events,
            applied_height,
            genesis_state,
            genesis_payload,
        } = config;

        Self {
            submitter,
            max_block_transactions,
            dkg,
            consensus,
            events,
            applied_height,
            genesis_state,
            genesis_payload,
            _runtime: PhantomData,
        }
    }

    fn timestamp<E: Clock>(
        runtime_context: &E,
        parent: &Block<R::Transaction, Ext>,
    ) -> Option<u64> {
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
        context: RuntimeContext,
        candidates: Vec<R::Transaction>,
    ) -> Option<(Vec<R::Transaction>, QmdbMerkleized<E>)> {
        let mut batch = QmdbBatch::new(batches);
        let mut included = Vec::new();

        for transaction in candidates {
            if included.len() == self.max_block_transactions {
                break;
            }
            let mut overlay = Overlay::new(&mut batch);
            match R::validate(&mut overlay, context, &transaction).await {
                Ok(()) => {
                    overlay.commit();
                    included.push(transaction);
                }
                Err(error) if R::is_storage_error(&error) => {
                    error!(?error, "storage failure while building block");
                    return None;
                }
                Err(error) => {
                    debug!(?error, "skipping non-executable txpool transaction");
                }
            }
        }

        let merkleized = match batch.merkleize().await {
            Ok(merkleized) => merkleized,
            Err(error) => {
                error!(?error, "merkleization failed while building block");
                return None;
            }
        };
        Some((included, merkleized))
    }

    async fn execute_block<E, EventHandler>(
        batches: <QmdbDatabaseSet<E> as DatabaseSet<E>>::Unmerkleized,
        context: RuntimeContext,
        transactions: &[R::Transaction],
        events: &EventHandler,
    ) -> Option<QmdbMerkleized<E>>
    where
        E: Storage + Clock + Metrics,
        EventHandler: EventConsumer,
    {
        events.begin_block(context).await;
        let mut batch = QmdbBatch::new(batches);
        for (tx_index, transaction) in transactions.iter().enumerate() {
            let transaction_events = TransactionEventContext {
                tx_index: u32::try_from(tx_index).expect("block contains more than u32::MAX txs"),
                tx_digest: transaction.digest(),
            };
            let mut sink = events.transaction_sink(context, transaction_events);
            match R::apply(&mut batch, context, transaction, &mut sink).await {
                Ok(()) => {
                    events.transaction_applied(sink).await;
                }
                Err(error) if R::is_storage_error(&error) => {
                    panic!("storage failure while executing block: {error}");
                }
                Err(_) => {
                    if let Some(digest) = context.block_digest {
                        events.discard_block(digest).await;
                    }
                    return None;
                }
            }
        }
        Some(
            batch
                .merkleize()
                .await
                .expect("merkleization failed while executing block"),
        )
    }

    fn proposal_runtime_context(epoch: u64, height: Height, timestamp_ms: u64) -> RuntimeContext {
        RuntimeContext {
            epoch,
            height: height.get(),
            timestamp_ms,
            block_digest: None,
        }
    }

    fn block_runtime_context(block: &Block<R::Transaction, Ext>) -> RuntimeContext {
        RuntimeContext {
            epoch: block.context.round.epoch().get(),
            height: block.height.get(),
            timestamp_ms: block.timestamp,
            block_digest: Some(block.digest()),
        }
    }

    fn state_range<E: Storage + Clock + Metrics>(
        merkleized: &QmdbMerkleized<E>,
    ) -> NonEmptyRange<Location> {
        let bounds = merkleized.bounds();
        non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size))
    }

    async fn verify_timestamp<E: Clock>(
        runtime_context: &E,
        block: &Block<R::Transaction, Ext>,
        parent: &Block<R::Transaction, Ext>,
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

impl<R, Ext> Application<R, Ext, NoopEventConsumer>
where
    R: Runtime,
    R::Transaction: PoolTransaction<Digest = sha256::Digest>,
    Ext: ConsensusExtension + Sync,
{
    pub fn with_consensus(
        submitter: MempoolHandle<R::Transaction>,
        max_block_transactions: usize,
        consensus: Ext,
        dkg: Option<DkgMailbox<R::Transaction, Ext>>,
        applied_height: SharedAppliedHeight,
        genesis_state: StateCommitment,
        genesis_payload: sha256::Digest,
    ) -> Self {
        Self::with_consensus_and_events(
            ApplicationConfig {
                submitter,
                max_block_transactions,
                consensus,
                events: NoopEventConsumer,
                applied_height,
                genesis_state,
                genesis_payload,
            },
            dkg,
        )
    }
}

impl<R> Application<R>
where
    R: Runtime,
    R::Transaction: PoolTransaction<Digest = sha256::Digest>,
{
    pub fn new(
        submitter: MempoolHandle<R::Transaction>,
        max_block_transactions: usize,
        applied_height: SharedAppliedHeight,
        genesis_state: StateCommitment,
        genesis_payload: sha256::Digest,
    ) -> Self {
        Self::with_consensus(
            submitter,
            max_block_transactions,
            NoConsensusExtension,
            None,
            applied_height,
            genesis_state,
            genesis_payload,
        )
    }
}

impl<R, Events> Application<R, NoConsensusExtension, Events>
where
    R: Runtime,
    R::Transaction: PoolTransaction<Digest = sha256::Digest>,
    Events: EventConsumer,
{
    pub fn new_with_events(
        submitter: MempoolHandle<R::Transaction>,
        max_block_transactions: usize,
        events: Events,
        applied_height: SharedAppliedHeight,
        genesis_state: StateCommitment,
        genesis_payload: sha256::Digest,
    ) -> Self {
        Self::with_consensus_and_events(
            ApplicationConfig {
                submitter,
                max_block_transactions,
                consensus: NoConsensusExtension,
                events,
                applied_height,
                genesis_state,
                genesis_payload,
            },
            None,
        )
    }
}

impl<R> Application<R>
where
    R: Runtime,
    R::Transaction: PoolTransaction<Digest = sha256::Digest>,
    Block<R::Transaction>: nunchi_dkg::ReshareBlock,
{
    pub fn with_dkg(
        submitter: MempoolHandle<R::Transaction>,
        max_block_transactions: usize,
        dkg: DkgMailbox<R::Transaction>,
        applied_height: SharedAppliedHeight,
        genesis_state: StateCommitment,
        genesis_payload: sha256::Digest,
    ) -> Self {
        Self::with_consensus(
            submitter,
            max_block_transactions,
            NoConsensusExtension,
            Some(dkg),
            applied_height,
            genesis_state,
            genesis_payload,
        )
    }
}

impl<R, Events> Application<R, NoConsensusExtension, Events>
where
    R: Runtime,
    R::Transaction: PoolTransaction<Digest = sha256::Digest>,
    Block<R::Transaction>: nunchi_dkg::ReshareBlock,
    Events: EventConsumer,
{
    pub fn with_dkg_and_events(
        submitter: MempoolHandle<R::Transaction>,
        max_block_transactions: usize,
        dkg: DkgMailbox<R::Transaction>,
        events: Events,
        applied_height: SharedAppliedHeight,
        genesis_state: StateCommitment,
        genesis_payload: sha256::Digest,
    ) -> Self {
        Self::with_consensus_and_events(
            ApplicationConfig {
                submitter,
                max_block_transactions,
                consensus: NoConsensusExtension,
                events,
                applied_height,
                genesis_state,
                genesis_payload,
            },
            Some(dkg),
        )
    }
}

impl<E, R, Ext, Events> StatefulApplication<E> for Application<R, Ext, Events>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    R: Runtime + Clone + Send + Sync + 'static,
    R::Transaction: PoolTransaction<Digest = sha256::Digest>,
    Ext: ConsensusExtension + Sync,
    Events: EventConsumer,
{
    type SigningScheme = Scheme;
    type Context = Context;
    type Block = Block<R::Transaction, Ext>;
    type Databases = QmdbDatabaseSet<E>;
    type InputProvider = MempoolHandle<R::Transaction>;

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
        let execution_context = Self::proposal_runtime_context(
            context.round.epoch().get(),
            parent.height.next(),
            timestamp,
        );
        let (transactions, merkleized) = self
            .build_valid_transactions(batches, execution_context, candidates)
            .await?;
        let state_range = Self::state_range(&merkleized);
        let reshare_log = match &mut self.dkg {
            Some(dkg) => dkg.act().await,
            None => None,
        };
        let extension = self.consensus.propose().await;
        let block = Block::new(
            context,
            parent.digest(),
            parent.height.next(),
            timestamp,
            transactions,
            reshare_log,
            extension,
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

        if block
            .transactions
            .iter()
            .any(|tx| PoolTransaction::verify(tx).is_err())
        {
            return None;
        }

        if !self.consensus.verify_payload(&block.extension).await {
            return None;
        }

        let execution_context = Self::block_runtime_context(&block);
        let merkleized = Self::execute_block(
            batches,
            execution_context,
            &block.transactions,
            &NoopEventConsumer,
        )
        .await?;
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
        let execution_context = Self::block_runtime_context(block);
        let merkleized = Self::execute_block(
            batches,
            execution_context,
            &block.transactions,
            &self.events,
        )
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
        let applied = block
            .transactions
            .iter()
            .map(PoolTransaction::digest)
            .collect();
        let mut lane_nonces: HashMap<<R::Transaction as PoolTransaction>::NonceKey, u64> =
            HashMap::new();
        for transaction in &block.transactions {
            let next = transaction.nonce() + 1;
            lane_nonces
                .entry(transaction.nonce_key())
                .and_modify(|nonce| *nonce = (*nonce).max(next))
                .or_insert(next);
        }
        debug!(
            height = %block.height(),
            digest = ?block.digest(),
            transactions = block.transactions.len(),
            "finalized block"
        );
        *self.applied_height.lock().await = block.height();
        self.submitter.finalized(
            applied,
            lane_nonces.into_iter().collect(),
            block.height().get(),
        );
        self.events
            .finalized(Self::block_runtime_context(block))
            .await;
    }
}
