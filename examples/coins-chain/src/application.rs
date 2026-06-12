use crate::execution::SharedAppliedHeight;
use crate::{Block, Context, Scheme, StateCommitment, EPOCH};
use commonware_consensus::{
    types::{Height, Round, View},
    Heightable,
};
use commonware_cryptography::{ed25519, sha256, Digest as _, Digestible, Hasher, Sha256, Signer};
use commonware_glue::stateful::{
    db::{DatabaseSet, Merkleized as _},
    Application as StatefulApplication, Proposed,
};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::{mmr::Location, qmdb::sync::Target};
use commonware_utils::{non_empty_range, range::NonEmptyRange, SystemTimeExt};
use futures::StreamExt;
use nunchi_coins::{Address, Ledger, LedgerError, Transaction};
use nunchi_common::{Overlay, QmdbBatch, QmdbDatabaseSet, QmdbMerkleized};
use nunchi_dkg as dkg;
use nunchi_mempool::MempoolHandle;
use rand::Rng;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tracing::debug;

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"nunchi coins chain";

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// The consensus application for the coins chain.
#[derive(Clone)]
pub struct Application {
    submitter: MempoolHandle<Transaction>,
    max_block_transactions: usize,
    dkg: Option<dkg::Mailbox<Block>>,
    applied_height: SharedAppliedHeight,
    genesis_state: StateCommitment,
}

impl Application {
    /// The genesis block, committing to `genesis_state` (the root of an empty state database,
    /// derived at startup by [`Engine::new`](crate::engine::Engine)).
    pub fn genesis_block(&self) -> Block {
        let genesis_context = Context {
            round: Round::new(EPOCH, View::zero()),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (View::zero(), sha256::Digest::EMPTY),
        };
        Block::new(
            genesis_context,
            Sha256::hash(GENESIS),
            Height::zero(),
            0,
            Vec::new(),
            None,
            self.genesis_state.clone(),
        )
    }

    pub fn new(
        submitter: MempoolHandle<Transaction>,
        max_block_transactions: usize,
        applied_height: SharedAppliedHeight,
        genesis_state: StateCommitment,
    ) -> Self {
        Self {
            submitter,
            max_block_transactions,
            dkg: None,
            applied_height,
            genesis_state,
        }
    }

    pub fn with_dkg(
        submitter: MempoolHandle<Transaction>,
        max_block_transactions: usize,
        dkg: dkg::Mailbox<Block>,
        applied_height: SharedAppliedHeight,
        genesis_state: StateCommitment,
    ) -> Self {
        Self {
            submitter,
            max_block_transactions,
            dkg: Some(dkg),
            applied_height,
            genesis_state,
        }
    }

    fn timestamp<E: Clock>(runtime_context: &E, parent: &Block) -> Option<u64> {
        let mut current = runtime_context.current().epoch_millis();
        if current <= parent.timestamp {
            current = parent.timestamp.checked_add(1)?;
        }
        (current <= MAX_BLOCK_TIMESTAMP_MS).then_some(current)
    }

    /// Execute txpool candidates in order, including the first `max_block_transactions` that
    /// apply cleanly (signature, authorization, nonce, balances) against the parent state.
    async fn build_valid_transactions<E: Storage + Clock + Metrics>(
        &self,
        batches: <QmdbDatabaseSet<E> as DatabaseSet<E>>::Unmerkleized,
        candidates: Vec<Transaction>,
    ) -> (Vec<Transaction>, QmdbMerkleized<E>) {
        let mut batch = QmdbBatch::new(batches);
        let mut included = Vec::new();

        for transaction in candidates {
            if included.len() == self.max_block_transactions {
                break;
            }
            // Each candidate executes against an overlay so a transaction that fails partway
            // through leaves no writes behind: the proposed state root must commit only to the
            // transactions actually included in the block.
            let mut ledger = Ledger::new(Overlay::new(&mut batch));
            match ledger.apply_transaction(&transaction).await {
                Ok(()) => {
                    ledger.into_inner().commit();
                    included.push(transaction);
                }
                Err(error @ LedgerError::Storage(_)) => {
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

    /// Execute a block's transactions against fresh batches.
    ///
    /// Returns `None` only when a transaction is deterministically inapplicable. Storage
    /// failures panic: they indicate local corruption, not block invalidity, and `verify`
    /// must never report a block permanently invalid because of a local fault.
    async fn execute_block<E: Storage + Clock + Metrics>(
        batches: <QmdbDatabaseSet<E> as DatabaseSet<E>>::Unmerkleized,
        transactions: &[Transaction],
    ) -> Option<QmdbMerkleized<E>> {
        let mut ledger = Ledger::new(QmdbBatch::new(batches));
        for transaction in transactions {
            match ledger.apply_transaction(transaction).await {
                Ok(()) => {}
                Err(error @ LedgerError::Storage(_)) => {
                    panic!("storage failure while executing block: {error}");
                }
                Err(_) => return None,
            }
        }
        Some(
            ledger
                .into_inner()
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
        block: &Block,
        parent: &Block,
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

impl<E> StatefulApplication<E> for Application
where
    E: Rng + Spawner + Metrics + Clock + Storage,
{
    type SigningScheme = Scheme;
    type Context = Context;
    type Block = Block;
    type Databases = QmdbDatabaseSet<E>;
    type InputProvider = MempoolHandle<Transaction>;

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
        // The pool returns gap-free, (account, nonce)-ordered candidates; the overlay
        // execution below remains the authoritative validity gate (balances etc.).
        let candidates = input.pending(self.max_block_transactions).await;
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
        let applied = block.transactions.iter().map(Transaction::digest).collect();
        let mut account_nonces: HashMap<Address, u64> = HashMap::new();
        // enforce sequential nonces
        for transaction in &block.transactions {
            let next = transaction.payload.nonce + 1;
            account_nonces
                .entry(transaction.account_id.clone())
                .and_modify(|nonce| *nonce = (*nonce).max(next))
                .or_insert(next);
        }
        debug!(
            height = %block.height(),
            digest = ?block.digest(),
            transactions = block.transactions.len(),
            has_reshare_log = block.reshare_log.is_some(),
            "finalized block"
        );
        *self.applied_height.lock().await = block.height();
        self.submitter.finalized(
            applied,
            account_nonces.into_iter().collect(),
            block.height().get(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::sync::AsyncRwLock;
    use futures::lock::Mutex as AsyncMutex;
    use nunchi_coins::{
        multisig_account_id, AccountPolicy, CoinOperation, CoinSpec, MultisigPolicy, PrivateKey,
    };
    use nunchi_common::{QmdbBackend, QmdbState};
    use nunchi_mempool::{Mempool, PoolConfig};
    use std::sync::Arc;

    fn spec() -> CoinSpec {
        CoinSpec::new("NCH", "Nunchi", 9, 1_000, None)
    }

    #[test]
    fn proposal_skips_unregistered_multisig() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (_mempool, submitter) = Mempool::new(PoolConfig::default());
            let config = QmdbState::<deterministic::Context>::config(&context, "application-test");
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
            let app = Application::new(submitter, 16, applied_height, genesis_state);

            let alice_a = PrivateKey::ed25519_from_seed(1);
            let alice_b = PrivateKey::secp256r1_from_seed(2);
            let policy =
                MultisigPolicy::new(2, vec![alice_a.public_key(), alice_b.public_key()]).unwrap();
            let account_id = multisig_account_id(&policy);
            let tx = Transaction::sign_multisig(
                account_id.clone(),
                policy.clone(),
                &[&alice_a, &alice_b],
                0,
                CoinOperation::CreateToken { spec: spec() },
            );

            // The multisig policy is unregistered, so the candidate is excluded at proposal time.
            let batches = databases.new_batches().await;
            let (included, _) = app
                .build_valid_transactions(batches, vec![tx.clone()])
                .await;
            assert!(included.is_empty());

            // Register the policy and finalize it into committed state.
            let batches = databases.new_batches().await;
            let mut ledger = Ledger::new(QmdbBatch::new(batches));
            ledger
                .register_account_policy(account_id, AccountPolicy::Multisig(policy))
                .await
                .expect("register policy");
            let merkleized = ledger
                .into_inner()
                .merkleize()
                .await
                .expect("merkleize policy registration");
            databases.finalize(merkleized).await;

            let batches = databases.new_batches().await;
            let (included, _) = app
                .build_valid_transactions(batches, vec![tx.clone()])
                .await;
            assert_eq!(included, vec![tx]);
        });
    }
}
