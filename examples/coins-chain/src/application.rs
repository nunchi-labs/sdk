use crate::execution::SharedAppliedHeight;
use crate::txpool::Submitter;
use crate::{Block, Context, Scheme, EPOCH};
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
use nunchi_coins::{Ledger, LedgerError, Transaction};
use nunchi_common::{QmdbBatch, QmdbDatabaseSet, QmdbMerkleized};
use nunchi_dkg as dkg;
use rand::Rng;
use std::time::{Duration, SystemTime};
use tracing::debug;

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"nunchi coins chain";

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// Root of an empty `any::unordered::variable` QMDB with an empty operation range.
fn empty_state_root() -> sha256::Digest {
    sha256::Digest::from([
        0xe2, 0x4b, 0xf5, 0x6a, 0xc8, 0xc9, 0xcd, 0x13, 0x2a, 0xb3, 0x93, 0x1b, 0x8c, 0x85, 0x79,
        0x5a, 0xf8, 0x61, 0x17, 0x44, 0xe8, 0x74, 0x20, 0x63, 0x30, 0x72, 0x22, 0xff, 0x9d, 0x7c,
        0xcd, 0x82,
    ])
}

/// The consensus application for the coins chain.
#[derive(Clone)]
pub struct Application {
    submitter: Submitter,
    max_block_transactions: usize,
    dkg: Option<dkg::Mailbox<Block>>,
    applied_height: SharedAppliedHeight,
}

impl Application {
    pub fn genesis() -> Block {
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
            empty_state_root(),
            non_empty_range!(Location::new(0), Location::new(1)),
        )
    }

    pub fn new(
        submitter: Submitter,
        max_block_transactions: usize,
        applied_height: SharedAppliedHeight,
    ) -> Self {
        Self {
            submitter,
            max_block_transactions,
            dkg: None,
            applied_height,
        }
    }

    pub fn with_dkg(
        submitter: Submitter,
        max_block_transactions: usize,
        dkg: dkg::Mailbox<Block>,
        applied_height: SharedAppliedHeight,
    ) -> Self {
        Self {
            submitter,
            max_block_transactions,
            dkg: Some(dkg),
            applied_height,
        }
    }

    async fn timestamp<E: Clock>(runtime_context: &E, parent: &Block) -> Option<u64> {
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
    ) -> Option<(Vec<Transaction>, QmdbMerkleized<E>)> {
        let mut batch = QmdbBatch::new(batches);
        let mut included = Vec::new();

        for transaction in candidates {
            if included.len() == self.max_block_transactions {
                break;
            }
            let mut ledger = Ledger::new(batch);
            match ledger.apply_transaction(&transaction).await {
                Ok(()) => {
                    batch = ledger.into_inner();
                    included.push(transaction);
                }
                Err(LedgerError::Storage(error)) => {
                    debug!(?error, "failed to read state while building block");
                    return None;
                }
                Err(error) => {
                    debug!(?error, "skipping non-executable txpool transaction");
                    batch = ledger.into_inner();
                }
            }
        }

        let merkleized = batch.merkleize().await.ok()?;
        Some((included, merkleized))
    }

    async fn execute_block<E: Storage + Clock + Metrics>(
        batches: <QmdbDatabaseSet<E> as DatabaseSet<E>>::Unmerkleized,
        transactions: &[Transaction],
    ) -> Option<QmdbMerkleized<E>> {
        let mut ledger = Ledger::new(QmdbBatch::new(batches));
        for transaction in transactions {
            ledger.apply_transaction(transaction).await.ok()?;
        }
        ledger.into_inner().merkleize().await.ok()
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
    type InputProvider = Submitter;

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        Target::new(block.state_root, block.state_range.clone())
    }

    async fn genesis(&mut self) -> Self::Block {
        Self::genesis()
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
        let timestamp = Self::timestamp(&runtime_context, &parent).await?;
        // TODO: Bound txpool memory and proposal-time revalidation through admission
        // control and eviction. Bounding this fetch while the pool remains unbounded
        // can starve valid transactions behind lower-sorting unexecutable entries.
        let candidates = input.pending(usize::MAX).await;
        let (transactions, merkleized) = self.build_valid_transactions(batches, candidates).await?;
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
            merkleized.root(),
            state_range,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::txpool::TxPool;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::sync::AsyncRwLock;
    use futures::lock::Mutex as AsyncMutex;
    use nunchi_coins::{
        multisig_account_id, AccountPolicy, CoinOperation, CoinSpec, MultisigPolicy, PrivateKey,
    };
    use nunchi_common::{QmdbBackend, QmdbState};
    use std::sync::Arc;

    fn spec() -> CoinSpec {
        CoinSpec::new("NCH", "Nunchi", 9, 1_000, None)
    }

    #[test]
    fn proposal_skips_unregistered_multisig() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (_, submitter) = TxPool::new();
            let config = QmdbState::<deterministic::Context>::config(&context, "application-test");
            let db = QmdbBackend::init(context, config)
                .await
                .expect("init state db");
            let databases: QmdbDatabaseSet<deterministic::Context> =
                Arc::new(AsyncRwLock::new(db));
            let applied_height = Arc::new(AsyncMutex::new(Height::zero()));
            let app = Application::new(submitter, 16, applied_height);

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
                .await
                .expect("proposal execution succeeds");
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
                .await
                .expect("proposal execution succeeds");
            assert_eq!(included, vec![tx]);
        });
    }
}
