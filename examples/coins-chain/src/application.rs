use crate::execution::SharedLedger;
use crate::txpool::Submitter;
use crate::{Block, Context, Scheme, EPOCH};
use commonware_actor::Feedback;
use commonware_consensus::{
    marshal::{ancestry::Ancestry, Update},
    types::{Height, Round, View},
    Application as ConsensusApplication, Heightable, Reporter,
};
use commonware_cryptography::{ed25519, sha256, Digest as _, Digestible, Hasher, Sha256, Signer};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_storage::Context as StorageContext;
use commonware_utils::{Acknowledgement, SystemTimeExt};
use futures::StreamExt;
use rand::Rng;
use std::time::{Duration, SystemTime};
use tracing::info;

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"nunchi coins chain";

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// The consensus application for the coins chain.
pub struct Application<E: StorageContext> {
    submitter: Submitter,
    ledger: SharedLedger<E>,
    max_block_transactions: usize,
}

impl<E: StorageContext> Clone for Application<E> {
    fn clone(&self) -> Self {
        Self {
            submitter: self.submitter.clone(),
            ledger: self.ledger.clone(),
            max_block_transactions: self.max_block_transactions,
        }
    }
}

impl<E: StorageContext> Application<E> {
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
        )
    }

    pub fn new(
        submitter: Submitter,
        ledger: SharedLedger<E>,
        max_block_transactions: usize,
    ) -> Self {
        Self {
            submitter,
            ledger,
            max_block_transactions,
        }
    }

    async fn authorization_valid(&self, tx: &nunchi_coins::Transaction) -> bool {
        let state = self.ledger.lock().await;
        state.ledger.validate_authorization(tx).await.is_ok()
    }
}

impl<E> ConsensusApplication<E> for Application<E>
where
    E: Rng + Spawner + Metrics + Clock + StorageContext,
{
    type SigningScheme = Scheme;
    type Context = Context;
    type Block = Block;

    async fn propose(
        &mut self,
        (runtime_context, context): (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
    ) -> Option<Self::Block> {
        let parent = ancestry.next().await?;

        // Advance the timestamp past the parent (mirrors the template's validity rule).
        let mut current = runtime_context.current().epoch_millis();
        if current <= parent.timestamp {
            current = parent
                .timestamp
                .checked_add(1)
                .expect("parent timestamp overflowed");
        }
        assert!(
            current <= MAX_BLOCK_TIMESTAMP_MS,
            "proposed timestamp exceeded maximum",
        );

        let pending = self.submitter.pending(self.max_block_transactions).await;
        let mut transactions = Vec::with_capacity(pending.len());
        for transaction in pending {
            if self.authorization_valid(&transaction).await {
                transactions.push(transaction);
            }
        }

        Some(Block::new(
            context,
            parent.digest(),
            parent.height.next(),
            current,
            transactions,
        ))
    }

    async fn verify(
        &mut self,
        (runtime_context, _): (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        let Some(block) = ancestry.next().await else {
            return false;
        };
        let Some(parent) = ancestry.next().await else {
            return false;
        };

        // Timestamp validity (waiting until the timestamp matures to tolerate skew).
        if block.timestamp <= parent.timestamp || block.timestamp > MAX_BLOCK_TIMESTAMP_MS {
            return false;
        }

        if block.transactions.len() > self.max_block_transactions {
            return false;
        }

        // Every carried transaction must bear a valid signature from its declared signer.
        // Application-level validity (nonce, balances, token existence) is enforced at execution.
        for tx in &block.transactions {
            if tx.verify().is_err() || !self.authorization_valid(tx).await {
                return false;
            }
        }

        let deadline = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(block.timestamp))
            .expect("block timestamp exceeded maximum");
        runtime_context.sleep_until(deadline).await;

        true
    }
}

impl<E: StorageContext> Reporter for Application<E> {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // The executor (a separate marshal reporter) performs execution; this application only
        // observes and acknowledges its own copy of the finalized-block stream.
        if let Update::Block(block, ack) = activity {
            info!(
                height = %block.height(),
                digest = ?block.digest(),
                transactions = block.transactions.len(),
                "finalized block"
            );
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ChainState;
    use crate::txpool::TxPool;
    use commonware_consensus::types::Height;
    use commonware_runtime::{deterministic, Runner as _};
    use futures::lock::Mutex as AsyncMutex;
    use nunchi_coins::{
        AccountPolicy, CoinOperation, CoinSpec, Ledger, MultisigPolicy, PrivateKey, Transaction,
    };
    use nunchi_common::QmdbState;
    use std::sync::Arc;

    fn spec() -> CoinSpec {
        CoinSpec::new("NCH", "Nunchi", 9, 1_000, None)
    }

    #[test]
    fn authorization_filter_rejects_unregistered_multisig() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (_, submitter) = TxPool::new();
            let db = QmdbState::init(context, "application-test")
                .await
                .expect("init state db");
            let ledger = Ledger::new(db);
            let shared = Arc::new(AsyncMutex::new(ChainState {
                ledger,
                applied_height: Height::zero(),
            }));
            let app = Application::new(submitter, shared.clone(), 16);

            let alice_a = PrivateKey::ed25519_from_seed(1);
            let alice_b = PrivateKey::secp256r1_from_seed(2);
            let account_id = PrivateKey::ed25519_from_seed(99).public_key();
            let policy =
                MultisigPolicy::new(2, vec![alice_a.public_key(), alice_b.public_key()]).unwrap();
            let tx = Transaction::sign_multisig(
                account_id.clone(),
                policy.clone(),
                &[&alice_a, &alice_b],
                0,
                CoinOperation::CreateToken { spec: spec() },
            );

            assert!(!app.authorization_valid(&tx).await);

            shared
                .lock()
                .await
                .ledger
                .register_account_policy(account_id, AccountPolicy::Multisig(policy))
                .await
                .expect("register policy");

            assert!(app.authorization_valid(&tx).await);
        });
    }
}
