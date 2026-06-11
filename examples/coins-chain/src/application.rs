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
use nunchi_dkg as dkg;
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
    dkg: Option<dkg::Mailbox<Block>>,
}

impl<E: StorageContext> Clone for Application<E> {
    fn clone(&self) -> Self {
        Self {
            submitter: self.submitter.clone(),
            ledger: self.ledger.clone(),
            max_block_transactions: self.max_block_transactions,
            dkg: self.dkg.clone(),
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
            None,
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
            dkg: None,
        }
    }

    pub fn with_dkg(
        submitter: Submitter,
        ledger: SharedLedger<E>,
        max_block_transactions: usize,
        dkg: dkg::Mailbox<Block>,
    ) -> Self {
        Self {
            submitter,
            ledger,
            max_block_transactions,
            dkg: Some(dkg),
        }
    }

    async fn filter_authorized(
        &self,
        pending: Vec<nunchi_coins::Transaction>,
    ) -> Vec<nunchi_coins::Transaction> {
        let ledger = self.ledger.lock().await;
        let mut transactions = Vec::with_capacity(self.max_block_transactions.min(pending.len()));
        for transaction in pending {
            if transactions.len() == self.max_block_transactions {
                break;
            }
            if ledger.validate_authorization(&transaction).await.is_ok() {
                transactions.push(transaction);
            }
        }
        transactions
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

        // TODO: Bound txpool memory and proposal-time revalidation through admission
        // control and eviction. Bounding this fetch while the pool remains unbounded
        // can starve valid transactions behind lower-sorting unauthorized entries.
        let pending = self.submitter.pending(usize::MAX).await;
        let transactions = self.filter_authorized(pending).await;
        let reshare_log = match &mut self.dkg {
            Some(dkg) => dkg.act().await,
            None => None,
        };

        Some(Block::new(
            context,
            parent.digest(),
            parent.height.next(),
            current,
            transactions,
            reshare_log,
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
            if tx.verify().is_err() {
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
                has_reshare_log = block.reshare_log.is_some(),
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
    use crate::txpool::TxPool;
    use commonware_runtime::{deterministic, Runner as _};
    use nunchi_coins::{
        multisig_account_id, AccountPolicy, CoinOperation, CoinSpec, Ledger, MultisigPolicy,
        PrivateKey, Transaction,
    };
    use nunchi_common::QmdbState;

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
            let shared = SharedLedger::new(Ledger::new(db));
            let app = Application::new(submitter, shared.clone(), 16);

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

            assert!(app.filter_authorized(vec![tx.clone()]).await.is_empty());

            shared
                .lock()
                .await
                .register_account_policy(account_id, AccountPolicy::Multisig(policy))
                .await
                .expect("register policy");

            assert_eq!(app.filter_authorized(vec![tx.clone()]).await, vec![tx]);
        });
    }
}
