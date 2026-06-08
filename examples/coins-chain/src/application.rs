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
#[derive(Clone)]
pub struct Application {
    submitter: Submitter,
    max_block_transactions: usize,
    dkg: Option<dkg::Mailbox<Block>>,
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
        )
    }

    pub fn new(submitter: Submitter, max_block_transactions: usize) -> Self {
        Self {
            submitter,
            max_block_transactions,
            dkg: None,
        }
    }

    pub fn with_dkg(
        submitter: Submitter,
        max_block_transactions: usize,
        dkg: dkg::Mailbox<Block>,
    ) -> Self {
        Self {
            submitter,
            max_block_transactions,
            dkg: Some(dkg),
        }
    }
}

impl<E> ConsensusApplication<E> for Application
where
    E: Rng + Spawner + Metrics + Clock,
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

        let transactions = self.submitter.pending(self.max_block_transactions).await;
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
        if block.transactions.iter().any(|tx| tx.verify().is_err()) {
            return false;
        }

        let deadline = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(block.timestamp))
            .expect("block timestamp exceeded maximum");
        runtime_context.sleep_until(deadline).await;

        true
    }
}

impl Reporter for Application {
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
