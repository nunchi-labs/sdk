use crate::{genesis, Block, Context, Scheme};
use commonware_actor::Feedback;
use commonware_consensus::{
    marshal::{ancestry::Ancestry, Update},
    Application as ConsensusApplication, Heightable, Reporter,
};
use commonware_cryptography::Digestible;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_utils::{Acknowledgement, SystemTimeExt};
use futures::StreamExt;
use nunchi_dkg as dkg;
use rand::Rng;
use std::time::{Duration, SystemTime};
use tracing::info;

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
///
/// Different platforms have different `SystemTime` limits, so we use a fixed
/// timestamp to ensure consistent application of block validity rules.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

#[derive(Clone, Default)]
pub struct Application {
    dkg: Option<dkg::Mailbox<Block>>,
}

impl Application {
    pub fn genesis() -> Block {
        genesis()
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_dkg(dkg: dkg::Mailbox<Block>) -> Self {
        Self { dkg: Some(dkg) }
    }
}

impl<E> ConsensusApplication<E> for Application
where
    E: Rng + Spawner + Metrics + Clock + Storage,
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

        // Create a new block.
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

        let reshare = match &mut self.dkg {
            Some(dkg) => dkg.act().await,
            None => None,
        };

        Some(Block::new(
            context,
            parent.digest(),
            parent.height.next(),
            current,
            reshare,
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

        // Verify the block (waiting until the block timestamp has passed to vote in case of skew).
        if block.timestamp <= parent.timestamp || block.timestamp > MAX_BLOCK_TIMESTAMP_MS {
            return false;
        }
        let deadline = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(block.timestamp))
            .expect("block timestamp exceeded maximum");
        runtime_context.sleep_until(deadline).await;

        // The height and digest invariants are enforced in `Marshaled`:
        // - The block height must be one greater than the parent's height.
        // - The block's parent digest must match the parent's digest.
        true
    }
}

impl Reporter for Application {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Block(block, _) = &activity {
            info!(
                height = %block.height(),
                digest = ?block.digest(),
                timestamp = block.timestamp,
                has_reshare_log = block.log.is_some(),
                "finalized block"
            );
        }

        if let Update::Block(_, ack_rx) = activity {
            ack_rx.acknowledge();
        }
        Feedback::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{
        marshal::ancestry,
        types::{Height, Round, View},
    };
    use commonware_cryptography::{ed25519, sha256, Digest as _, Hasher, Sha256, Signer};
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};

    fn test_context(view: u64, parent: (View, sha256::Digest)) -> Context {
        Context {
            round: Round::new(crate::EPOCH, View::new(view)),
            leader: ed25519::PrivateKey::from_seed(view).public_key(),
            parent,
        }
    }

    async fn verify_block(
        context: deterministic::Context,
        application: &mut Application,
        block: &Block,
        parent: &Block,
    ) -> bool {
        let ancestry = ancestry::from_iter([block.clone(), parent.clone()]);
        ConsensusApplication::verify(application, (context, block.context.clone()), ancestry).await
    }

    async fn propose_child(
        context: deterministic::Context,
        application: &mut Application,
        child_context: Context,
        parent: &Block,
    ) -> Block {
        let ancestry = ancestry::from_iter([parent.clone()]);
        ConsensusApplication::propose(application, (context, child_context), ancestry)
            .await
            .expect("expected proposal")
    }

    #[test]
    fn verify_waits_for_far_future_block_timestamp() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut application = Application::new();

            let now = context.current().epoch_millis();
            let parent = Block::new(
                test_context(1, (View::zero(), sha256::Digest::EMPTY)),
                Sha256::hash(b"genesis"),
                Height::new(1),
                now,
                None,
            );
            let block = Block::new(
                test_context(2, (View::new(1), parent.digest())),
                parent.digest(),
                parent.height.next(),
                now + 5_000,
                None,
            );

            let start = context.current();
            assert!(verify_block(context.child("verify"), &mut application, &block, &parent).await);
            let finished = context.current();
            assert!(finished.duration_since(start).unwrap() > Duration::ZERO);
            assert!(finished.epoch_millis() >= block.timestamp);
        });
    }

    #[test]
    fn verify_rejects_equal_parent_timestamp() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut application = Application::new();

            let now = context.current().epoch_millis();
            let parent = Block::new(
                test_context(1, (View::zero(), sha256::Digest::EMPTY)),
                Sha256::hash(b"genesis"),
                Height::new(1),
                now,
                None,
            );
            let block = Block::new(
                test_context(2, (View::new(1), parent.digest())),
                parent.digest(),
                parent.height.next(),
                now,
                None,
            );

            assert!(
                !verify_block(context.child("verify"), &mut application, &block, &parent).await
            );
        });
    }

    #[test]
    fn verify_returns_immediately_for_mature_block_timestamp() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut application = Application::new();

            context.sleep(Duration::from_millis(10)).await;
            let now = context.current().epoch_millis();
            let parent = Block::new(
                test_context(1, (View::zero(), sha256::Digest::EMPTY)),
                Sha256::hash(b"genesis"),
                Height::new(1),
                now - 1,
                None,
            );
            let block = Block::new(
                test_context(2, (View::new(1), parent.digest())),
                parent.digest(),
                parent.height.next(),
                now,
                None,
            );

            let start = context.current();
            assert!(verify_block(context.child("verify"), &mut application, &block, &parent).await);
            let finished = context.current();
            assert!(finished.duration_since(start).unwrap() < Duration::from_millis(10));
        });
    }

    #[test]
    fn propose_uses_parent_timestamp_plus_one_when_clock_is_behind() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut application = Application::new();

            let now = context.current().epoch_millis();
            let parent = Block::new(
                test_context(1, (View::zero(), sha256::Digest::EMPTY)),
                Sha256::hash(b"genesis"),
                Height::new(1),
                now + 5_000,
                None,
            );
            let proposal = propose_child(
                context.child("propose"),
                &mut application,
                test_context(2, (View::new(1), parent.digest())),
                &parent,
            )
            .await;

            assert_eq!(proposal.timestamp, parent.timestamp + 1);
            assert_eq!(proposal.parent, parent.digest());
            assert_eq!(proposal.height, parent.height.next());
            assert!(proposal.log.is_none());
        });
    }
}
