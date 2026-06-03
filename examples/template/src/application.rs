use crate::{dkg, genesis, Block, Context, Scheme};
use commonware_actor::Feedback;
use commonware_consensus::{
    marshal::{ancestry::Ancestry, Update},
    Application as ConsensusApplication, Heightable, Reporter,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519, Digestible, Sha256};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_utils::Acknowledgement;
use futures::StreamExt;
use rand::Rng;
use tracing::info;

#[derive(Clone)]
pub struct Application {
    dkg: dkg::Mailbox<Sha256, ed25519::PrivateKey, MinSig>,
}

impl Application {
    pub fn genesis() -> Block {
        genesis::<Sha256, ed25519::PrivateKey, MinSig>()
    }

    pub fn new(dkg: dkg::Mailbox<Sha256, ed25519::PrivateKey, MinSig>) -> Self {
        Self { dkg }
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
        (_, context): (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
    ) -> Option<Self::Block> {
        let parent = ancestry.next().await?;
        let reshare = self.dkg.act().await;

        Some(Block::new(
            context,
            parent.digest(),
            parent.height().next(),
            reshare,
        ))
    }

    async fn verify(&mut self, _: (E, Self::Context), _: impl Ancestry<Self::Block>) -> bool {
        // `Marshaled` handles parent/height ancestry checks. DKG dealer logs are
        // processed only after finalization, matching the reference reshare example.
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
