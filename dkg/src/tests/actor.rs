use super::super::*;
use crate::state::{Epoch as EpochState, Storage};
use crate::{orchestrator::Message, ContinueOnUpdate, PeerConfig};
use bytes::{Buf, BufMut};
use commonware_actor::{mailbox, Feedback};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::types::Epoch;
use commonware_consensus::{types::Height, Heightable};
use commonware_cryptography::{
    bls12381::{dkg::feldman_desmedt::deal, primitives::variant::MinSig},
    ed25519::{PrivateKey, PublicKey as Ed25519PublicKey},
    sha256,
    transcript::Summary,
    Digest as _, Digestible, PublicKey, Signer,
};
use commonware_macros::test_traced;
use commonware_math::algebra::Random;
use commonware_p2p::{utils::mocks::inert_channel, PeerSetSubscription, Provider};
use commonware_runtime::{deterministic, Runner, Supervisor as _};
use commonware_utils::{channel::mpsc, N3f1, NZUsize, TryCollect, NZU32, NZU64};
use core::marker::PhantomData;
use std::collections::BTreeMap;

#[derive(Clone)]
struct TestBlock {
    height: Height,
    parent: sha256::Digest,
}

impl Write for TestBlock {
    fn write(&self, writer: &mut impl BufMut) {
        self.height.write(writer);
        self.parent.write(writer);
    }
}

impl Read for TestBlock {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::read(reader)?,
            parent: sha256::Digest::read(reader)?,
        })
    }
}

impl EncodeSize for TestBlock {
    fn encode_size(&self) -> usize {
        self.height.encode_size() + self.parent.encode_size()
    }
}

impl Digestible for TestBlock {
    type Digest = sha256::Digest;

    fn digest(&self) -> Self::Digest {
        sha256::Digest::EMPTY
    }
}

impl Heightable for TestBlock {
    fn height(&self) -> Height {
        self.height
    }
}

impl commonware_consensus::Block for TestBlock {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl crate::ReshareBlock for TestBlock {
    fn reshare_log(&self) -> Option<&crate::DealerLog> {
        None
    }
}

#[derive(Clone, Debug)]
struct NoopManager<P: PublicKey>(PhantomData<P>);

impl<P: PublicKey> Default for NoopManager<P> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<P: PublicKey> Provider for NoopManager<P> {
    type PublicKey = P;

    async fn peer_set(&mut self, _: u64) -> Option<commonware_p2p::TrackedPeers<Self::PublicKey>> {
        None
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
        let (_, rx) = mpsc::unbounded_channel();
        rx
    }
}

impl<P: PublicKey> commonware_p2p::Manager for NoopManager<P> {
    fn track<R>(&mut self, _: u64, _: R) -> Feedback
    where
        R: Into<commonware_p2p::TrackedPeers<Self::PublicKey>> + Send,
    {
        Feedback::Ok
    }
}

fn peer_config(
    total: u64,
    per_round: Vec<u32>,
) -> (
    PeerConfig<Ed25519PublicKey>,
    BTreeMap<Ed25519PublicKey, PrivateKey>,
) {
    let participants = (0..total)
        .map(|seed| {
            let signer = PrivateKey::from_seed(seed);
            (signer.public_key(), signer)
        })
        .collect::<BTreeMap<_, _>>();
    let peer_config = PeerConfig {
        num_participants_per_round: per_round,
        participants: participants.keys().cloned().try_collect().unwrap(),
    };
    (peer_config, participants)
}

#[test_traced]
fn recovered_storage_controls_dkg_mode_on_restart() {
    let executor = deterministic::Runner::seeded(8);
    executor.start(|mut context| async move {
        const RECOVERED_EPOCH: u64 = 5;
        const RECOVERED_ROUND: u64 = 5;
        let (peer_config, participants) = peer_config(6, vec![4]);
        let first_player = peer_config
            .dealers(RECOVERED_ROUND)
            .iter()
            .next()
            .cloned()
            .expect("recovered dealer exists");
        let signer = participants
            .get(&first_player)
            .cloned()
            .expect("signer should exist");
        let (output, shares) = deal::<MinSig, _, N3f1>(
            &mut context,
            Default::default(),
            peer_config.dealers(RECOVERED_ROUND),
        )
        .expect("deal should succeed");
        let share = shares.get_value(&first_player).cloned();
        let partition_prefix = format!("recovered_restart_{first_player}");

        let mut storage = Storage::<_, MinSig, Ed25519PublicKey>::init(
            context.child("seed_storage"),
            &partition_prefix,
            NZU32!(peer_config.max_participants_per_round()),
            crate::MAX_SUPPORTED_MODE,
        )
        .await;
        storage
            .set_epoch(
                Epoch::new(RECOVERED_EPOCH),
                EpochState {
                    round: RECOVERED_ROUND,
                    rng_seed: Summary::random(&mut context),
                    output: Some(output),
                    share,
                },
            )
            .await;
        drop(storage);

        let (actor, _mailbox) = Actor::<_, _, TestBlock>::new(
            context.child("actor"),
            Config {
                manager: NoopManager::<Ed25519PublicKey>::default(),
                signer,
                mailbox_size: NZUsize!(8),
                partition_prefix,
                peer_config: peer_config.clone(),
                max_supported_mode: crate::MAX_SUPPORTED_MODE,
                namespace: b"test_dkg".to_vec(),
                epoch_length: NZU64!(200),
            },
        );
        let (sender, receiver) = inert_channel(&peer_config.participants);
        let (orchestrator_sender, mut orchestrator_receiver) =
            mailbox::new(context.child("orchestrator_mailbox"), NZUsize!(4));
        actor.start(
            None,
            None,
            crate::orchestrator::Mailbox::new(orchestrator_sender),
            (sender, receiver),
            ContinueOnUpdate::boxed(),
        );

        let Some(Message::Enter(transition)) = orchestrator_receiver.recv().await else {
            panic!("actor should emit an epoch transition");
        };
        assert_eq!(transition.epoch, Epoch::new(RECOVERED_EPOCH));
        assert!(transition.poly.is_some());
        assert_eq!(transition.dealers, peer_config.dealers(RECOVERED_ROUND));
    });
}
