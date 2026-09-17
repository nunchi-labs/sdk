use super::super::*;
use crate::state::{Epoch as EpochState, Storage};
use crate::{
    orchestrator::Message, protector::StorageProtector, ContinueOnUpdate, PeerConfig, PostUpdate,
    Update, UpdateCallBack,
};
use bytes::{Buf, BufMut};
use commonware_actor::{mailbox, Feedback};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::marshal::Update as MarshalUpdate;
use commonware_consensus::types::Epoch;
use commonware_consensus::{types::Height, Heightable, Reporter};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{deal, Dealer, DealerLog, Player, Reveal},
        primitives::{group::Share, sharing::Mode, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey as Ed25519PublicKey},
    sha256,
    transcript::Summary,
    Digest as _, Digestible, PublicKey, Signer,
};
use commonware_macros::test_traced;
use commonware_math::algebra::Random;
use commonware_p2p::{utils::mocks::inert_channel, PeerSetSubscription, Provider};
use commonware_runtime::{deterministic, Clock, Runner, Supervisor as _};
use commonware_utils::{
    acknowledgement::Exact, channel::mpsc, Acknowledgement, N3f1, NZUsize, TryCollect, NZU32,
    NZU64,
};
use core::marker::PhantomData;
use futures::channel::oneshot;
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

const TEST_STORAGE_KEY: [u8; 32] = [7u8; 32];

#[test]
fn static_secondaries_are_tracked_and_dealers_are_filtered() {
    let dealer = PrivateKey::from_seed(1).public_key();
    let observer = PrivateKey::from_seed(2).public_key();
    let other_player = PrivateKey::from_seed(3).public_key();
    let dealers = commonware_utils::ordered::Set::from_iter_dedup([dealer.clone()]);
    let players = commonware_utils::ordered::Set::from_iter_dedup([
        dealer.clone(),
        other_player.clone(),
    ]);
    let secondaries = commonware_utils::ordered::Set::from_iter_dedup([
        dealer.clone(),
        observer.clone(),
    ]);
    let tracked = crate::actor::tracked_peers(
        dealers,
        &players,
        &Default::default(),
        &secondaries,
    );

    assert!(tracked.primary.position(&dealer).is_some());
    assert!(tracked.secondary.position(&dealer).is_none());
    assert!(tracked.secondary.position(&observer).is_some());
    assert!(tracked.secondary.position(&other_player).is_some());
}

#[derive(Clone)]
struct TestBlock {
    height: Height,
    parent: sha256::Digest,
    reshare_log: Option<crate::DealerLog>,
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
            reshare_log: None,
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
        self.reshare_log.as_ref()
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

fn finalized_dkg_log(
    namespace: &[u8],
    epoch: Epoch,
    dealers: commonware_utils::ordered::Set<Ed25519PublicKey>,
    players: commonware_utils::ordered::Set<Ed25519PublicKey>,
    participants: &BTreeMap<Ed25519PublicKey, PrivateKey>,
    dealer_pk: &Ed25519PublicKey,
) -> DealerLog<MinSig, Ed25519PublicKey> {
    let round = commonware_cryptography::bls12381::dkg::feldman_desmedt::Info::new::<N3f1>(
        namespace,
        epoch.get(),
        None,
        Mode::NonZeroCounter,
            Reveal::V1,
        dealers,
        players,
    )
    .expect("round info should be valid");
    let dealer_signer = participants
        .get(dealer_pk)
        .cloned()
        .expect("dealer signer should exist");
    let (mut dealer, public, private) = Dealer::<MinSig, _>::start::<N3f1>(
        commonware_utils::test_rng(),
        round.clone(),
        dealer_signer,
        None,
    )
    .expect("dealer should start");

    for (player_pk, private) in private {
        let player_signer = participants
            .get(&player_pk)
            .cloned()
            .expect("player signer should exist");
        let mut player = Player::new(round.clone(), player_signer).expect("player should start");
        let ack = player
            .dealer_message::<N3f1>(dealer_pk.clone(), public.clone(), private)
            .expect("valid dealing")
            .expect("dealing should be acknowledged");
        dealer.receive_player_ack(player_pk, ack).unwrap();
    }

    dealer
        .finalize::<N3f1>()
        .check(&round)
        .expect("finalized log should check")
        .1
}

fn assert_recovered_storage_controls_dkg_mode_on_restart(execution: Execution, suffix: &str) {
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
            Mode::NonZeroCounter,
            peer_config.dealers(RECOVERED_ROUND),
        )
        .expect("deal should succeed");
        let share = shares.get_value(&first_player).cloned();
        let partition_prefix = format!("recovered_restart_{suffix}_{first_player}");

        let mut storage = Storage::<_, MinSig, Ed25519PublicKey>::init(
            context.child("seed_storage"),
            &partition_prefix,
            StorageProtector::new(TEST_STORAGE_KEY),
            b"test_dkg".to_vec(),
            first_player.clone(),
            NZU32!(peer_config.max_participants_per_round()),
            crate::MAX_SUPPORTED_MODE,
        )
        .await
        .expect("storage init should succeed");
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
            .await
            .expect("set epoch should succeed");
        drop(storage);

        let (actor, _mailbox) = Actor::<_, _, TestBlock>::new(
            context.child("actor"),
            Config {
                manager: NoopManager::<Ed25519PublicKey>::default(),
                signer,
                mailbox_size: NZUsize!(8),
                execution,
                partition_prefix,
                peer_config: peer_config.clone(),
                secondary_nodes: Default::default(),
                max_supported_mode: crate::MAX_SUPPORTED_MODE,
                namespace: b"test_dkg".to_vec(),
                storage_protector: StorageProtector::new(TEST_STORAGE_KEY),
                epoch_length: NZU64!(200),
            },
        );
        let (sender, receiver) = inert_channel(&peer_config.participants);
        let (orchestrator_sender, mut orchestrator_receiver) =
            mailbox::new(context.child("orchestrator_mailbox"), NZUsize!(4));
        let handle = actor.start(
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

        handle.abort();
        let _ = handle.await;
    });
}

#[test_traced]
fn default_execution_recovered_storage_controls_dkg_mode_on_restart() {
    assert_recovered_storage_controls_dkg_mode_on_restart(Execution::default(), "shared");
}

#[test_traced]
fn dedicated_execution_recovered_storage_controls_dkg_mode_on_restart() {
    assert_recovered_storage_controls_dkg_mode_on_restart(Execution::Dedicated, "dedicated");
}

#[test_traced]
fn legacy_missing_player_dealing_exits_actor() {
    let executor = deterministic::Runner::seeded(9);
    executor.start(|mut context| async move {
        let namespace = b"test_dkg".to_vec();
        let epoch = Epoch::zero();
        let (peer_config, participants) = peer_config(4, vec![4]);
        let self_pk = peer_config
            .participants
            .iter()
            .next()
            .cloned()
            .expect("participant exists");
        let signer = participants
            .get(&self_pk)
            .cloned()
            .expect("signer should exist");
        let dealer_pk = peer_config
            .participants
            .iter()
            .find(|candidate| **candidate != self_pk)
            .cloned()
            .expect("dealer exists");
        let log = finalized_dkg_log(
            &namespace,
            epoch,
            peer_config.participants.clone(),
            peer_config.dealers(0),
            &participants,
            &dealer_pk,
        );
        let partition_prefix = format!("legacy_missing_player_dealing_{self_pk}");

        let mut storage = Storage::<_, MinSig, Ed25519PublicKey>::init(
            context.child("seed_storage"),
            &partition_prefix,
            StorageProtector::new(TEST_STORAGE_KEY),
            namespace.clone(),
            self_pk.clone(),
            NZU32!(peer_config.max_participants_per_round()),
            crate::MAX_SUPPORTED_MODE,
        )
        .await
        .expect("storage init should succeed");
        storage
            .set_epoch(
                epoch,
                EpochState {
                    round: 0,
                    rng_seed: Summary::random(&mut context),
                    output: None,
                    share: None,
                },
            )
            .await
            .expect("set epoch should succeed");
        storage
            .append_log(epoch, dealer_pk, log)
            .await
            .expect("append log should succeed");
        drop(storage);

        let (actor, _mailbox) = Actor::<_, _, TestBlock>::new(
            context.child("actor"),
            Config {
                manager: NoopManager::<Ed25519PublicKey>::default(),
                signer,
                mailbox_size: NZUsize!(8),
                execution: Execution::default(),
                partition_prefix,
                peer_config: peer_config.clone(),
                secondary_nodes: Default::default(),
                max_supported_mode: crate::MAX_SUPPORTED_MODE,
                namespace,
                storage_protector: StorageProtector::new(TEST_STORAGE_KEY),
                epoch_length: NZU64!(200),
            },
        );
        let (sender, receiver) = inert_channel(&peer_config.participants);
        let (orchestrator_sender, mut orchestrator_receiver) =
            mailbox::new(context.child("orchestrator_mailbox"), NZUsize!(4));
        let handle = actor.start(
            None,
            None,
            crate::orchestrator::Mailbox::new(orchestrator_sender),
            (sender, receiver),
            ContinueOnUpdate::boxed(),
        );

        let Some(Message::Enter(transition)) = orchestrator_receiver.recv().await else {
            panic!("actor should emit an epoch transition before detecting bad player state");
        };
        assert_eq!(transition.epoch, epoch);

        commonware_macros::select! {
            _ = handle => {},
            _ = context.sleep(std::time::Duration::from_secs(1)) => {
                panic!("legacy actor should fail closed instead of continuing shareless");
            },
        }
    });
}

struct CaptureUpdate {
    tx: Option<oneshot::Sender<Update<MinSig, Ed25519PublicKey>>>,
}

impl UpdateCallBack<MinSig, Ed25519PublicKey> for CaptureUpdate {
    fn on_update(
        &mut self,
        update: Update<MinSig, Ed25519PublicKey>,
    ) -> Pin<Box<dyn Future<Output = PostUpdate> + Send>> {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(update);
        }
        Box::pin(async { PostUpdate::Stop })
    }
}

fn signed_reshare_log(
    namespace: &[u8],
    output: &commonware_cryptography::bls12381::dkg::feldman_desmedt::Output<
        MinSig,
        Ed25519PublicKey,
    >,
    dealers: commonware_utils::ordered::Set<Ed25519PublicKey>,
    players: commonware_utils::ordered::Set<Ed25519PublicKey>,
    participants: &BTreeMap<Ed25519PublicKey, PrivateKey>,
    shares: &commonware_utils::ordered::Map<Ed25519PublicKey, Share>,
    dealer_pk: &Ed25519PublicKey,
) -> crate::DealerLog {
    let round = commonware_cryptography::bls12381::dkg::feldman_desmedt::Info::new::<N3f1>(
        namespace,
        0,
        Some(output.clone()),
        Mode::NonZeroCounter,
        Reveal::V1,
        dealers,
        players,
    )
    .expect("reshare round info should be valid");
    let dealer_signer = participants
        .get(dealer_pk)
        .cloned()
        .expect("dealer signer should exist");
    let share = shares.get_value(dealer_pk).cloned();
    let (mut dealer, public, private) = Dealer::<MinSig, _>::start::<N3f1>(
        commonware_utils::test_rng(),
        round.clone(),
        dealer_signer,
        share,
    )
    .expect("reshare dealer should start");

    for (player_pk, private) in private {
        let player_signer = participants
            .get(&player_pk)
            .cloned()
            .expect("player signer should exist");
        let mut player = Player::new(round.clone(), player_signer).expect("player should start");
        let ack = player
            .dealer_message::<N3f1>(dealer_pk.clone(), public.clone(), private)
            .expect("valid dealing")
            .expect("dealing should be acknowledged");
        dealer.receive_player_ack(player_pk, ack).unwrap();
    }

    dealer.finalize::<N3f1>()
}

fn test_block(height: u64, reshare_log: Option<crate::DealerLog>) -> TestBlock {
    TestBlock {
        height: Height::new(height),
        parent: sha256::Digest::EMPTY,
        reshare_log,
    }
}

#[test_traced]
fn public_transition_continues_shareless_when_player_dealing_is_missing() {
    let executor = deterministic::Runner::seeded(11);
    executor.start(|mut context| async move {
        const EPOCH_LENGTH: u64 = 4;
        let namespace = b"test_dkg".to_vec();
        let (peer_config, participants) = peer_config(4, vec![3, 4]);
        let dealers = peer_config.dealers(0);
        let players = peer_config.dealers(1);
        let self_pk = players
            .iter()
            .find(|player| dealers.position(player).is_none())
            .cloned()
            .expect("round-1 players include a node that was not a round-0 dealer");
        let signer = participants
            .get(&self_pk)
            .cloned()
            .expect("signer should exist");
        let (output, shares) = deal::<MinSig, _, N3f1>(
            &mut context,
            Mode::NonZeroCounter,
            dealers.clone(),
        )
        .expect("deal should succeed");
        let logs: Vec<_> = dealers
            .iter()
            .map(|dealer_pk| {
                signed_reshare_log(
                    &namespace,
                    &output,
                    dealers.clone(),
                    players.clone(),
                    &participants,
                    &shares,
                    dealer_pk,
                )
            })
            .collect();
        let partition_prefix = format!("missing_player_finalize_{self_pk}");

        let (actor, mut mailbox) = Actor::<_, _, TestBlock>::new(
            context.child("actor"),
            Config {
                manager: NoopManager::<Ed25519PublicKey>::default(),
                signer,
                mailbox_size: NZUsize!(16),
                execution: Execution::default(),
                partition_prefix,
                peer_config: peer_config.clone(),
                secondary_nodes: Default::default(),
                max_supported_mode: crate::MAX_SUPPORTED_MODE,
                namespace,
                storage_protector: StorageProtector::new(TEST_STORAGE_KEY),
                epoch_length: NZU64!(EPOCH_LENGTH),
            },
        );
        let (sender, receiver) = inert_channel(&peer_config.participants);
        let (orchestrator_sender, mut orchestrator_receiver) =
            mailbox::new(context.child("orchestrator_mailbox"), NZUsize!(4));
        let (update_tx, update_rx) = oneshot::channel();
        let handle = actor.start(
            Some(output),
            None,
            crate::orchestrator::Mailbox::new(orchestrator_sender),
            (sender, receiver),
            Box::new(CaptureUpdate {
                tx: Some(update_tx),
            }),
        );

        let Some(Message::Enter(transition)) = orchestrator_receiver.recv().await else {
            panic!("actor should enter the recovered epoch");
        };
        assert_eq!(transition.epoch, Epoch::zero());

        for height in 0..EPOCH_LENGTH {
            let log = logs.get(height as usize).cloned();
            let (ack, waiter) = Exact::handle();
            assert!(mailbox
                .report(MarshalUpdate::Block(
                    Arc::new(test_block(height, log)),
                    ack,
                ))
                .accepted());
            waiter.await.expect("finalized block should be acknowledged");
        }

        let update = update_rx.await.expect("actor should report a DKG update");
        let Update::Success {
            epoch,
            share: next_share,
            ..
        } = update
        else {
            panic!("expected a successful public DKG transition");
        };
        assert_eq!(epoch, Epoch::zero());
        assert!(
            next_share.is_none(),
            "player without local dealings should continue shareless"
        );

        handle.abort();
        let _ = handle.await;
    });
}
