use crate::{protector::StorageProtector, state::{Dealer, Storage}};
use commonware_codec::{Encode, ReadExt};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{DealerPrivMsg, Info, PlayerAck},
        primitives::{group::Scalar, sharing::Mode, variant::MinPk},
    },
    ed25519::{self},
    Signer,
};
use commonware_macros::test_traced;
use commonware_math::algebra::{Random, Ring};
use commonware_runtime::{deterministic, Runner, Supervisor as _};
use commonware_utils::NZU32;
use commonware_utils::{ordered::Set, test_rng, test_rng_seeded, N3f1};
use std::collections::BTreeMap;

const TEST_NAMESPACE: &[u8] = b"test_dkg";
const TEST_STORAGE_KEY: [u8; 32] = [7u8; 32];

fn create_test_signers(n: usize) -> Vec<ed25519::PrivateKey> {
    (0..n)
        .map(|i| {
            let mut rng = test_rng_seeded(i as u64);
            ed25519::PrivateKey::random(&mut rng)
        })
        .collect()
}

fn create_round_info(signers: &[ed25519::PrivateKey]) -> Info<MinPk, ed25519::PublicKey> {
    let players = Set::from_iter_dedup(signers.iter().map(|s| s.public_key()));
    let dealers = players.clone();
    Info::new::<N3f1>(
        TEST_NAMESPACE,
        0,
        None,
        Mode::NonZeroCounter,
        dealers,
        players,
    )
    .expect("valid info")
}

#[test_traced]
fn test_dealer_handle_returns_false_when_player_not_in_unsent() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let signers = create_test_signers(4);
        let round_info = create_round_info(&signers);

        let mut storage = Storage::<_, MinPk, _>::init(
            context.child("storage"),
            "test",
            StorageProtector::new(TEST_STORAGE_KEY),
            TEST_NAMESPACE.to_vec(),
            signers[0].public_key(),
            NZU32!(10),
            crate::MAX_SUPPORTED_MODE,
        )
        .await;

        let dealer_signer = signers[0].clone();
        let mut rng = test_rng();
        let (crypto_dealer, pub_msg, priv_msgs) =
            commonware_cryptography::bls12381::dkg::feldman_desmedt::Dealer::<MinPk, _>::start::<
                N3f1,
            >(&mut rng, round_info, dealer_signer, None)
            .expect("valid dealer");

        let unsent: BTreeMap<_, _> = priv_msgs.into_iter().collect();
        let mut dealer = Dealer::new(Some(crypto_dealer), pub_msg, unsent);

        let unknown_player = {
            let mut rng = test_rng_seeded(100);
            ed25519::PrivateKey::random(&mut rng).public_key()
        };
        let fake_ack = PlayerAck::read(&mut signers[1].sign(b"ns", b"msg").encode().as_ref())
            .expect("valid ack");

        let result = dealer
            .handle(&mut storage, Epoch::zero(), unknown_player, fake_ack)
            .await;

        assert!(
            !result,
            "handle should return false when player not in unsent"
        );
    });
}

#[test_traced]
fn test_dealer_handle_returns_false_when_crypto_dealer_is_none() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let signers = create_test_signers(4);
        let round_info = create_round_info(&signers);

        let mut storage = Storage::<_, MinPk, ed25519::PublicKey>::init(
            context.child("storage"),
            "test",
            StorageProtector::new(TEST_STORAGE_KEY),
            TEST_NAMESPACE.to_vec(),
            signers[0].public_key(),
            NZU32!(10),
            crate::MAX_SUPPORTED_MODE,
        )
        .await;

        let dealer_signer = signers[0].clone();
        let mut rng = test_rng();
        let (_crypto_dealer, pub_msg, priv_msgs) =
            commonware_cryptography::bls12381::dkg::feldman_desmedt::Dealer::<MinPk, _>::start::<
                N3f1,
            >(&mut rng, round_info, dealer_signer, None)
            .expect("valid dealer");

        let player = signers[1].public_key();
        let mut unsent: BTreeMap<_, _> = priv_msgs.into_iter().collect();
        unsent.insert(player.clone(), DealerPrivMsg::new(Scalar::one()));

        let mut dealer = Dealer::<MinPk, ed25519::PrivateKey>::new(None, pub_msg, unsent);

        let sig = signers[1].sign(b"ns", b"msg");
        let fake_ack: PlayerAck<ed25519::PublicKey> =
            PlayerAck::read(&mut sig.encode().as_ref()).expect("valid ack");

        let result = dealer
            .handle(&mut storage, Epoch::zero(), player, fake_ack)
            .await;

        assert!(
            !result,
            "handle should return false when crypto dealer is None"
        );
    });
}

#[test_traced]
fn test_dealer_handle_returns_true_for_valid_ack() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let signers = create_test_signers(4);
        let round_info = create_round_info(&signers);

        let mut storage = Storage::<_, MinPk, _>::init(
            context.child("storage"),
            "test",
            StorageProtector::new(TEST_STORAGE_KEY),
            TEST_NAMESPACE.to_vec(),
            signers[0].public_key(),
            NZU32!(10),
            crate::MAX_SUPPORTED_MODE,
        )
        .await;

        let dealer_signer = signers[0].clone();
        let mut rng = test_rng();
        let (crypto_dealer, pub_msg, priv_msgs) =
            commonware_cryptography::bls12381::dkg::feldman_desmedt::Dealer::<MinPk, _>::start::<
                N3f1,
            >(&mut rng, round_info.clone(), dealer_signer.clone(), None)
            .expect("valid dealer");

        let unsent: BTreeMap<_, _> = priv_msgs.into_iter().collect();
        let mut dealer = Dealer::new(Some(crypto_dealer), pub_msg.clone(), unsent);

        let player_signer = signers[1].clone();
        let player_pk = player_signer.public_key();
        let player_priv_msg = dealer
            .shares_to_distribute()
            .find(|(p, _, _)| *p == player_pk)
            .map(|(_, _, priv_msg)| priv_msg)
            .expect("player should have a share");

        let mut crypto_player =
            commonware_cryptography::bls12381::dkg::feldman_desmedt::Player::new(
                round_info,
                player_signer,
            )
            .expect("valid player");
        let ack = crypto_player
            .dealer_message::<N3f1>(dealer_signer.public_key(), pub_msg, player_priv_msg)
            .expect("valid ack");

        let result = dealer
            .handle(&mut storage, Epoch::zero(), player_pk, ack)
            .await;

        assert!(result, "handle should return true for valid ack");
    });
}

#[test_traced]
fn test_dealer_handle_returns_false_for_duplicate_ack() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let signers = create_test_signers(4);
        let round_info = create_round_info(&signers);

        let mut storage = Storage::<_, MinPk, ed25519::PublicKey>::init(
            context.child("storage"),
            "test",
            StorageProtector::new(TEST_STORAGE_KEY),
            TEST_NAMESPACE.to_vec(),
            signers[0].public_key(),
            NZU32!(10),
            crate::MAX_SUPPORTED_MODE,
        )
        .await;

        let dealer_signer = signers[0].clone();
        let mut rng = test_rng();
        let (crypto_dealer, pub_msg, priv_msgs) =
            commonware_cryptography::bls12381::dkg::feldman_desmedt::Dealer::<MinPk, _>::start::<
                N3f1,
            >(&mut rng, round_info.clone(), dealer_signer.clone(), None)
            .expect("valid dealer");

        let unsent: BTreeMap<_, _> = priv_msgs.into_iter().collect();
        let mut dealer = Dealer::new(Some(crypto_dealer), pub_msg.clone(), unsent);

        let player_signer = signers[1].clone();
        let player_pk = player_signer.public_key();
        let player_priv_msg = dealer
            .shares_to_distribute()
            .find(|(p, _, _)| *p == player_pk)
            .map(|(_, _, priv_msg)| priv_msg)
            .expect("player should have a share");

        let mut crypto_player =
            commonware_cryptography::bls12381::dkg::feldman_desmedt::Player::new(
                round_info,
                player_signer,
            )
            .expect("valid player");
        let ack = crypto_player
            .dealer_message::<N3f1>(dealer_signer.public_key(), pub_msg, player_priv_msg)
            .expect("valid ack");

        let result = dealer
            .handle(&mut storage, Epoch::zero(), player_pk.clone(), ack.clone())
            .await;
        assert!(result, "first ack should succeed");

        let result = dealer
            .handle(&mut storage, Epoch::zero(), player_pk, ack)
            .await;
        assert!(!result, "duplicate ack should return false");
    });
}
