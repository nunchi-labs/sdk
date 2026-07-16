use crate::{
    protector::{ProtectionError, SealedRecord, StorageProtector},
    state::{Dealer, Epoch as EpochState, Error as StorageError, Storage},
};
use bytes::Bytes;
use commonware_codec::{Encode, RangeCfg, ReadExt};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{DealerPrivMsg, DealerPubMsg, Info, PlayerAck, Verdict},
        primitives::{
            group::{Private, Scalar, Share},
            sharing::Mode,
            variant::MinPk,
        },
    },
    ed25519::{self},
    transcript::Summary,
    Signer,
};
use commonware_macros::test_traced;
use commonware_math::algebra::{Random, Ring};
use commonware_runtime::{
    deterministic, BufferPooler, Clock, Metrics, Runner, Storage as RuntimeStorage, Supervisor as _,
};
use commonware_storage::{
    metadata::{Config as MetadataConfig, Metadata},
    Context as StorageContext,
};
use commonware_utils::{ordered::Set, test_rng, TestRng, N3f1, Participant, NZU32};
use rand::CryptoRng;
use std::collections::BTreeMap;

const TEST_NAMESPACE: &[u8] = b"test_dkg";
const TEST_STORAGE_KEY: [u8; 32] = [7u8; 32];
const WRONG_STORAGE_KEY: [u8; 32] = [8u8; 32];

fn create_test_signers(n: usize) -> Vec<ed25519::PrivateKey> {
    (0..n)
        .map(|i| {
            let mut rng = TestRng::new(i as u64);
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

async fn init_storage<E>(
    context: E,
    partition: &str,
    key: [u8; 32],
    namespace: Vec<u8>,
    public_key: ed25519::PublicKey,
) -> Storage<E, MinPk, ed25519::PublicKey>
where
    E: BufferPooler + Clock + RuntimeStorage + Metrics + CryptoRng,
{
    Storage::<_, MinPk, ed25519::PublicKey>::init(
        context,
        partition,
        StorageProtector::new(key),
        namespace,
        public_key,
        NZU32!(10),
        crate::MAX_SUPPORTED_MODE,
    )
    .await
    .expect("storage init should succeed")
}

fn epoch_state<E>(
    context: &mut E,
    round: u64,
    share: Option<Share>,
) -> EpochState<MinPk, ed25519::PublicKey>
where
    E: CryptoRng,
{
    EpochState {
        round,
        rng_seed: Summary::random(context),
        output: None,
        share,
    }
}

fn test_dealing(
    signers: &[ed25519::PrivateKey],
) -> (ed25519::PublicKey, DealerPubMsg<MinPk>, DealerPrivMsg) {
    let round_info = create_round_info(signers);
    let dealer_signer = signers[0].clone();
    let player = signers[1].public_key();
    let mut rng = test_rng();
    let (_crypto_dealer, pub_msg, priv_msgs) =
        commonware_cryptography::bls12381::dkg::feldman_desmedt::Dealer::<MinPk, _>::start::<
            N3f1,
        >(&mut rng, round_info, dealer_signer.clone(), None)
        .expect("valid dealer");
    let priv_msg = priv_msgs
        .into_iter()
        .find(|(candidate, _)| *candidate == player)
        .map(|(_, priv_msg)| priv_msg)
        .expect("player should have a share");
    (dealer_signer.public_key(), pub_msg, priv_msg)
}

async fn corrupt_epoch_record<E>(context: E, partition: &str, epoch: Epoch)
where
    E: StorageContext,
{
    let mut metadata = Metadata::<_, u64, SealedRecord>::init(
        context,
        MetadataConfig {
            partition: format!("{partition}_states"),
            codec_config: RangeCfg::from(..),
        },
    )
    .await
    .expect("metadata init should succeed");
    let record = metadata
        .get_mut(&epoch.get())
        .expect("epoch record should exist");
    let mut ciphertext = record.ciphertext.to_vec();
    let byte = ciphertext
        .first_mut()
        .expect("sealed record should have ciphertext");
    *byte ^= 1;
    record.ciphertext = Bytes::from(ciphertext);
    metadata.sync().await.expect("metadata sync should succeed");
}

fn assert_open_failure<T>(result: Result<T, StorageError>, message: &str) {
    match result {
        Err(StorageError::Protection(ProtectionError::Open)) => {}
        Err(err) => panic!("expected protection open failure, got {err}"),
        Ok(_) => panic!("{message}"),
    }
}

#[test_traced]
fn storage_recovers_sealed_metadata_and_journal_records() {
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let signers = create_test_signers(4);
        let public_key = signers[0].public_key();
        let partition = "sealed_recovery";
        let epoch = Epoch::new(1);
        let state = epoch_state(
            &mut context,
            7,
            Some(Share::new(Participant::new(1), Private::new(Scalar::one()))),
        );
        let (dealer, pub_msg, priv_msg) = test_dealing(&signers);

        let mut storage = init_storage(
            context.child("storage"),
            partition,
            TEST_STORAGE_KEY,
            TEST_NAMESPACE.to_vec(),
            public_key.clone(),
        )
        .await;
        storage
            .set_epoch(epoch, state.clone())
            .await
            .expect("set epoch should succeed");
        storage
            .append_dealing(epoch, dealer.clone(), pub_msg.clone(), priv_msg.clone())
            .await
            .expect("append dealing should succeed");
        drop(storage);

        let recovered = init_storage(
            context.child("recovered_storage"),
            partition,
            TEST_STORAGE_KEY,
            TEST_NAMESPACE.to_vec(),
            public_key,
        )
        .await;

        let (recovered_epoch, recovered_state) =
            recovered.epoch().expect("epoch should recover");
        assert_eq!(recovered_epoch, epoch);
        assert_eq!(recovered_state.round, state.round);
        assert_eq!(recovered_state.rng_seed, state.rng_seed);
        assert_eq!(recovered_state.share, state.share);
        assert_eq!(
            recovered.dealings(epoch),
            vec![(dealer, pub_msg, priv_msg)]
        );
    });
}

#[test_traced]
fn storage_recovery_rejects_wrong_key() {
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let signers = create_test_signers(4);
        let public_key = signers[0].public_key();
        let partition = "wrong_key_recovery";

        let mut storage = Storage::<_, MinPk, ed25519::PublicKey>::init(
            context.child("storage"),
            partition,
            StorageProtector::new(TEST_STORAGE_KEY),
            TEST_NAMESPACE.to_vec(),
            public_key.clone(),
            NZU32!(10),
            crate::MAX_SUPPORTED_MODE,
        )
        .await
        .expect("storage init should succeed");
        storage
            .set_epoch(
                Epoch::zero(),
                EpochState {
                    round: 0,
                    rng_seed: Summary::random(&mut context),
                    output: None,
                    share: None,
                },
            )
            .await
            .expect("set epoch should succeed");
        drop(storage);

        let result = Storage::<_, MinPk, ed25519::PublicKey>::init(
            context.child("wrong_key_storage"),
            partition,
            StorageProtector::new(WRONG_STORAGE_KEY),
            TEST_NAMESPACE.to_vec(),
            public_key,
            NZU32!(10),
            crate::MAX_SUPPORTED_MODE,
        )
        .await;

        match result {
            Err(StorageError::Protection(ProtectionError::Open)) => {}
            Err(err) => panic!("expected protection open failure, got {err}"),
            Ok(_) => panic!("wrong key should fail closed"),
        }
    });
}

#[test_traced]
fn storage_recovery_rejects_wrong_associated_data() {
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let signers = create_test_signers(4);
        let public_key = signers[0].public_key();
        let partition = "wrong_ad_recovery";

        let mut storage = Storage::<_, MinPk, ed25519::PublicKey>::init(
            context.child("storage"),
            partition,
            StorageProtector::new(TEST_STORAGE_KEY),
            TEST_NAMESPACE.to_vec(),
            public_key.clone(),
            NZU32!(10),
            crate::MAX_SUPPORTED_MODE,
        )
        .await
        .expect("storage init should succeed");
        storage
            .set_epoch(
                Epoch::zero(),
                EpochState {
                    round: 0,
                    rng_seed: Summary::random(&mut context),
                    output: None,
                    share: None,
                },
            )
            .await
            .expect("set epoch should succeed");
        drop(storage);

        let result = Storage::<_, MinPk, ed25519::PublicKey>::init(
            context.child("wrong_ad_storage"),
            partition,
            StorageProtector::new(TEST_STORAGE_KEY),
            b"wrong_namespace".to_vec(),
            public_key,
            NZU32!(10),
            crate::MAX_SUPPORTED_MODE,
        )
        .await;

        match result {
            Err(StorageError::Protection(ProtectionError::Open)) => {}
            Err(err) => panic!("expected protection open failure, got {err}"),
            Ok(_) => panic!("wrong associated data should fail closed"),
        }
    });
}

#[test_traced]
fn storage_recovery_rejects_corrupted_record() {
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let signers = create_test_signers(4);
        let public_key = signers[0].public_key();
        let partition = "corrupted_record_recovery";
        let epoch = Epoch::zero();

        let mut storage = init_storage(
            context.child("storage"),
            partition,
            TEST_STORAGE_KEY,
            TEST_NAMESPACE.to_vec(),
            public_key.clone(),
        )
        .await;
        storage
            .set_epoch(epoch, epoch_state(&mut context, 0, None))
            .await
            .expect("set epoch should succeed");
        drop(storage);

        corrupt_epoch_record(context.child("metadata"), partition, epoch).await;

        let result = Storage::<_, MinPk, ed25519::PublicKey>::init(
            context.child("corrupted_storage"),
            partition,
            StorageProtector::new(TEST_STORAGE_KEY),
            TEST_NAMESPACE.to_vec(),
            public_key,
            NZU32!(10),
            crate::MAX_SUPPORTED_MODE,
        )
        .await;
        assert_open_failure(result, "corrupted record should fail closed");
    });
}

#[test_traced]
fn storage_prune_removes_old_sealed_records_after_restart() {
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let signers = create_test_signers(4);
        let public_key = signers[0].public_key();
        let partition = "pruned_sealed_records";
        let (dealer, pub_msg, priv_msg) = test_dealing(&signers);

        let mut storage = init_storage(
            context.child("storage"),
            partition,
            TEST_STORAGE_KEY,
            TEST_NAMESPACE.to_vec(),
            public_key.clone(),
        )
        .await;
        for raw_epoch in 0..=2 {
            let epoch = Epoch::new(raw_epoch);
            storage
                .set_epoch(epoch, epoch_state(&mut context, raw_epoch, None))
                .await
                .expect("set epoch should succeed");
            storage
                .append_dealing(epoch, dealer.clone(), pub_msg.clone(), priv_msg.clone())
                .await
                .expect("append dealing should succeed");
        }
        storage
            .prune(Epoch::new(2))
            .await
            .expect("prune should succeed");
        drop(storage);

        let recovered = init_storage(
            context.child("recovered_storage"),
            partition,
            TEST_STORAGE_KEY,
            TEST_NAMESPACE.to_vec(),
            public_key,
        )
        .await;

        let (recovered_epoch, recovered_state) =
            recovered.epoch().expect("epoch should recover");
        assert_eq!(recovered_epoch, Epoch::new(2));
        assert_eq!(recovered_state.round, 2);
        assert!(recovered.dealings(Epoch::zero()).is_empty());
        assert!(recovered.dealings(Epoch::new(1)).is_empty());
        assert_eq!(
            recovered.dealings(Epoch::new(2)),
            vec![(dealer, pub_msg, priv_msg)]
        );
    });
}

#[test_traced]
fn storage_recovers_no_share_observer_epoch() {
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let signers = create_test_signers(4);
        let public_key = signers[0].public_key();
        let partition = "no_share_observer_epoch";
        let epoch = Epoch::new(3);
        let participants = Set::from_iter_dedup(signers.iter().map(|s| s.public_key()));
        let (output, _) =
            commonware_cryptography::bls12381::dkg::feldman_desmedt::deal::<MinPk, _, N3f1>(
                &mut context,
                Default::default(),
                participants,
            )
            .expect("deal should succeed");

        let state = EpochState {
            round: 3,
            rng_seed: Summary::random(&mut context),
            output: Some(output),
            share: None,
        };
        let mut storage = init_storage(
            context.child("storage"),
            partition,
            TEST_STORAGE_KEY,
            TEST_NAMESPACE.to_vec(),
            public_key.clone(),
        )
        .await;
        storage
            .set_epoch(epoch, state)
            .await
            .expect("set epoch should succeed");
        drop(storage);

        let recovered = init_storage(
            context.child("recovered_storage"),
            partition,
            TEST_STORAGE_KEY,
            TEST_NAMESPACE.to_vec(),
            public_key,
        )
        .await;
        let (recovered_epoch, recovered_state) =
            recovered.epoch().expect("epoch should recover");
        assert_eq!(recovered_epoch, epoch);
        assert_eq!(recovered_state.round, 3);
        assert!(recovered_state.output.is_some());
        assert!(recovered_state.share.is_none());
    });
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
        .await
        .expect("storage init should succeed");

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
            let mut rng = TestRng::new(100);
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
        .await
        .expect("storage init should succeed");

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
        .await
        .expect("storage init should succeed");

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
        let Verdict::Valid(ack) = crypto_player.dealer_message::<N3f1>(
            dealer_signer.public_key(),
            pub_msg,
            player_priv_msg,
        ) else {
            panic!("valid ack");
        };

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
        .await
        .expect("storage init should succeed");

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
        let Verdict::Valid(ack) = crypto_player.dealer_message::<N3f1>(
            dealer_signer.public_key(),
            pub_msg,
            player_priv_msg,
        ) else {
            panic!("valid ack");
        };

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
