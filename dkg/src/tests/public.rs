use crate::{
    public_transition, transition_logs, validate_anchor, validate_share,
    DkgProtocolConfig, PublicCheckpoint, STATE_FORMAT_VERSION,
};
use commonware_codec::{Encode, Read};
use commonware_consensus::types::{Epoch, Epocher, FixedEpocher, Height};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{deal, Dealer, Player, Verdict},
        primitives::{
            group::{Private, Scalar, Share},
            sharing::Mode,
            variant::MinSig,
        },
    },
    ed25519::{self, Batch},
    Signer,
};
use commonware_math::algebra::Ring;
use commonware_parallel::Sequential;
use commonware_utils::{
    ordered::Set, test_rng, N3f1, Participant, TestRng, NZU64,
};

fn setup() -> (
    DkgProtocolConfig,
    Vec<ed25519::PrivateKey>,
    PublicCheckpoint,
    commonware_utils::ordered::Map<ed25519::PublicKey, Share>,
) {
    let signers = (0..4)
        .map(ed25519::PrivateKey::from_seed)
        .collect::<Vec<_>>();
    let participants =
        Set::from_iter_dedup(signers.iter().map(Signer::public_key));
    let (output, shares) = deal::<MinSig, _, N3f1>(
        test_rng(),
        Mode::NonZeroCounter,
        participants.clone(),
    )
    .unwrap();
    let config = DkgProtocolConfig {
        state_format_version: STATE_FORMAT_VERSION,
        namespace: b"nunchi-public-state-test".to_vec(),
        epoch_length: NZU64!(10),
        participants,
        num_participants_per_round: vec![4],
        mode: Mode::NonZeroCounter,
        mode_version: 0,
        fault_model: crate::public::N3F1_FAULT_MODEL,
        trusted_initial_identity: *output.public().public(),
    };
    let checkpoint = PublicCheckpoint::genesis(&config, output).unwrap();
    (config, signers, checkpoint, shares)
}

#[test]
fn protocol_digest_is_canonical_and_binds_configuration() {
    let (config, _, _, _) = setup();
    let mut same = config.clone();
    assert_eq!(config.digest().unwrap(), same.digest().unwrap());
    same.epoch_length = NZU64!(11);
    assert_ne!(config.digest().unwrap(), same.digest().unwrap());
    assert_eq!(
        commonware_formatting::hex(&config.digest().unwrap()),
        "cef10ca10a298de2fc304c09729e8e846ed682db984a66a8d5c09cd8a1be8b0d"
    );
}

#[test]
fn checkpoint_codec_is_bounded_and_rejects_wrong_format() {
    let (config, _, checkpoint, _) = setup();
    let encoded = checkpoint.encode();
    let mut input = encoded.as_ref();
    let decoded = PublicCheckpoint::read_cfg(
        &mut input,
        &(
            commonware_utils::NZU32!(config.max_participants_per_round()),
            crate::MAX_SUPPORTED_MODE,
        ),
    )
    .unwrap();
    assert_eq!(decoded, checkpoint);
    assert!(input.is_empty());

    let mut malformed = encoded.to_vec();
    malformed[0] ^= 1;
    assert!(PublicCheckpoint::<MinSig, ed25519::PublicKey>::read_cfg(
        &mut malformed.as_slice(),
        &(
            commonware_utils::NZU32!(config.max_participants_per_round()),
            crate::MAX_SUPPORTED_MODE,
        ),
    )
    .is_err());
}

#[test]
fn failed_public_transition_advances_epoch_only() {
    let (config, _, checkpoint, _) = setup();
    let boundary = FixedEpocher::new(config.epoch_length)
        .last(Epoch::zero())
        .unwrap();
    let transition = transition_logs::<_, _, Batch>(
        &config,
        &checkpoint,
        Default::default(),
        boundary,
        &mut test_rng(),
        &Sequential,
    )
    .unwrap();
    assert!(!transition.succeeded);
    assert_eq!(transition.checkpoint.epoch, Epoch::new(1));
    assert_eq!(
        transition.checkpoint.successful_round,
        checkpoint.successful_round
    );
    assert_eq!(transition.checkpoint.output, checkpoint.output);
    assert_eq!(transition.checkpoint.activation_height, boundary);
    validate_anchor(&config, &transition.checkpoint, boundary).unwrap();
}

#[test]
fn successful_transition_and_identical_duplicate_are_deterministic() {
    let (config, signers, checkpoint, shares) = setup();
    let info = config.round_info(&checkpoint).unwrap();
    let mut logs = Vec::new();
    for (dealer_index, signer) in signers.iter().enumerate() {
        let dealer_pk = signer.public_key();
        let (mut dealer, public, private) = Dealer::<MinSig, _>::start::<N3f1>(
            TestRng::new(100 + dealer_index as u64),
            info.clone(),
            signer.clone(),
            shares.get_value(&dealer_pk).cloned(),
        )
        .unwrap();
        for (player_pk, private) in private {
            let player_signer = signers
                .iter()
                .find(|candidate| candidate.public_key() == player_pk)
                .unwrap()
                .clone();
            let mut player = Player::new(info.clone(), player_signer).unwrap();
            let Verdict::Valid(ack) =
                player.dealer_message::<N3f1>(dealer_pk.clone(), public.clone(), private)
            else {
                panic!("valid dealing should be acknowledged");
            };
            dealer.receive_player_ack(player_pk, ack).unwrap();
        }
        logs.push(dealer.finalize::<N3f1>());
    }
    logs.push(logs[0].clone());
    let boundary = FixedEpocher::new(config.epoch_length)
        .last(Epoch::zero())
        .unwrap();
    let transition = public_transition::<_, _, ed25519::PrivateKey, Batch>(
        &config,
        &checkpoint,
        logs,
        boundary,
        &mut test_rng(),
        &Sequential,
    )
    .unwrap();
    assert!(transition.succeeded);
    assert_eq!(transition.checkpoint.epoch, Epoch::new(1));
    assert_eq!(transition.checkpoint.successful_round, 1);
}

#[test]
fn local_share_validation_is_checked_without_panicking() {
    let (_, signers, checkpoint, shares) = setup();
    let participant = signers[0].public_key();
    let share = shares.get_value(&participant).unwrap();
    validate_share(&checkpoint.output, &participant, share).unwrap();

    let invalid = Share::new(
        Participant::new(share.index.get()),
        Private::new(Scalar::one()),
    );
    assert!(validate_share(&checkpoint.output, &participant, &invalid).is_err());
    let wrong_index = Share::new(Participant::new(1), share.private.clone());
    assert!(validate_share(&checkpoint.output, &participant, &wrong_index).is_err());
    assert!(validate_anchor(&setup().0, &checkpoint, Height::new(10)).is_err());
}
