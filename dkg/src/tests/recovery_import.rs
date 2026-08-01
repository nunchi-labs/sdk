use crate::{
    public::N3F1_FAULT_MODEL, DkgProtocolConfig, DkgRecoveryBundle, PublicCheckpoint,
    RecoveryEpochState, Storage, StorageInspection, StorageProtector, STATE_FORMAT_VERSION,
};
use commonware_codec::Encode;
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519,
    sha256::{Sha256},
    transcript::Summary,
    Hasher, Signer,
};
use commonware_math::algebra::Random;
use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use commonware_utils::{ordered::Set, test_rng, N3f1, NZU32, NZU64};

fn fixture() -> (
    ed25519::PublicKey,
    DkgRecoveryBundle<MinSig, ed25519::PublicKey>,
    PublicCheckpoint,
) {
    let signers = (0..4)
        .map(ed25519::PrivateKey::from_seed)
        .collect::<Vec<_>>();
    let participants = Set::from_iter_dedup(signers.iter().map(Signer::public_key));
    let (output, shares) = deal::<MinSig, _, N3f1>(
        test_rng(),
        Mode::NonZeroCounter,
        participants.clone(),
    )
    .unwrap();
    let config = DkgProtocolConfig {
        state_format_version: STATE_FORMAT_VERSION,
        namespace: b"import-test".to_vec(),
        epoch_length: NZU64!(10),
        participants,
        num_participants_per_round: vec![4],
        mode: Mode::NonZeroCounter,
        mode_version: 0,
        fault_model: N3F1_FAULT_MODEL,
        trusted_initial_identity: *output.public().public(),
    };
    let checkpoint = PublicCheckpoint::genesis(&config, output.clone()).unwrap();
    let validator = signers[0].public_key();
    let bundle = DkgRecoveryBundle {
        format_version: crate::recovery::RECOVERY_FORMAT_VERSION,
        protocol_config_digest: config.digest().unwrap(),
        namespace_digest: Sha256::hash(&config.namespace),
        validator: validator.clone(),
        partition_prefix: "import".to_owned(),
        checkpoint_digest: Sha256::hash(&checkpoint.encode()),
        checkpoint: checkpoint.clone(),
        created_at_ms: 10,
        epoch_state: RecoveryEpochState {
            epoch: Epoch::zero(),
            round: 0,
            rng_seed: Summary::random(test_rng()),
            output: Some(output),
            share: shares.get_value(&validator).cloned(),
        },
        reconciliation: None,
        epochs: Vec::new(),
    };
    (validator, bundle, checkpoint)
}

#[test]
fn transactional_import_is_exact_idempotent_and_fail_closed() {
    deterministic::Runner::default().start(|context| async move {
        let (validator, bundle, checkpoint) = fixture();
        let mut storage = Storage::<_, MinSig, ed25519::PublicKey>::init(
            context.child("storage"),
            "import",
            StorageProtector::new([7u8; 32]),
            b"import-test".to_vec(),
            validator,
            NZU32!(4),
            crate::MAX_SUPPORTED_MODE,
        )
        .await
        .unwrap();
        assert_eq!(storage.inspect(), StorageInspection::Empty);
        storage
            .import_recovery_bundle(bundle.clone(), &checkpoint, Sha256::hash(b"envelope-one"))
            .await
            .unwrap();
        assert_eq!(storage.inspect(), StorageInspection::Coherent);
        storage
            .import_recovery_bundle(bundle, &checkpoint, Sha256::hash(b"envelope-two"))
            .await
            .unwrap();
    });
}

#[test]
fn invalid_import_plan_performs_no_logical_writes() {
    deterministic::Runner::default().start(|context| async move {
        let (validator, mut bundle, checkpoint) = fixture();
        bundle.checkpoint_digest = Sha256::hash(b"wrong");
        let mut storage = Storage::<_, MinSig, ed25519::PublicKey>::init(
            context.child("storage"),
            "import",
            StorageProtector::new([7u8; 32]),
            b"import-test".to_vec(),
            validator,
            NZU32!(4),
            crate::MAX_SUPPORTED_MODE,
        )
        .await
        .unwrap();
        assert!(storage
            .import_recovery_bundle(bundle, &checkpoint, Sha256::hash(b"envelope"))
            .await
            .is_err());
        assert_eq!(storage.inspect(), StorageInspection::Empty);
    });
}
