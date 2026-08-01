use crate::{
    public::N3F1_FAULT_MODEL,
    recovery::{
        derive_recovery_keys, BUNDLE_AD_DOMAIN, MANIFEST_AD_DOMAIN, RECOVERY_FORMAT_VERSION,
        RECOVERY_ENVELOPE_VERSION,
    },
    DkgProtocolConfig, DkgRecoveryBundle, EncryptedRecoveryBundle, PublicCheckpoint,
    RecoveryAssociatedData, RecoveryEpochState, RecoveryManifest, RecoveryManifestEntry,
    RecoveryProtectors, RecoveryReadCfg, STATE_FORMAT_VERSION,
};
use commonware_codec::{Encode, ReadExt};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519,
    sha256::{Digest, Sha256},
    transcript::Summary,
    Hasher, Signer,
};
use commonware_formatting::hex;
use commonware_math::algebra::Random;
use commonware_utils::{ordered::Set, test_rng, N3f1, TestRng, NZU32, NZU64};

fn fixture() -> (
    DkgRecoveryBundle<MinSig, ed25519::PublicKey>,
    RecoveryAssociatedData<ed25519::PublicKey>,
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
        namespace: b"recovery-test".to_vec(),
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
    let protocol_config_digest = config.digest().unwrap();
    let namespace_digest = Sha256::hash(&config.namespace);
    let bundle = DkgRecoveryBundle {
        format_version: RECOVERY_FORMAT_VERSION,
        protocol_config_digest,
        namespace_digest,
        validator: validator.clone(),
        partition_prefix: "recovery-test".to_owned(),
        checkpoint_digest: Sha256::hash(&checkpoint.encode()),
        checkpoint,
        created_at_ms: 123_456,
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
    let ad = RecoveryAssociatedData {
        domain: BUNDLE_AD_DOMAIN.to_owned(),
        domain_version: RECOVERY_ENVELOPE_VERSION,
        protocol_config_digest,
        namespace_digest,
        validator,
        partition_prefix: "recovery-test".to_owned(),
    };
    (bundle, ad)
}

#[test]
fn recovery_codecs_and_aead_reject_noncanonical_or_tampered_inputs() {
    let (bundle, ad) = fixture();
    let protectors = RecoveryProtectors::new([7u8; 32]);
    let cfg = RecoveryReadCfg::new(NZU32!(4), crate::MAX_SUPPORTED_MODE);
    let envelope = protectors
        .bundle
        .encrypt(&bundle, &ad, &mut TestRng::new(7))
        .unwrap();
    assert!(protectors.bundle.decrypt(&envelope, &ad, &cfg).unwrap() == bundle);

    let mut wrong_ad = ad.clone();
    wrong_ad.partition_prefix.push('x');
    assert!(protectors.bundle.decrypt::<MinSig, _>(&envelope, &wrong_ad, &cfg).is_err());
    assert!(RecoveryProtectors::new([8u8; 32]).bundle.decrypt::<MinSig, _>(&envelope, &ad, &cfg).is_err());

    let mut tampered = envelope.clone();
    tampered.nonce[0] ^= 1;
    assert!(protectors.bundle.decrypt::<MinSig, _>(&tampered, &ad, &cfg).is_err());
    let mut tampered = envelope.clone();
    let mut ciphertext = tampered.ciphertext.to_vec();
    ciphertext[0] ^= 1;
    tampered.ciphertext = ciphertext.into();
    assert!(protectors.bundle.decrypt::<MinSig, _>(&tampered, &ad, &cfg).is_err());

    let mut encoded = envelope.encode().to_vec();
    encoded.push(0);
    let mut input = encoded.as_slice();
    let _ = EncryptedRecoveryBundle::read(&mut input).unwrap();
    assert!(!input.is_empty(), "callers must reject trailing bytes");

    let manifest_ad = RecoveryAssociatedData { domain: MANIFEST_AD_DOMAIN.to_owned(), ..ad };
    let manifest = RecoveryManifest {
        format_version: RECOVERY_FORMAT_VERSION,
        generation: 1,
        entries: vec![RecoveryManifestEntry {
            bundle_digest: envelope.digest(),
            created_at_ms: bundle.created_at_ms,
            checkpoint_epoch: bundle.checkpoint.epoch,
            checkpoint_digest: bundle.checkpoint_digest,
        }],
    };
    let sealed = protectors.manifest.encrypt(&manifest, &manifest_ad, &mut TestRng::new(8)).unwrap();
    assert_eq!(protectors.manifest.decrypt(&sealed, &manifest_ad).unwrap(), manifest);
}

#[test]
fn bundle_digest_covers_complete_encrypted_envelope() {
    let (bundle, ad) = fixture();
    let envelope = RecoveryProtectors::new([7u8; 32])
        .bundle
        .encrypt(&bundle, &ad, &mut TestRng::new(7))
        .unwrap();
    let digest = envelope.digest();
    let ciphertext_only = Sha256::hash(&envelope.ciphertext);
    assert_ne!(digest, ciphertext_only);

    let mut changed = envelope.clone();
    changed.magic[0] ^= 1;
    assert_ne!(digest, changed.digest());
    let mut changed = envelope.clone();
    changed.envelope_version = changed.envelope_version.wrapping_add(1);
    assert_ne!(digest, changed.digest());
    let mut changed = envelope.clone();
    changed.nonce[0] ^= 1;
    assert_ne!(digest, changed.digest());
    let mut changed = envelope.clone();
    let mut ciphertext = changed.ciphertext.to_vec();
    ciphertext[0] ^= 1;
    changed.ciphertext = ciphertext.into();
    assert_ne!(digest, changed.digest());
}

#[test]
fn recovery_key_derivation_is_fixed_and_domain_separated() {
    let (bundle, manifest) = derive_recovery_keys([0u8; 32]);
    assert_ne!(bundle, manifest);
    assert_eq!(hex(&bundle), "2d8ef25d021c389f21d90d80e06e814c4f5ab75a4cb6ac94f8f2ab43b69db29b");
    assert_eq!(hex(&manifest), "206c60dbd7a50fd3c9093791f0d61fd8202bdf2bf9fe12da999373e0849e94d5");
}

#[test]
fn recovery_errors_and_operational_types_are_redacted() {
    let error = crate::RecoveryError::Authentication;
    let formatted = format!("{error:?} {error}");
    assert!(!formatted.contains(&hex(&Digest([7u8; 32]))));
}
