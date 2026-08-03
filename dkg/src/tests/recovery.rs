use crate::{
    public::N3F1_FAULT_MODEL,
    recovery::{
        derive_recovery_keys, BUNDLE_AD_DOMAIN, BUNDLE_MAGIC, MANIFEST_AD_DOMAIN,
        RECOVERY_FORMAT_VERSION, RECOVERY_IMPORT_VERSION, RECOVERY_ENVELOPE_VERSION,
    },
    DkgProtocolConfig, DkgRecoveryBundle, DurableReceipt, EncryptedRecoveryBundle,
    PublicCheckpoint, RecipientState, RecoveryAssociatedData, RecoveryDealing, RecoveryDealer,
    RecoveryEpoch, RecoveryEpochState, RecoveryError, RecoveryImportPhase,
    RecoveryImportTransaction, RecoveryManifest, RecoveryManifestEntry, RecoveryMetadata,
    RecoveryProtectors, RecoveryReadCfg, STATE_FORMAT_VERSION,
};
use bytes::Bytes;
use commonware_codec::{Encode, Read, ReadExt};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{
            deal, Dealer as CryptoDealer, Info, Player as CryptoPlayer, Verdict,
        },
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

fn rich_bundle() -> DkgRecoveryBundle<MinSig, ed25519::PublicKey> {
    let (mut bundle, _) = fixture();
    let signers = (0..4)
        .map(ed25519::PrivateKey::from_seed)
        .collect::<Vec<_>>();
    let participants = Set::from_iter_dedup(signers.iter().map(Signer::public_key));
    let info = Info::new::<N3f1>(
        b"recovery-test",
        0,
        None,
        Mode::NonZeroCounter,
        participants.clone(),
        participants,
    )
    .unwrap();
    let dealer_signer = signers[0].clone();
    let dealer_pk = dealer_signer.public_key();
    let (mut dealer, public_message, private_messages) =
        CryptoDealer::<MinSig, _>::start::<N3f1>(
            test_rng(),
            info.clone(),
            dealer_signer,
            None,
        )
        .unwrap();
    let mut dealings = Vec::new();
    let mut recipients = Vec::new();
    for (index, (player_pk, private_message)) in private_messages.into_iter().enumerate() {
        let player_signer = signers
            .iter()
            .find(|signer| signer.public_key() == player_pk)
            .unwrap()
            .clone();
        let mut player = CryptoPlayer::new(info.clone(), player_signer).unwrap();
        let Verdict::Valid(ack) = player.dealer_message::<N3f1>(
            dealer_pk.clone(),
            public_message.clone(),
            private_message.clone(),
        ) else {
            panic!("valid dealing should be acknowledged");
        };
        dealer
            .receive_player_ack(player_pk.clone(), ack.clone())
            .unwrap();
        if index == 0 {
            dealings.push(RecoveryDealing {
                dealer: dealer_pk.clone(),
                public_message: public_message.clone(),
                private_message: private_message.clone(),
                acknowledgement: ack.encode(),
            });
        }
        recipients.push(if index % 2 == 0 {
            RecipientState::Acknowledged {
                player: player_pk,
                private_message,
                ack,
            }
        } else {
            RecipientState::Unacknowledged {
                player: player_pk,
                private_message,
            }
        });
    }
    let signed = dealer.finalize::<N3f1>();
    let signed_log = signed.encode();
    let (_, log) = signed.check(&info).unwrap();
    let active = RecoveryEpoch {
        epoch: Epoch::zero(),
        dealings,
        logs: vec![(dealer_pk, log)],
        local_dealer: Some(RecoveryDealer::Active {
            public_message: public_message.clone(),
            recipients: recipients.clone(),
        }),
    };
    let finalized = RecoveryEpoch {
        epoch: Epoch::new(1),
        dealings: Vec::new(),
        logs: Vec::new(),
        local_dealer: Some(RecoveryDealer::Finalized {
            public_message,
            recipients,
            signed_log,
        }),
    };
    bundle.epochs = vec![active, finalized];
    bundle
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
fn recovery_bundle_round_trips_complete_epoch_state() {
    let bundle = rich_bundle();
    bundle.validate_canonical().unwrap();
    let encoded = bundle.encode();
    let decoded = DkgRecoveryBundle::<MinSig, ed25519::PublicKey>::read_cfg(
        &mut encoded.as_ref(),
        &RecoveryReadCfg::new(NZU32!(4), crate::MAX_SUPPORTED_MODE),
    )
    .unwrap();
    assert!(decoded == bundle);
}

#[test]
fn recovery_bundle_codec_rejects_every_truncated_prefix() {
    let encoded = rich_bundle().encode();
    let cfg = RecoveryReadCfg::new(NZU32!(4), crate::MAX_SUPPORTED_MODE);
    for length in 0..encoded.len() {
        let mut input = &encoded[..length];
        assert!(
            DkgRecoveryBundle::<MinSig, ed25519::PublicKey>::read_cfg(&mut input, &cfg).is_err(),
            "truncated recovery bundle of length {length} was accepted"
        );
    }

    let mut invalid_version = encoded.to_vec();
    invalid_version[0] = RECOVERY_FORMAT_VERSION + 1;
    assert!(DkgRecoveryBundle::<MinSig, ed25519::PublicKey>::read_cfg(
        &mut invalid_version.as_slice(),
        &cfg,
    )
    .is_err());
}

#[test]
fn recovery_bundle_rejects_noncanonical_identity_and_ordering() {
    let (bundle, _) = fixture();

    let mut changed = bundle.clone();
    changed.format_version = RECOVERY_FORMAT_VERSION + 1;
    assert!(matches!(changed.validate_canonical(), Err(RecoveryError::UnsupportedFormat(_))));

    let mut changed = bundle.clone();
    changed.checkpoint.format_version = STATE_FORMAT_VERSION + 1;
    assert!(matches!(changed.validate_canonical(), Err(RecoveryError::Checkpoint)));

    let mut changed = bundle.clone();
    changed.checkpoint_digest = Sha256::hash(b"wrong checkpoint");
    assert!(matches!(changed.validate_canonical(), Err(RecoveryError::Checkpoint)));

    let mut changed = bundle.clone();
    changed.epoch_state.epoch = Epoch::new(1);
    assert!(matches!(changed.validate_canonical(), Err(RecoveryError::Epoch)));

    let mut changed = bundle.clone();
    changed.protocol_config_digest = Sha256::hash(b"wrong protocol");
    assert!(matches!(changed.validate_canonical(), Err(RecoveryError::Identity(_))));

    for prefix in [String::new(), "x".repeat(crate::recovery::MAX_PARTITION_PREFIX_LEN + 1)] {
        let mut changed = bundle.clone();
        changed.partition_prefix = prefix;
        assert!(matches!(changed.validate_canonical(), Err(RecoveryError::Bound(_))));
    }

    let mut changed = bundle.clone();
    let epoch = RecoveryEpoch {
        epoch: Epoch::zero(),
        dealings: Vec::new(),
        logs: Vec::new(),
        local_dealer: None,
    };
    changed.epochs = vec![epoch; crate::recovery::MAX_RECOVERY_EPOCHS + 1];
    assert!(matches!(changed.validate_canonical(), Err(RecoveryError::Bound(_))));

    let mut changed = rich_bundle();
    changed.epochs.reverse();
    assert!(matches!(changed.validate_canonical(), Err(RecoveryError::Identity(_))));

    let mut changed = rich_bundle();
    let duplicate = changed.epochs[0].dealings[0].clone();
    changed.epochs[0].dealings.push(duplicate);
    assert!(matches!(changed.validate_canonical(), Err(RecoveryError::Identity(_))));

    let mut changed = rich_bundle();
    let duplicate = changed.epochs[0].logs[0].clone();
    changed.epochs[0].logs.push(duplicate);
    assert!(matches!(changed.validate_canonical(), Err(RecoveryError::Identity(_))));

    let mut changed = rich_bundle();
    let Some(RecoveryDealer::Active { recipients, .. }) = changed.epochs[0].local_dealer.as_mut()
    else {
        panic!("active dealer should exist");
    };
    recipients.swap(0, 1);
    assert!(matches!(changed.validate_canonical(), Err(RecoveryError::Identity(_))));
}

#[test]
fn recovery_operational_codecs_round_trip_and_reject_invalid_variants() {
    let (_, ad) = fixture();
    let encoded = ad.encode();
    assert_eq!(
        RecoveryAssociatedData::<ed25519::PublicKey>::read_cfg(
            &mut encoded.as_ref(),
            &(crate::recovery::MAX_RECOVERY_DOMAIN_LEN, crate::recovery::MAX_PARTITION_PREFIX_LEN),
        )
        .unwrap(),
        ad
    );

    let metadata = RecoveryMetadata {
        checkpoint_epoch: Epoch::new(3),
        created_at_ms: 9,
        checkpoint_digest: Sha256::hash(b"checkpoint"),
    };
    let encoded = metadata.encode();
    assert_eq!(RecoveryMetadata::read(&mut encoded.as_ref()).unwrap(), metadata);
    let receipt = DurableReceipt {
        manifest_generation: 4,
        checkpoint_epoch: metadata.checkpoint_epoch,
        created_at_ms: metadata.created_at_ms,
        checkpoint_digest: metadata.checkpoint_digest,
        bundle_digest: Sha256::hash(b"bundle"),
    };
    let encoded = receipt.encode();
    assert_eq!(DurableReceipt::read(&mut encoded.as_ref()).unwrap(), receipt);
    let transaction = RecoveryImportTransaction {
        format_version: RECOVERY_IMPORT_VERSION,
        bundle_digest: receipt.bundle_digest,
        logical_state_digest: Sha256::hash(b"state"),
        checkpoint_digest: receipt.checkpoint_digest,
        target_epoch: receipt.checkpoint_epoch,
        phase: RecoveryImportPhase::Complete,
    };
    let encoded = transaction.encode();
    assert!(RecoveryImportTransaction::read(&mut encoded.as_ref()).unwrap() == transaction);

    assert!(RecoveryImportPhase::read(&mut &[2u8][..]).is_err());
    assert!(RecipientState::<ed25519::PublicKey>::read(&mut &[2u8][..]).is_err());
    assert!(RecoveryDealer::<MinSig, ed25519::PublicKey>::read_cfg(
        &mut &[2u8][..],
        &(NZU32!(4), crate::recovery::MAX_SIGNED_LOG_LEN),
    )
    .is_err());

    let mut invalid_transaction = transaction.encode().to_vec();
    invalid_transaction[0] = RECOVERY_IMPORT_VERSION + 1;
    assert!(RecoveryImportTransaction::read(&mut invalid_transaction.as_slice()).is_err());

    let envelope = EncryptedRecoveryBundle {
        magic: BUNDLE_MAGIC,
        envelope_version: RECOVERY_ENVELOPE_VERSION,
        nonce: [0; 12],
        ciphertext: Bytes::new(),
    };
    let mut invalid_magic = envelope.encode().to_vec();
    invalid_magic[0] ^= 1;
    assert!(EncryptedRecoveryBundle::read(&mut invalid_magic.as_slice()).is_err());
    let mut invalid_version = envelope.encode().to_vec();
    invalid_version[BUNDLE_MAGIC.len()] = RECOVERY_ENVELOPE_VERSION + 1;
    assert!(EncryptedRecoveryBundle::read(&mut invalid_version.as_slice()).is_err());

    let codec_error: RecoveryError =
        commonware_codec::Error::Invalid("recovery", "test").into();
    assert!(matches!(codec_error, RecoveryError::Codec(_)));
}

#[test]
fn recovery_manifest_rejects_invalid_version_generation_and_duplicates() {
    let entry = RecoveryManifestEntry {
        bundle_digest: Sha256::hash(b"bundle"),
        created_at_ms: 1,
        checkpoint_epoch: Epoch::zero(),
        checkpoint_digest: Sha256::hash(b"checkpoint"),
    };
    let manifest = RecoveryManifest {
        format_version: RECOVERY_FORMAT_VERSION,
        generation: 1,
        entries: vec![entry],
    };

    let mut invalid_version = manifest.encode().to_vec();
    invalid_version[0] = RECOVERY_FORMAT_VERSION + 1;
    assert!(RecoveryManifest::read(&mut invalid_version.as_slice()).is_err());

    let zero_generation = RecoveryManifest { generation: 0, ..manifest.clone() };
    assert!(RecoveryManifest::read(&mut zero_generation.encode().as_ref()).is_err());

    let duplicates = RecoveryManifest { entries: vec![entry, entry], ..manifest };
    assert!(RecoveryManifest::read(&mut duplicates.encode().as_ref()).is_err());
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
