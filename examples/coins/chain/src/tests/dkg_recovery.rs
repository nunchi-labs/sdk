use crate::dkg_recovery::{FileRecoveryError, FileRecoveryWorker};
use bytes::Bytes;
use commonware_consensus::types::Epoch;
use commonware_cryptography::{ed25519, sha256::Digest, Signer};
use nunchi_dkg::{
    recovery::{MANIFEST_AD_DOMAIN, RECOVERY_ENVELOPE_VERSION}, EncryptedRecoveryBundle,
    RecoveryAssociatedData, RecoveryMetadata, RecoveryProtectors, RecoveryPublication,
    RecoverySink,
};
use std::{fs, path::Path};

fn secure_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn associated_data() -> RecoveryAssociatedData<ed25519::PublicKey> {
    RecoveryAssociatedData {
        domain: MANIFEST_AD_DOMAIN.to_owned(),
        domain_version: RECOVERY_ENVELOPE_VERSION,
        protocol_config_digest: Digest([1u8; 32]),
        namespace_digest: Digest([2u8; 32]),
        validator: ed25519::PrivateKey::from_seed(7).public_key(),
        partition_prefix: "worker-test".to_owned(),
    }
}

fn envelope(marker: u8) -> EncryptedRecoveryBundle {
    EncryptedRecoveryBundle {
        magic: nunchi_dkg::recovery::BUNDLE_MAGIC,
        envelope_version: RECOVERY_ENVELOPE_VERSION,
        nonce: [marker; 12],
        ciphertext: Bytes::from(vec![marker; 32]),
    }
}

fn metadata(marker: u8) -> RecoveryMetadata {
    RecoveryMetadata {
        checkpoint_epoch: Epoch::new(marker as u64),
        created_at_ms: marker as u64,
        checkpoint_digest: Digest([marker; 32]),
    }
}

#[tokio::test]
async fn file_worker_is_fifo_exclusive_supervised_and_idempotent() {
    let root = tempfile::tempdir().unwrap();
    let storage = root.path().join("storage");
    let recovery = root.path().join("recovery");
    secure_directory(&storage);
    secure_directory(&recovery);
    fs::remove_dir(&storage).unwrap();
    let protectors = RecoveryProtectors::new([7u8; 32]);
    let (worker, mut sink) = FileRecoveryWorker::start(
        recovery.clone(),
        storage.clone(),
        protectors.manifest.clone(),
        associated_data(),
    )
    .await
    .unwrap();

    let second = FileRecoveryWorker::start(
        recovery.clone(),
        storage.clone(),
        protectors.manifest.clone(),
        associated_data(),
    )
    .await;
    assert!(matches!(second, Err(FileRecoveryError::LockConflict)));

    let first = sink
        .publish(RecoveryPublication::GenesisFirst, envelope(1), metadata(1))
        .await
        .unwrap();
    let repeated = sink
        .publish(RecoveryPublication::Runtime, envelope(1), metadata(1))
        .await
        .unwrap();
    assert_eq!(first, repeated);
    assert_eq!(sink.load_candidates().await.unwrap().len(), 1);
    worker.shutdown().await.unwrap();

    let (worker, _) = FileRecoveryWorker::start(
        recovery,
        storage,
        protectors.manifest,
        associated_data(),
    )
    .await
    .unwrap();
    worker.shutdown().await.unwrap();
}

#[tokio::test]
async fn manifest_publication_remains_recoverable_at_every_crash_point() {
    let root = tempfile::tempdir().unwrap();
    let storage = root.path().join("storage");
    let recovery = root.path().join("recovery");
    secure_directory(&storage);
    secure_directory(&recovery);
    let protectors = RecoveryProtectors::new([9u8; 32]);
    let (worker, mut sink) = FileRecoveryWorker::start(
        recovery,
        storage,
        protectors.manifest,
        associated_data(),
    )
    .await
    .unwrap();
    for marker in 1..=4 {
        let operation = if marker == 1 {
            RecoveryPublication::GenesisFirst
        } else {
            RecoveryPublication::Runtime
        };
        sink.publish(operation, envelope(marker), metadata(marker))
            .await
            .unwrap();
    }
    let candidates = sink.load_candidates().await.unwrap();
    assert_eq!(candidates.len(), 3);
    assert_eq!(candidates[0].1.checkpoint_epoch, Epoch::new(4));
    assert_eq!(candidates[2].1.checkpoint_epoch, Epoch::new(2));
    worker.shutdown().await.unwrap();
}
