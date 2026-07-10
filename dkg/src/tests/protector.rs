use crate::protector::{
    InsecurePlaintextProtector, ProtectionError, SealedRecord, StorageProtector,
    SEALED_RECORD_VERSION,
};
use bytes::Bytes;

const KEY: [u8; 32] = [7; 32];
const WRONG_KEY: [u8; 32] = [8; 32];
const NONCE: [u8; 12] = [9; 12];
const PLAINTEXT: &[u8] = b"dkg recovery material";
const AD: &[u8] = b"dkg record associated data";

#[test]
fn aead_protector_seals_and_opens_record() {
    let protector = StorageProtector::new(KEY);

    let record = protector
        .seal(PLAINTEXT, AD, NONCE)
        .expect("seal should succeed");
    let opened = protector
        .open(&record, AD)
        .expect("open should succeed with same key and associated data");

    assert_eq!(record.version, SEALED_RECORD_VERSION);
    assert_eq!(record.nonce, NONCE);
    assert_ne!(record.ciphertext.as_ref(), PLAINTEXT);
    assert_eq!(opened.as_ref(), PLAINTEXT);
}

#[test]
fn aead_protector_rejects_wrong_key() {
    let protector = StorageProtector::new(KEY);
    let wrong_protector = StorageProtector::new(WRONG_KEY);
    let record = protector
        .seal(PLAINTEXT, AD, NONCE)
        .expect("seal should succeed");

    let result = wrong_protector.open(&record, AD);

    assert_eq!(result, Err(ProtectionError::Open));
}

#[test]
fn aead_protector_rejects_wrong_associated_data() {
    let protector = StorageProtector::new(KEY);
    let record = protector
        .seal(PLAINTEXT, AD, NONCE)
        .expect("seal should succeed");

    let result = protector.open(&record, b"wrong associated data");

    assert_eq!(result, Err(ProtectionError::Open));
}

#[test]
fn aead_protector_rejects_unsupported_version() {
    let protector = StorageProtector::new(KEY);
    let mut record = protector
        .seal(PLAINTEXT, AD, NONCE)
        .expect("seal should succeed");
    record.version = SEALED_RECORD_VERSION + 1;

    let result = protector.open(&record, AD);

    assert_eq!(
        result,
        Err(ProtectionError::UnsupportedVersion(SEALED_RECORD_VERSION + 1))
    );
}

#[test]
fn insecure_plaintext_protector_is_explicit_and_round_trips() {
    let protector = InsecurePlaintextProtector;

    let record = protector.seal(PLAINTEXT, AD, NONCE);
    let opened = protector
        .open(&record, AD)
        .expect("plaintext open should succeed");

    assert_eq!(record.version, SEALED_RECORD_VERSION);
    assert_eq!(record.nonce, NONCE);
    assert_eq!(record.ciphertext.as_ref(), PLAINTEXT);
    assert_eq!(opened.as_ref(), PLAINTEXT);
}

#[test]
fn insecure_plaintext_protector_rejects_unsupported_version() {
    let protector = InsecurePlaintextProtector;
    let record = SealedRecord {
        version: SEALED_RECORD_VERSION + 1,
        nonce: NONCE,
        ciphertext: Bytes::copy_from_slice(PLAINTEXT),
    };

    let result = protector.open(&record, AD);

    assert_eq!(
        result,
        Err(ProtectionError::UnsupportedVersion(SEALED_RECORD_VERSION + 1))
    );
}
