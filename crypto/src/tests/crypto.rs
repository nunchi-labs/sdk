use commonware_codec::{DecodeExt, Encode, Error};

use crate::{Curve, PrivateKey, PublicKey, Signature, SignatureError};

const NAMESPACE: &[u8] = b"nunchi-crypto/test";
const MESSAGE: &[u8] = b"hello nunchi";

#[test]
fn ed25519_signatures_roundtrip_and_verify() {
    let private = PrivateKey::ed25519_from_seed(7);
    let public = private.public_key();
    let signature = private.sign(NAMESPACE, MESSAGE);

    assert_eq!(public.curve(), Curve::Ed25519);
    assert_eq!(public.verify(NAMESPACE, MESSAGE, &signature), Ok(()));
    assert_eq!(PublicKey::decode(public.encode().as_ref()).unwrap(), public);
    assert_eq!(
        Signature::decode(signature.encode().as_ref()).unwrap(),
        signature
    );
}

#[test]
fn secp256r1_signatures_roundtrip_and_verify() {
    let private = PrivateKey::secp256r1_from_seed(7);
    let public = private.public_key();
    let signature = private.sign(NAMESPACE, MESSAGE);

    assert_eq!(public.curve(), Curve::Secp256r1);
    assert_eq!(public.verify(NAMESPACE, MESSAGE, &signature), Ok(()));
    assert_eq!(PublicKey::decode(public.encode().as_ref()).unwrap(), public);
    assert_eq!(
        Signature::decode(signature.encode().as_ref()).unwrap(),
        signature
    );
}

#[test]
fn mismatched_curve_fails_verification() {
    let ed_private = PrivateKey::ed25519_from_seed(7);
    let secp_public = PrivateKey::secp256r1_from_seed(7).public_key();
    let signature = ed_private.sign(NAMESPACE, MESSAGE);

    assert_eq!(
        secp_public.verify(NAMESPACE, MESSAGE, &signature),
        Err(SignatureError::IncompatibleKey)
    );
}

#[test]
fn invalid_signature_fails_verification() {
    let private = PrivateKey::ed25519_from_seed(7);
    let public = private.public_key();
    let signature = private.sign(NAMESPACE, MESSAGE);

    assert_eq!(
        public.verify(NAMESPACE, b"tampered", &signature),
        Err(SignatureError::InvalidSignature)
    );
}

#[test]
fn signatures_are_deterministic() {
    for private in [
        PrivateKey::ed25519_from_seed(7),
        PrivateKey::secp256r1_from_seed(7),
    ] {
        let sig_a = private.sign(NAMESPACE, MESSAGE);
        let sig_b = private.sign(NAMESPACE, MESSAGE);

        assert_eq!(
            sig_a,
            sig_b,
            "{:?} signing must be deterministic",
            private.curve()
        );
    }
}

#[test]
fn unknown_curve_tag_is_rejected_at_parse() {
    let mut encoded = vec![0xff];
    encoded.extend_from_slice(&[0; 32]);

    assert!(matches!(
        PublicKey::decode(encoded.as_ref()),
        Err(Error::InvalidEnum(0xff))
    ));
}

#[test]
fn private_keys_roundtrip_with_ed25519() {
    let private = PrivateKey::ed25519_from_seed(7);
    let decoded = PrivateKey::decode(private.encode().as_ref()).unwrap();
    let signature = private.sign(NAMESPACE, MESSAGE);
    let decoded_signature = decoded.sign(NAMESPACE, MESSAGE);

    assert_eq!(decoded.curve(), Curve::Ed25519);
    assert_eq!(decoded.public_key(), private.public_key());
    assert_eq!(
        decoded_signature, signature,
        "decoded Ed25519 key must produce byte-identical signatures"
    );
    assert_eq!(
        private
            .public_key()
            .verify(NAMESPACE, MESSAGE, &decoded_signature),
        Ok(())
    );
}

#[test]
fn private_keys_roundtrip_with_secp256r1() {
    let private = PrivateKey::secp256r1_from_seed(7);
    let decoded = PrivateKey::decode(private.encode().as_ref()).unwrap();
    let signature = private.sign(NAMESPACE, MESSAGE);
    let decoded_signature = decoded.sign(NAMESPACE, MESSAGE);

    assert_eq!(decoded.curve(), Curve::Secp256r1);
    assert_eq!(decoded.public_key(), private.public_key());
    assert_eq!(
        decoded_signature, signature,
        "decoded Secp256r1 key must produce byte-identical signatures"
    );
    assert_eq!(
        private
            .public_key()
            .verify(NAMESPACE, MESSAGE, &decoded_signature),
        Ok(())
    );
}

#[test]
fn private_key_debug_redacts_key_material() {
    let private = PrivateKey::ed25519_from_seed(7);
    let debug = format!("{private:?}");

    assert!(debug.contains("Ed25519"));
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("Secret"));
}
