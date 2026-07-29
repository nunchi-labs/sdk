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
fn truncated_ed25519_public_key_is_rejected() {
    // Valid Ed25519 tag (0x01) but zero key bytes
    let truncated = vec![0x01u8];
    assert!(PublicKey::decode(truncated.as_ref()).is_err());

    // Valid Ed25519 tag but only 16 of 32 required key bytes
    let mut truncated = vec![0x01u8];
    truncated.extend_from_slice(&[0xAB; 16]);
    assert!(PublicKey::decode(truncated.as_ref()).is_err());
}

#[test]
fn truncated_secp256r1_public_key_is_rejected() {
    // Valid Secp256r1 tag (0x02) but zero key bytes
    let truncated = vec![0x02u8];
    assert!(PublicKey::decode(truncated.as_ref()).is_err());

    // Valid Secp256r1 tag but only 10 of 33 required bytes
    let mut truncated = vec![0x02u8];
    truncated.extend_from_slice(&[0xAB; 10]);
    assert!(PublicKey::decode(truncated.as_ref()).is_err());
}

#[test]
fn truncated_ed25519_signature_is_rejected() {
    // Valid Ed25519 tag but only 16 of 64 required signature bytes
    let mut truncated = vec![0x01u8];
    truncated.extend_from_slice(&[0xAB; 16]);
    assert!(Signature::decode(truncated.as_ref()).is_err());
}

#[test]
fn truncated_secp256r1_signature_is_rejected() {
    // Valid Secp256r1 tag but only 16 of 64 required signature bytes
    let mut truncated = vec![0x02u8];
    truncated.extend_from_slice(&[0xAB; 16]);
    assert!(Signature::decode(truncated.as_ref()).is_err());
}

#[test]
fn all_zeros_ed25519_key_is_rejected() {
    // Ed25519 tag followed by 32 zero bytes (identity point)
    let mut all_zeros = vec![0x01u8];
    all_zeros.extend_from_slice(&[0x00; 32]);
    // The all-zeros key should either be rejected at decode time or fail verification.
    // We document whichever behavior the library exhibits.
    if let Ok(key) = PublicKey::decode(all_zeros.as_ref()) {
        // If decode accepts it, it must not verify any signature
        let private = PrivateKey::ed25519_from_seed(1);
        let sig = private.sign(NAMESPACE, MESSAGE);
        assert!(key.verify(NAMESPACE, MESSAGE, &sig).is_err());
    }
}

#[test]
fn all_zeros_secp256r1_key_is_rejected() {
    // Secp256r1 tag followed by 33 zero bytes (not a valid compressed point)
    let mut all_zeros = vec![0x02u8];
    all_zeros.extend_from_slice(&[0x00; 33]);
    // The all-zeros key is not a valid compressed secp256r1 point and should be rejected
    assert!(PublicKey::decode(all_zeros.as_ref()).is_err());
}

#[test]
fn empty_input_is_rejected_for_public_key() {
    assert!(PublicKey::decode([].as_ref()).is_err());
}

#[test]
fn empty_input_is_rejected_for_signature() {
    assert!(Signature::decode([].as_ref()).is_err());
}

#[test]
fn public_key_extra_trailing_bytes_rejected_by_exact_decode() {
    // Encode a valid public key, then append garbage bytes.
    // DecodeExt::decode (used by our tests) calls Read::read then checks remaining == 0.
    let private = PrivateKey::ed25519_from_seed(1);
    let mut encoded = private.public_key().encode().to_vec();
    encoded.extend_from_slice(&[0xFF, 0xFF]);
    // Using the strict DecodeExt::decode path which rejects trailing data
    assert!(PublicKey::decode(encoded.as_ref()).is_err());
}

#[test]
fn signature_extra_trailing_bytes_rejected_by_exact_decode() {
    let private = PrivateKey::ed25519_from_seed(1);
    let sig = private.sign(NAMESPACE, MESSAGE);
    let mut encoded = sig.encode().to_vec();
    encoded.extend_from_slice(&[0xFF, 0xFF]);
    assert!(Signature::decode(encoded.as_ref()).is_err());
}

#[test]
fn private_key_debug_redacts_key_material() {
    let private = PrivateKey::ed25519_from_seed(7);
    let debug = format!("{private:?}");

    assert!(debug.contains("Ed25519"));
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("Secret"));
}
