use commonware_codec::{DecodeExt, Encode, Error};

use crate::{Curve, PrivateKey, PublicKey, Signature, SignatureError};

const NAMESPACE: &[u8] = b"nunchi-crypto/test";
const MESSAGE: &[u8] = b"hello nunchi";

/// Seeds used across tests to increase key-space coverage. Includes zero, small values,
/// the original default (7), a mid-range value, and values near `u64::MAX` to exercise
/// potential edge cases in key derivation.
const SEEDS: &[u64] = &[0, 1, 7, 42, u64::MAX - 1, u64::MAX];

#[test]
fn ed25519_signatures_roundtrip_and_verify() {
    for &seed in SEEDS {
        let private = PrivateKey::ed25519_from_seed(seed);
        let public = private.public_key();
        let signature = private.sign(NAMESPACE, MESSAGE);

        assert_eq!(public.curve(), Curve::Ed25519);
        assert_eq!(
            public.verify(NAMESPACE, MESSAGE, &signature),
            Ok(()),
            "ed25519 verify failed for seed {seed}"
        );
        assert_eq!(
            PublicKey::decode(public.encode().as_ref()).unwrap(),
            public,
            "ed25519 public key roundtrip failed for seed {seed}"
        );
        assert_eq!(
            Signature::decode(signature.encode().as_ref()).unwrap(),
            signature,
            "ed25519 signature roundtrip failed for seed {seed}"
        );
    }
}

#[test]
fn secp256r1_signatures_roundtrip_and_verify() {
    for &seed in SEEDS {
        let private = PrivateKey::secp256r1_from_seed(seed);
        let public = private.public_key();
        let signature = private.sign(NAMESPACE, MESSAGE);

        assert_eq!(public.curve(), Curve::Secp256r1);
        assert_eq!(
            public.verify(NAMESPACE, MESSAGE, &signature),
            Ok(()),
            "secp256r1 verify failed for seed {seed}"
        );
        assert_eq!(
            PublicKey::decode(public.encode().as_ref()).unwrap(),
            public,
            "secp256r1 public key roundtrip failed for seed {seed}"
        );
        assert_eq!(
            Signature::decode(signature.encode().as_ref()).unwrap(),
            signature,
            "secp256r1 signature roundtrip failed for seed {seed}"
        );
    }
}

#[test]
fn mismatched_curve_fails_verification() {
    // Use different seeds for each curve so the test does not accidentally pass
    // due to shared intermediate values from identical seed derivation.
    let ed_private = PrivateKey::ed25519_from_seed(1);
    let secp_public = PrivateKey::secp256r1_from_seed(2).public_key();
    let signature = ed_private.sign(NAMESPACE, MESSAGE);

    assert_eq!(
        secp_public.verify(NAMESPACE, MESSAGE, &signature),
        Err(SignatureError::IncompatibleKey)
    );
}

#[test]
fn invalid_signature_fails_verification() {
    for &seed in SEEDS {
        let private = PrivateKey::ed25519_from_seed(seed);
        let public = private.public_key();
        let signature = private.sign(NAMESPACE, MESSAGE);

        assert_eq!(
            public.verify(NAMESPACE, b"tampered", &signature),
            Err(SignatureError::InvalidSignature),
            "tampered message should fail for seed {seed}"
        );
    }
}

#[test]
fn signatures_are_deterministic() {
    for &seed in SEEDS {
        for private in [
            PrivateKey::ed25519_from_seed(seed),
            PrivateKey::secp256r1_from_seed(seed),
        ] {
            let sig_a = private.sign(NAMESPACE, MESSAGE);
            let sig_b = private.sign(NAMESPACE, MESSAGE);

            assert_eq!(
                sig_a,
                sig_b,
                "{:?} signing must be deterministic (seed {seed})",
                private.curve()
            );
        }
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
    for &seed in SEEDS {
        let private = PrivateKey::ed25519_from_seed(seed);
        let decoded = PrivateKey::decode(private.encode().as_ref()).unwrap();
        let signature = private.sign(NAMESPACE, MESSAGE);
        let decoded_signature = decoded.sign(NAMESPACE, MESSAGE);

        assert_eq!(decoded.curve(), Curve::Ed25519);
        assert_eq!(
            decoded.public_key(),
            private.public_key(),
            "ed25519 private key roundtrip public key mismatch for seed {seed}"
        );
        assert_eq!(
            decoded_signature, signature,
            "decoded Ed25519 key must produce byte-identical signatures (seed {seed})"
        );
        assert_eq!(
            private
                .public_key()
                .verify(NAMESPACE, MESSAGE, &decoded_signature),
            Ok(()),
            "ed25519 decoded signature verify failed for seed {seed}"
        );
    }
}

#[test]
fn private_keys_roundtrip_with_secp256r1() {
    for &seed in SEEDS {
        let private = PrivateKey::secp256r1_from_seed(seed);
        let decoded = PrivateKey::decode(private.encode().as_ref()).unwrap();
        let signature = private.sign(NAMESPACE, MESSAGE);
        let decoded_signature = decoded.sign(NAMESPACE, MESSAGE);

        assert_eq!(decoded.curve(), Curve::Secp256r1);
        assert_eq!(
            decoded.public_key(),
            private.public_key(),
            "secp256r1 private key roundtrip public key mismatch for seed {seed}"
        );
        assert_eq!(
            decoded_signature, signature,
            "decoded Secp256r1 key must produce byte-identical signatures (seed {seed})"
        );
        assert_eq!(
            private
                .public_key()
                .verify(NAMESPACE, MESSAGE, &decoded_signature),
            Ok(()),
            "secp256r1 decoded signature verify failed for seed {seed}"
        );
    }
}

#[test]
fn private_key_debug_redacts_key_material() {
    let private = PrivateKey::ed25519_from_seed(7);
    let debug = format!("{private:?}");

    assert!(debug.contains("Ed25519"));
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("Secret"));
}
