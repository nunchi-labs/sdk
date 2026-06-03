use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{ed25519, secp256r1, Signer as _, Verifier as _};

/// A signature verification failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SignatureError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("incompatible signature/key curves")]
    IncompatibleKey,
}

/// Signature curve supported by Nunchi account keys.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Curve {
    Ed25519 = 1,
    Secp256r1 = 2,
}

impl Curve {
    fn tag(self) -> u8 {
        self as u8
    }

    fn read(buf: &mut impl bytes::Buf) -> Result<Self, Error> {
        match u8::read(buf)? {
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::Secp256r1),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

/// A Nunchi public key tagged with its signature curve.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PublicKey {
    Ed25519(ed25519::PublicKey),
    Secp256r1(secp256r1::standard::PublicKey),
}

impl PublicKey {
    pub fn curve(&self) -> Curve {
        match self {
            Self::Ed25519(_) => Curve::Ed25519,
            Self::Secp256r1(_) => Curve::Secp256r1,
        }
    }

    pub fn verify(
        &self,
        namespace: &[u8],
        msg: &[u8],
        sig: &Signature,
    ) -> Result<(), SignatureError> {
        match (self, sig) {
            (Self::Ed25519(public), Signature::Ed25519(signature)) => public
                .verify(namespace, msg, signature)
                .then_some(())
                .ok_or(SignatureError::InvalidSignature),
            (Self::Secp256r1(public), Signature::Secp256r1(signature)) => public
                .verify(namespace, msg, signature)
                .then_some(())
                .ok_or(SignatureError::InvalidSignature),
            _ => Err(SignatureError::IncompatibleKey),
        }
    }
}

impl Write for PublicKey {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.curve().tag().write(buf);
        match self {
            Self::Ed25519(key) => key.write(buf),
            Self::Secp256r1(key) => key.write(buf),
        }
    }
}

impl Read for PublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match Curve::read(buf)? {
            Curve::Ed25519 => Ok(Self::Ed25519(ed25519::PublicKey::read(buf)?)),
            Curve::Secp256r1 => Ok(Self::Secp256r1(secp256r1::standard::PublicKey::read(buf)?)),
        }
    }
}

impl EncodeSize for PublicKey {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Ed25519(key) => key.encode_size(),
            Self::Secp256r1(key) => key.encode_size(),
        }
    }
}

/// A Nunchi private key tagged with its signature curve.
///
/// Private keys encode raw key material for controlled SDK persistence/export flows. Callers that
/// store encoded private keys should wrap the bytes with their own keystore encryption.
#[derive(Clone)]
pub enum PrivateKey {
    Ed25519(ed25519::PrivateKey),
    Secp256r1(secp256r1::standard::PrivateKey),
}

impl PrivateKey {
    pub fn ed25519_from_seed(seed: u64) -> Self {
        Self::Ed25519(ed25519::PrivateKey::from_seed(seed))
    }

    pub fn secp256r1_from_seed(seed: u64) -> Self {
        Self::Secp256r1(secp256r1::standard::PrivateKey::from_seed(seed))
    }

    /// Create a deterministic Ed25519 key for tests and examples.
    pub fn from_seed(seed: u64) -> Self {
        Self::ed25519_from_seed(seed)
    }

    pub fn curve(&self) -> Curve {
        match self {
            Self::Ed25519(_) => Curve::Ed25519,
            Self::Secp256r1(_) => Curve::Secp256r1,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Ed25519(key) => PublicKey::Ed25519(key.public_key()),
            Self::Secp256r1(key) => PublicKey::Secp256r1(key.public_key()),
        }
    }

    pub fn sign(&self, namespace: &[u8], msg: &[u8]) -> Signature {
        match self {
            Self::Ed25519(key) => Signature::Ed25519(key.sign(namespace, msg)),
            Self::Secp256r1(key) => Signature::Secp256r1(key.sign(namespace, msg)),
        }
    }
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("curve", &self.curve())
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Write for PrivateKey {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.curve().tag().write(buf);
        match self {
            Self::Ed25519(key) => key.write(buf),
            Self::Secp256r1(key) => key.write(buf),
        }
    }
}

impl Read for PrivateKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match Curve::read(buf)? {
            Curve::Ed25519 => Ok(Self::Ed25519(ed25519::PrivateKey::read(buf)?)),
            Curve::Secp256r1 => Ok(Self::Secp256r1(secp256r1::standard::PrivateKey::read(buf)?)),
        }
    }
}

impl EncodeSize for PrivateKey {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Ed25519(key) => key.encode_size(),
            Self::Secp256r1(key) => key.encode_size(),
        }
    }
}

/// A Nunchi signature tagged with its signature curve.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Signature {
    Ed25519(ed25519::Signature),
    Secp256r1(secp256r1::standard::Signature),
}

impl Signature {
    pub fn curve(&self) -> Curve {
        match self {
            Self::Ed25519(_) => Curve::Ed25519,
            Self::Secp256r1(_) => Curve::Secp256r1,
        }
    }
}

impl Write for Signature {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.curve().tag().write(buf);
        match self {
            Self::Ed25519(signature) => signature.write(buf),
            Self::Secp256r1(signature) => signature.write(buf),
        }
    }
}

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match Curve::read(buf)? {
            Curve::Ed25519 => Ok(Self::Ed25519(ed25519::Signature::read(buf)?)),
            Curve::Secp256r1 => Ok(Self::Secp256r1(secp256r1::standard::Signature::read(buf)?)),
        }
    }
}

impl EncodeSize for Signature {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Ed25519(signature) => signature.encode_size(),
            Self::Secp256r1(signature) => signature.encode_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

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
}
