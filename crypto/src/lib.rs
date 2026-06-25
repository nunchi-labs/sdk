commonware_macros::stability_scope!(ALPHA {
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{ed25519, secp256r1, Signer as _, Verifier as _};

#[cfg(test)]
mod tests;

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
});
