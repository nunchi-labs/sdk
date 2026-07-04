use commonware_codec::{
    DecodeExt, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_crypto::PublicKey;
use std::{fmt, str::FromStr};
use thiserror::Error;

const ADDRESS_DOMAIN: &[u8] = b"nunchi/account/v1";
const ADDRESS_EXTERNAL: u8 = 0;
const ADDRESS_MULTISIG: u8 = 1;
const ADDRESS_MODULE: u8 = 2;

/// Bech32 human-readable prefix for account addresses.
pub const ADDRESS_HRP: &str = "nch";

/// A unified Nunchi account address.
///
/// Addresses are derived identifiers, not public keys. Different account kinds
/// hash typed material into the same fixed-width address space.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address(Digest);

impl Address {
    /// Derive an external-account address from a curve-tagged public key.
    pub fn external(public_key: &PublicKey) -> Self {
        Self::derive(ADDRESS_EXTERNAL, &public_key.encode())
    }

    /// Derive a multisig account's bootstrap address from its initial policy.
    pub fn multisig(policy: &MultisigPolicy) -> Self {
        Self::derive(ADDRESS_MULTISIG, &policy.encode())
    }

    /// Derive a protocol/module-owned address.
    pub fn module(domain: &'static [u8], label: &[u8]) -> Self {
        let mut material = domain.encode().as_ref().to_vec();
        material.extend_from_slice(label.encode().as_ref());
        Self::derive(ADDRESS_MODULE, &material)
    }

    /// Encode this address using Nunchi's Bech32 human-facing format.
    pub fn to_bech32(&self) -> String {
        let hrp = bech32::Hrp::parse(ADDRESS_HRP).expect("static address HRP is valid");
        bech32::encode::<bech32::Bech32>(hrp, self.encode().as_ref())
            .expect("fixed-width address always encodes")
    }

    /// Decode a Nunchi Bech32 address.
    pub fn from_bech32(value: &str) -> Result<Self, Bech32Error> {
        let (hrp, bytes) = bech32::decode(value).map_err(Bech32Error::Decode)?;
        if hrp.as_str() != ADDRESS_HRP {
            return Err(Bech32Error::WrongHrp {
                expected: ADDRESS_HRP,
                actual: hrp.to_string(),
            });
        }
        if bytes.len() != Self::SIZE {
            return Err(Bech32Error::WrongLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Self::decode(bytes.as_ref()).map_err(Bech32Error::Codec)
    }

    fn derive(kind: u8, material: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(ADDRESS_DOMAIN);
        hasher.update(&[kind]);
        hasher.update(material);
        Self(hasher.finalize())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_bech32())
    }
}

impl FromStr for Address {
    type Err = Bech32Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bech32(s)
    }
}

impl From<PublicKey> for Address {
    fn from(value: PublicKey) -> Self {
        Self::external(&value)
    }
}

impl Write for Address {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for Address {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(Digest::read(buf)?))
    }
}

impl FixedSize for Address {
    const SIZE: usize = Digest::SIZE;
}

/// Invalid Bech32 address encoding.
#[derive(Debug, Error)]
pub enum Bech32Error {
    #[error("invalid bech32 address: {0}")]
    Decode(#[from] bech32::DecodeError),
    #[error("invalid address HRP: expected {expected}, got {actual}")]
    WrongHrp {
        expected: &'static str,
        actual: String,
    },
    #[error("invalid address length: expected {expected} bytes, got {actual}")]
    WrongLength { expected: usize, actual: usize },
    #[error("invalid address bytes: {0}")]
    Codec(CodecError),
}

/// Maximum number of signers a threshold multisig policy can carry.
pub const MAX_MULTISIG_SIGNERS: usize = 256;

/// A threshold multisig policy over Nunchi public keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultisigPolicy {
    threshold: u16,
    signers: Vec<PublicKey>,
}

impl MultisigPolicy {
    pub fn new(threshold: u16, mut signers: Vec<PublicKey>) -> Result<Self, AccountPolicyError> {
        if threshold == 0 {
            return Err(AccountPolicyError::ZeroThreshold);
        }
        if signers.len() > MAX_MULTISIG_SIGNERS {
            return Err(AccountPolicyError::TooManySigners {
                max: MAX_MULTISIG_SIGNERS,
                actual: signers.len(),
            });
        }
        if threshold as usize > signers.len() {
            return Err(AccountPolicyError::ThresholdExceedsSigners {
                threshold,
                signers: signers.len(),
            });
        }
        let original_signers = signers.len();
        signers.sort_by_cached_key(|signer| signer.encode().as_ref().to_vec());
        signers.dedup();
        if signers.len() != original_signers {
            return Err(AccountPolicyError::DuplicateSigner);
        }

        Ok(Self { threshold, signers })
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn signers(&self) -> &[PublicKey] {
        &self.signers
    }

    pub fn contains(&self, signer: &PublicKey) -> bool {
        self.signers.iter().any(|candidate| candidate == signer)
    }
}

impl Write for MultisigPolicy {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.threshold.write(buf);
        self.signers.write(buf);
    }
}

impl Read for MultisigPolicy {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let threshold = u16::read(buf)?;
        let signers =
            Vec::<PublicKey>::read_cfg(buf, &(RangeCfg::new(0..=MAX_MULTISIG_SIGNERS), ()))?;
        Self::new(threshold, signers).map_err(|_| CodecError::Invalid("multisig policy", "invalid"))
    }
}

impl EncodeSize for MultisigPolicy {
    fn encode_size(&self) -> usize {
        self.threshold.encode_size() + self.signers.encode_size()
    }
}

/// Invalid account policy configuration.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AccountPolicyError {
    #[error("multisig threshold must be greater than zero")]
    ZeroThreshold,
    #[error("multisig threshold {threshold} exceeds signer count {signers}")]
    ThresholdExceedsSigners { threshold: u16, signers: usize },
    #[error("multisig signers must be unique")]
    DuplicateSigner,
    #[error("multisig has {actual} signers, but the maximum is {max}")]
    TooManySigners { max: usize, actual: usize },
}
