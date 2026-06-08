use commonware_codec::{Encode, EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_crypto::PublicKey;
use thiserror::Error;

const ADDRESS_DOMAIN: &[u8] = b"nunchi/account/v1";
const ADDRESS_EXTERNAL: u8 = 0;
const ADDRESS_MULTISIG: u8 = 1;
const ACCOUNT_TYPE_EXTERNAL: u8 = 0;
const ACCOUNT_TYPE_MULTISIG: u8 = 1;

/// A unified Nunchi account address.
///
/// Addresses are derived identifiers, not public keys. Different account kinds
/// hash typed material into the same fixed-width address space.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address(Digest);

impl Address {
    pub fn external(public_key: &PublicKey) -> Self {
        Self::derive(ADDRESS_EXTERNAL, &public_key.encode())
    }

    pub fn multisig(policy: &MultisigPolicy) -> Self {
        Self::derive(ADDRESS_MULTISIG, &policy.encode())
    }

    fn derive(kind: u8, material: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(ADDRESS_DOMAIN);
        hasher.update(&[kind]);
        hasher.update(material);
        Self(hasher.finalize())
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

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(Digest::read(buf)?))
    }
}

impl EncodeSize for Address {
    fn encode_size(&self) -> usize {
        Digest::SIZE
    }
}

/// Authorization scheme expected for an account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountType {
    External,
    Multisig,
}

impl Write for AccountType {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::External => ACCOUNT_TYPE_EXTERNAL.write(buf),
            Self::Multisig => ACCOUNT_TYPE_MULTISIG.write(buf),
        }
    }
}

impl Read for AccountType {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            ACCOUNT_TYPE_EXTERNAL => Ok(Self::External),
            ACCOUNT_TYPE_MULTISIG => Ok(Self::Multisig),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for AccountType {
    fn encode_size(&self) -> usize {
        1
    }
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

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let threshold = u16::read(buf)?;
        let signers =
            Vec::<PublicKey>::read_cfg(buf, &(RangeCfg::new(0..=MAX_MULTISIG_SIGNERS), ()))?;
        Self::new(threshold, signers).map_err(|_| Error::Invalid("multisig policy", "invalid"))
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
