use crate::COINS_NAMESPACE;
use commonware_codec::{Encode, EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_crypto::PublicKey;
use thiserror::Error;

pub type PrivateKey = nunchi_crypto::PrivateKey;
pub type Signature = nunchi_crypto::Signature;

const ACCOUNT_ID_SINGLE: u8 = 0;
const ACCOUNT_ID_MULTISIG: u8 = 1;
const ACCOUNT_POLICY_SINGLE: u8 = 0;
const ACCOUNT_POLICY_MULTISIG: u8 = 1;
pub const MAX_MULTISIG_SIGNERS: usize = 256;

/// A coin account identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AccountId {
    Single(PublicKey),
    Multisig(Digest),
}

impl AccountId {
    pub fn single(public_key: PublicKey) -> Self {
        Self::Single(public_key)
    }

    pub fn multisig(policy: &MultisigPolicy) -> Self {
        Self::Multisig(policy.id())
    }
}

impl From<PublicKey> for AccountId {
    fn from(value: PublicKey) -> Self {
        Self::Single(value)
    }
}

impl Write for AccountId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Single(public_key) => {
                ACCOUNT_ID_SINGLE.write(buf);
                public_key.write(buf);
            }
            Self::Multisig(policy_id) => {
                ACCOUNT_ID_MULTISIG.write(buf);
                policy_id.write(buf);
            }
        }
    }
}

impl Read for AccountId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            ACCOUNT_ID_SINGLE => Ok(Self::Single(PublicKey::read(buf)?)),
            ACCOUNT_ID_MULTISIG => Ok(Self::Multisig(Digest::read(buf)?)),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for AccountId {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Single(public_key) => public_key.encode_size(),
            Self::Multisig(_) => Digest::SIZE,
        }
    }
}

/// An account authorization policy known to the coin ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountPolicy {
    Single(PublicKey),
    Multisig(MultisigPolicy),
}

impl AccountPolicy {
    pub fn single(public_key: PublicKey) -> Self {
        Self::Single(public_key)
    }

    pub fn multisig(threshold: u16, signers: Vec<PublicKey>) -> Result<Self, AccountPolicyError> {
        Ok(Self::Multisig(MultisigPolicy::new(threshold, signers)?))
    }

    pub fn id(&self) -> AccountId {
        match self {
            Self::Single(public_key) => AccountId::Single(public_key.clone()),
            Self::Multisig(policy) => AccountId::multisig(policy),
        }
    }
}

impl Write for AccountPolicy {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Single(public_key) => {
                ACCOUNT_POLICY_SINGLE.write(buf);
                public_key.write(buf);
            }
            Self::Multisig(policy) => {
                ACCOUNT_POLICY_MULTISIG.write(buf);
                policy.write(buf);
            }
        }
    }
}

impl Read for AccountPolicy {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            ACCOUNT_POLICY_SINGLE => Ok(Self::Single(PublicKey::read(buf)?)),
            ACCOUNT_POLICY_MULTISIG => Ok(Self::Multisig(MultisigPolicy::read(buf)?)),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for AccountPolicy {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Single(public_key) => public_key.encode_size(),
            Self::Multisig(policy) => policy.encode_size(),
        }
    }
}

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

    pub fn id(&self) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(COINS_NAMESPACE);
        hasher.update(b"account-policy/multisig");
        hasher.update(&self.encode());
        hasher.finalize()
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

/// An account known to the coin ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    pub id: AccountId,
    pub nonce: u64,
}

impl Account {
    pub fn new(id: AccountId, nonce: u64) -> Self {
        Self { id, nonce }
    }
}

impl Write for Account {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.nonce.write(buf);
    }
}

impl Read for Account {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            id: AccountId::read(buf)?,
            nonce: u64::read(buf)?,
        })
    }
}

impl EncodeSize for Account {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.nonce.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn account_roundtrips_with_ed25519_id() {
        let id = AccountId::from(PrivateKey::ed25519_from_seed(1).public_key());
        let account = Account::new(id, 42);

        assert_eq!(Account::decode(account.encode().as_ref()).unwrap(), account);
    }

    #[test]
    fn account_roundtrips_with_secp256r1_id() {
        let id = AccountId::from(PrivateKey::secp256r1_from_seed(1).public_key());
        let account = Account::new(id, 42);

        assert_eq!(Account::decode(account.encode().as_ref()).unwrap(), account);
    }

    #[test]
    fn multisig_policy_canonicalizes_signer_order() {
        let ed = PrivateKey::ed25519_from_seed(1).public_key();
        let secp = PrivateKey::secp256r1_from_seed(2).public_key();

        let first = MultisigPolicy::new(2, vec![ed.clone(), secp.clone()]).unwrap();
        let second = MultisigPolicy::new(2, vec![secp, ed]).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.id(), second.id());
    }

    #[test]
    fn multisig_policy_rejects_invalid_thresholds() {
        let signer = PrivateKey::ed25519_from_seed(1).public_key();

        assert_eq!(
            MultisigPolicy::new(0, vec![signer.clone()]),
            Err(AccountPolicyError::ZeroThreshold)
        );
        assert_eq!(
            MultisigPolicy::new(2, vec![signer]),
            Err(AccountPolicyError::ThresholdExceedsSigners {
                threshold: 2,
                signers: 1
            })
        );
    }

    #[test]
    fn multisig_policy_rejects_duplicate_signers() {
        let signer = PrivateKey::ed25519_from_seed(1).public_key();

        assert_eq!(
            MultisigPolicy::new(1, vec![signer.clone(), signer]),
            Err(AccountPolicyError::DuplicateSigner)
        );
    }

    #[test]
    fn multisig_policy_rejects_too_many_signers() {
        let signers = (0..=MAX_MULTISIG_SIGNERS)
            .map(|seed| PrivateKey::ed25519_from_seed(seed as u64).public_key())
            .collect();

        assert_eq!(
            MultisigPolicy::new(1, signers),
            Err(AccountPolicyError::TooManySigners {
                max: MAX_MULTISIG_SIGNERS,
                actual: MAX_MULTISIG_SIGNERS + 1
            })
        );
    }

    #[test]
    fn account_policy_roundtrips_with_mixed_curve_multisig() {
        let policy = AccountPolicy::multisig(
            2,
            vec![
                PrivateKey::ed25519_from_seed(1).public_key(),
                PrivateKey::secp256r1_from_seed(2).public_key(),
            ],
        )
        .unwrap();

        assert_eq!(
            AccountPolicy::decode(policy.encode().as_ref()).unwrap(),
            policy
        );
        assert_eq!(
            AccountId::decode(policy.id().encode().as_ref()).unwrap(),
            policy.id()
        );
    }
}
