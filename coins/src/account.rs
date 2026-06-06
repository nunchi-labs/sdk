use crate::COINS_NAMESPACE;
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{Hasher, Sha256};
pub use nunchi_common::{AccountPolicyError, AccountType, MultisigPolicy};

pub type AccountId = nunchi_crypto::PublicKey;

pub type PrivateKey = nunchi_crypto::PrivateKey;
pub type Signature = nunchi_crypto::Signature;

const ACCOUNT_POLICY_MULTISIG: u8 = 1;

/// Derive a stable multisig account identifier from its initial policy.
///
/// The domain-separated derivation binds the identifier used during
/// bootstrap to the canonical initial policy. Future policy rotation must
/// use a separate operation authorized by the currently registered policy;
/// it must not reuse the bootstrap registration rules.
///
/// `COINS_NAMESPACE` is also used as the coin-operation signing namespace.
/// The `"account/multisig/v1"` tag keeps this derivation domain-separated.
pub fn multisig_account_id(policy: &MultisigPolicy) -> AccountId {
    let mut hasher = Sha256::new();
    hasher.update(COINS_NAMESPACE);
    hasher.update(b"account/multisig/v1");
    hasher.update(&policy.encode());
    AccountId::synthetic(hasher.finalize())
}

/// A coin account authorization policy persisted by the coin ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountPolicy {
    Multisig(MultisigPolicy),
}

impl AccountPolicy {
    pub fn multisig(threshold: u16, signers: Vec<AccountId>) -> Result<Self, AccountPolicyError> {
        Ok(Self::Multisig(MultisigPolicy::new(threshold, signers)?))
    }

    pub fn account_type(&self) -> AccountType {
        match self {
            Self::Multisig(_) => AccountType::Multisig,
        }
    }
}

impl Write for AccountPolicy {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
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
            ACCOUNT_POLICY_MULTISIG => Ok(Self::Multisig(MultisigPolicy::read(buf)?)),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for AccountPolicy {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Multisig(policy) => policy.encode_size(),
        }
    }
}

/// An account known to the coin ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    pub id: AccountId,
    pub kind: AccountType,
    pub nonce: u64,
}

impl Account {
    pub fn new(id: AccountId, kind: AccountType, nonce: u64) -> Self {
        Self { id, kind, nonce }
    }
}

impl Write for Account {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.kind.write(buf);
        self.nonce.write(buf);
    }
}

impl Read for Account {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            id: AccountId::read(buf)?,
            kind: AccountType::read(buf)?,
            nonce: u64::read(buf)?,
        })
    }
}

impl EncodeSize for Account {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.kind.encode_size() + self.nonce.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use nunchi_common::MAX_MULTISIG_SIGNERS;

    #[test]
    fn account_roundtrips_with_external_id() {
        let id = PrivateKey::ed25519_from_seed(1).public_key();
        let account = Account::new(id, AccountType::External, 42);

        assert_eq!(Account::decode(account.encode().as_ref()).unwrap(), account);
    }

    #[test]
    fn account_roundtrips_with_multisig_kind() {
        let id = PrivateKey::secp256r1_from_seed(1).public_key();
        let account = Account::new(id, AccountType::Multisig, 42);

        assert_eq!(Account::decode(account.encode().as_ref()).unwrap(), account);
    }

    #[test]
    fn multisig_policy_canonicalizes_signer_order() {
        let ed = PrivateKey::ed25519_from_seed(1).public_key();
        let secp = PrivateKey::secp256r1_from_seed(2).public_key();

        let first = MultisigPolicy::new(2, vec![ed.clone(), secp.clone()]).unwrap();
        let second = MultisigPolicy::new(2, vec![secp, ed]).unwrap();

        assert_eq!(first, second);
        assert_eq!(multisig_account_id(&first), multisig_account_id(&second));
        assert_eq!(
            multisig_account_id(&first).curve(),
            nunchi_crypto::Curve::Synthetic
        );
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
    fn multisig_policy_rejects_synthetic_signers() {
        let signer = PrivateKey::ed25519_from_seed(1).public_key();
        let policy = MultisigPolicy::new(1, vec![signer]).unwrap();

        assert_eq!(
            MultisigPolicy::new(1, vec![multisig_account_id(&policy)]),
            Err(AccountPolicyError::SyntheticSigner)
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
    }
}
