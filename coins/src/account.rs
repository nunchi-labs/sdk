use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
pub use nunchi_common::{AccountPolicyError, MultisigPolicy};
use nunchi_crypto::PublicKey;

pub type Address = nunchi_common::Address;

pub type PrivateKey = nunchi_crypto::PrivateKey;
pub type Signature = nunchi_crypto::Signature;

const ACCOUNT_POLICY_MULTISIG: u8 = 1;
const ACCOUNT_TYPE_EXTERNAL: u8 = 0;
const ACCOUNT_TYPE_MULTISIG: u8 = 1;

/// Authorization scheme currently registered for a coin account.
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

/// Derive a stable multisig address from its initial policy.
pub fn multisig_account_id(policy: &MultisigPolicy) -> Address {
    Address::multisig(policy)
}

/// Derive an external account address from a public key.
pub fn external_account_id(public_key: &PublicKey) -> Address {
    Address::external(public_key)
}

/// A coin account authorization policy persisted by the coin ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountPolicy {
    Multisig(MultisigPolicy),
}

impl AccountPolicy {
    pub fn multisig(threshold: u16, signers: Vec<PublicKey>) -> Result<Self, AccountPolicyError> {
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
    pub id: Address,
    pub kind: AccountType,
    pub nonce: u64,
}

impl Account {
    pub fn new(id: Address, kind: AccountType, nonce: u64) -> Self {
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
            id: Address::read(buf)?,
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
