use super::{AccountId, CoinId, CoinSpec, MultisigPolicy, PrivateKey, Signature, COINS_NAMESPACE};
use crate::account::MAX_MULTISIG_SIGNERS;
use commonware_codec::{Encode, EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_crypto::{PublicKey, SignatureError};
use std::collections::BTreeSet;

const OP_CREATE_TOKEN: u8 = 0;
const OP_MINT: u8 = 1;
const OP_BURN: u8 = 2;
const OP_TRANSFER: u8 = 3;
const AUTH_SINGLE: u8 = 0;
const AUTH_MULTISIG: u8 = 1;

/// A ledger operation authorized by a signed transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoinOperation {
    CreateToken {
        spec: CoinSpec,
    },
    Mint {
        coin: CoinId,
        to: AccountId,
        amount: u128,
    },
    Burn {
        coin: CoinId,
        from: AccountId,
        amount: u128,
    },
    Transfer {
        coin: CoinId,
        from: AccountId,
        to: AccountId,
        amount: u128,
    },
}

impl Write for CoinOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::CreateToken { spec } => {
                OP_CREATE_TOKEN.write(buf);
                spec.write(buf);
            }
            Self::Mint { coin, to, amount } => {
                OP_MINT.write(buf);
                coin.write(buf);
                to.write(buf);
                amount.write(buf);
            }
            Self::Burn { coin, from, amount } => {
                OP_BURN.write(buf);
                coin.write(buf);
                from.write(buf);
                amount.write(buf);
            }
            Self::Transfer {
                coin,
                from,
                to,
                amount,
            } => {
                OP_TRANSFER.write(buf);
                coin.write(buf);
                from.write(buf);
                to.write(buf);
                amount.write(buf);
            }
        }
    }
}

impl Read for CoinOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            OP_CREATE_TOKEN => Ok(Self::CreateToken {
                spec: CoinSpec::read(buf)?,
            }),
            OP_MINT => Ok(Self::Mint {
                coin: CoinId::read(buf)?,
                to: AccountId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            OP_BURN => Ok(Self::Burn {
                coin: CoinId::read(buf)?,
                from: AccountId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            OP_TRANSFER => Ok(Self::Transfer {
                coin: CoinId::read(buf)?,
                from: AccountId::read(buf)?,
                to: AccountId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for CoinOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::CreateToken { spec } => spec.encode_size(),
            Self::Mint { coin, to, amount } => {
                coin.encode_size() + to.encode_size() + amount.encode_size()
            }
            Self::Burn { coin, from, amount } => {
                coin.encode_size() + from.encode_size() + amount.encode_size()
            }
            Self::Transfer {
                coin,
                from,
                to,
                amount,
            } => coin.encode_size() + from.encode_size() + to.encode_size() + amount.encode_size(),
        }
    }
}

/// Signable coin transaction payload. The nonce is scoped to the account being authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionPayload {
    pub nonce: u64,
    pub operation: CoinOperation,
}

impl TransactionPayload {
    pub fn new(nonce: u64, operation: CoinOperation) -> Self {
        Self { nonce, operation }
    }
}

impl Write for TransactionPayload {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.nonce.write(buf);
        self.operation.write(buf);
    }
}

impl Read for TransactionPayload {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            nonce: u64::read(buf)?,
            operation: CoinOperation::read(buf)?,
        })
    }
}

impl EncodeSize for TransactionPayload {
    fn encode_size(&self) -> usize {
        self.nonce.encode_size() + self.operation.encode_size()
    }
}

/// A signer-specific signature over a coin transaction payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountSignature {
    pub signer: PublicKey,
    pub signature: Signature,
}

impl AccountSignature {
    pub fn sign(signer: &PrivateKey, account: &AccountId, payload: &TransactionPayload) -> Self {
        Self {
            signer: signer.public_key(),
            signature: signer.sign(COINS_NAMESPACE, &signing_bytes(account, payload)),
        }
    }

    pub fn verify(
        &self,
        account: &AccountId,
        payload: &TransactionPayload,
    ) -> Result<(), SignatureError> {
        self.signer.verify(
            COINS_NAMESPACE,
            &signing_bytes(account, payload),
            &self.signature,
        )
    }
}

impl Write for AccountSignature {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.signer.write(buf);
        self.signature.write(buf);
    }
}

impl Read for AccountSignature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let signer = PublicKey::read(buf)?;
        let signature = Signature::read(buf)?;

        if signer.curve() != signature.curve() {
            return Err(Error::Invalid(
                "account signature",
                "signature curve does not match signer curve",
            ));
        }

        Ok(Self { signer, signature })
    }
}

impl EncodeSize for AccountSignature {
    fn encode_size(&self) -> usize {
        self.signer.encode_size() + self.signature.encode_size()
    }
}

/// Authorization attached to a coin transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Authorization {
    Single(Signature),
    Multisig {
        policy: MultisigPolicy,
        signatures: Vec<AccountSignature>,
    },
}

impl Authorization {
    pub fn verify(
        &self,
        account: &AccountId,
        payload: &TransactionPayload,
    ) -> Result<(), SignatureError> {
        match (account, self) {
            (AccountId::Single(public_key), Self::Single(signature)) => {
                public_key.verify(COINS_NAMESPACE, &signing_bytes(account, payload), signature)
            }
            (AccountId::Multisig(policy_id), Self::Multisig { policy, signatures }) => {
                if &policy.id() != policy_id {
                    return Err(SignatureError::IncompatibleKey);
                }

                let mut seen = BTreeSet::new();
                let mut previous_signer_key: Option<Vec<u8>> = None;
                for signature in signatures {
                    let signer_key = signature.signer.encode().as_ref().to_vec();
                    if previous_signer_key
                        .as_ref()
                        .is_some_and(|previous| previous >= &signer_key)
                    {
                        return Err(SignatureError::IncompatibleKey);
                    }
                    if !policy.contains(&signature.signer) {
                        return Err(SignatureError::IncompatibleKey);
                    }
                    if !seen.insert(signature.signer.clone()) {
                        return Err(SignatureError::IncompatibleKey);
                    }
                    signature.verify(account, payload)?;
                    previous_signer_key = Some(signer_key);
                }

                if seen.len() >= policy.threshold() as usize {
                    Ok(())
                } else {
                    Err(SignatureError::InvalidSignature)
                }
            }
            _ => Err(SignatureError::IncompatibleKey),
        }
    }
}

impl Write for Authorization {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Single(signature) => {
                AUTH_SINGLE.write(buf);
                signature.write(buf);
            }
            Self::Multisig { policy, signatures } => {
                AUTH_MULTISIG.write(buf);
                policy.write(buf);
                signatures.write(buf);
            }
        }
    }
}

impl Read for Authorization {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            AUTH_SINGLE => Ok(Self::Single(Signature::read(buf)?)),
            AUTH_MULTISIG => Ok(Self::Multisig {
                policy: MultisigPolicy::read(buf)?,
                signatures: Vec::<AccountSignature>::read_cfg(
                    buf,
                    &(RangeCfg::new(0..=MAX_MULTISIG_SIGNERS), ()),
                )?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Authorization {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Single(signature) => signature.encode_size(),
            Self::Multisig { policy, signatures } => {
                policy.encode_size() + signatures.encode_size()
            }
        }
    }
}

/// A signed coin transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    pub account: AccountId,
    pub payload: TransactionPayload,
    pub authorization: Authorization,
}

impl Transaction {
    pub fn sign(signer: &PrivateKey, nonce: u64, operation: CoinOperation) -> Self {
        let account = AccountId::from(signer.public_key());
        let payload = TransactionPayload::new(nonce, operation);
        let authorization =
            Authorization::Single(signer.sign(COINS_NAMESPACE, &signing_bytes(&account, &payload)));
        Self {
            account,
            payload,
            authorization,
        }
    }

    pub fn sign_multisig(
        policy: MultisigPolicy,
        signers: &[&PrivateKey],
        nonce: u64,
        operation: CoinOperation,
    ) -> Self {
        let account = AccountId::multisig(&policy);
        let payload = TransactionPayload::new(nonce, operation);
        let mut signatures: Vec<AccountSignature> = signers
            .iter()
            .map(|signer| AccountSignature::sign(signer, &account, &payload))
            .collect();
        signatures.sort_by_cached_key(|signature| signature.signer.encode().as_ref().to_vec());
        Self {
            account,
            payload,
            authorization: Authorization::Multisig { policy, signatures },
        }
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        self.authorization.verify(&self.account, &self.payload)
    }

    pub fn digest(&self) -> Digest {
        Sha256::hash(&self.encode())
    }
}

impl Write for Transaction {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.account.write(buf);
        self.payload.write(buf);
        self.authorization.write(buf);
    }
}

impl Read for Transaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            account: AccountId::read(buf)?,
            payload: TransactionPayload::read(buf)?,
            authorization: Authorization::read(buf)?,
        })
    }
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        self.account.encode_size() + self.payload.encode_size() + self.authorization.encode_size()
    }
}

fn signing_bytes(account: &AccountId, payload: &TransactionPayload) -> Vec<u8> {
    let mut bytes = account.encode().as_ref().to_vec();
    bytes.extend_from_slice(payload.encode().as_ref());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> CoinSpec {
        CoinSpec::new("NCH", "Nunchi", 9, 1_000, None)
    }

    #[test]
    fn multisig_signature_order_does_not_change_digest() {
        let alice = PrivateKey::ed25519_from_seed(1);
        let bob = PrivateKey::secp256r1_from_seed(2);
        let policy = MultisigPolicy::new(2, vec![alice.public_key(), bob.public_key()]).unwrap();
        let operation = CoinOperation::CreateToken { spec: spec() };

        let first =
            Transaction::sign_multisig(policy.clone(), &[&alice, &bob], 0, operation.clone());
        let second = Transaction::sign_multisig(policy, &[&bob, &alice], 0, operation);

        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.authorization, second.authorization);
    }

    #[test]
    fn multisig_authorization_rejects_non_canonical_signature_order() {
        let alice = PrivateKey::ed25519_from_seed(1);
        let bob = PrivateKey::secp256r1_from_seed(2);
        let policy = MultisigPolicy::new(2, vec![alice.public_key(), bob.public_key()]).unwrap();
        let mut tx = Transaction::sign_multisig(
            policy,
            &[&alice, &bob],
            0,
            CoinOperation::CreateToken { spec: spec() },
        );

        let Authorization::Multisig { signatures, .. } = &mut tx.authorization else {
            panic!("expected multisig authorization");
        };
        signatures.reverse();

        assert_eq!(tx.verify(), Err(SignatureError::IncompatibleKey));
    }

    #[test]
    fn multisig_threshold_can_require_all_signers() {
        let alice = PrivateKey::ed25519_from_seed(1);
        let bob = PrivateKey::secp256r1_from_seed(2);
        let policy = MultisigPolicy::new(2, vec![alice.public_key(), bob.public_key()]).unwrap();
        let tx = Transaction::sign_multisig(
            policy,
            &[&alice, &bob],
            0,
            CoinOperation::CreateToken { spec: spec() },
        );

        assert_eq!(tx.verify(), Ok(()));
    }

    #[test]
    fn authorization_rejects_account_kind_mismatches() {
        let alice = PrivateKey::ed25519_from_seed(1);
        let bob = PrivateKey::secp256r1_from_seed(2);
        let policy = MultisigPolicy::new(2, vec![alice.public_key(), bob.public_key()]).unwrap();

        let single = Transaction::sign(&alice, 0, CoinOperation::CreateToken { spec: spec() });
        let multisig_account = AccountId::multisig(&policy);
        assert_eq!(
            single
                .authorization
                .verify(&multisig_account, &single.payload),
            Err(SignatureError::IncompatibleKey)
        );

        let multisig = Transaction::sign_multisig(
            policy,
            &[&alice, &bob],
            0,
            CoinOperation::CreateToken { spec: spec() },
        );
        let single_account = AccountId::from(alice.public_key());
        assert_eq!(
            multisig
                .authorization
                .verify(&single_account, &multisig.payload),
            Err(SignatureError::IncompatibleKey)
        );
    }
}
