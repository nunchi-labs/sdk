use crate::{AccountType, MultisigPolicy, MAX_MULTISIG_SIGNERS};
use commonware_codec::{Encode, EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_crypto::{PrivateKey, PublicKey, Signature, SignatureError};
use std::collections::BTreeSet;

const AUTH_SINGLE: u8 = 0;
const AUTH_MULTISIG: u8 = 1;

/// Operation types that can be carried by signed Nunchi transactions.
pub trait Operation: EncodeSize + Read<Cfg = ()> + Write {
    /// Domain separator used when signing and verifying transactions for this operation type.
    const NAMESPACE: &'static [u8];
}

/// Signable transaction payload. The nonce is scoped to the account being authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionPayload<Operation> {
    pub nonce: u64,
    pub operation: Operation,
}

impl<Operation> TransactionPayload<Operation> {
    pub fn new(nonce: u64, operation: Operation) -> Self {
        Self { nonce, operation }
    }
}

impl<Operation: Write> Write for TransactionPayload<Operation> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.nonce.write(buf);
        self.operation.write(buf);
    }
}

impl<Operation: Read<Cfg = ()>> Read for TransactionPayload<Operation> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            nonce: u64::read(buf)?,
            operation: Operation::read(buf)?,
        })
    }
}

impl<Operation: EncodeSize> EncodeSize for TransactionPayload<Operation> {
    fn encode_size(&self) -> usize {
        self.nonce.encode_size() + self.operation.encode_size()
    }
}

/// A signer-specific signature over a transaction payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountSignature {
    pub signer: PublicKey,
    pub signature: Signature,
}

impl AccountSignature {
    pub fn sign<Operation: self::Operation>(
        signer: &PrivateKey,
        account_id: &PublicKey,
        account_type: AccountType,
        payload: &TransactionPayload<Operation>,
    ) -> Self {
        Self {
            signer: signer.public_key(),
            signature: signer.sign(
                Operation::NAMESPACE,
                &signing_bytes(account_id, account_type, payload),
            ),
        }
    }

    pub fn verify<Operation: self::Operation>(
        &self,
        account_id: &PublicKey,
        account_type: AccountType,
        payload: &TransactionPayload<Operation>,
    ) -> Result<(), SignatureError> {
        self.signer.verify(
            Operation::NAMESPACE,
            &signing_bytes(account_id, account_type, payload),
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

/// Authorization attached to a Nunchi transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Authorization {
    Single(Signature),
    Multisig {
        policy: MultisigPolicy,
        signatures: Vec<AccountSignature>,
    },
}

impl Authorization {
    pub fn verify<Operation: self::Operation>(
        &self,
        account_id: &PublicKey,
        account_type: AccountType,
        payload: &TransactionPayload<Operation>,
    ) -> Result<(), SignatureError> {
        match (account_type, self) {
            (AccountType::External, Self::Single(signature)) => account_id.verify(
                Operation::NAMESPACE,
                &signing_bytes(account_id, account_type, payload),
                signature,
            ),
            (AccountType::Multisig, Self::Multisig { policy, signatures }) => {
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
                    signature.verify(account_id, account_type, payload)?;
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

/// A signed Nunchi transaction over a caller-defined operation enum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction<Operation> {
    pub account_id: PublicKey,
    pub account_type: AccountType,
    pub payload: TransactionPayload<Operation>,
    pub authorization: Authorization,
}

impl<Operation: self::Operation> Transaction<Operation> {
    pub fn sign(signer: &PrivateKey, nonce: u64, operation: Operation) -> Self {
        let account_id = signer.public_key();
        let account_type = AccountType::External;
        let payload = TransactionPayload::new(nonce, operation);
        let authorization = Authorization::Single(signer.sign(
            Operation::NAMESPACE,
            &signing_bytes(&account_id, account_type, &payload),
        ));
        Self {
            account_id,
            account_type,
            payload,
            authorization,
        }
    }

    pub fn sign_multisig(
        account_id: PublicKey,
        policy: MultisigPolicy,
        signers: &[&PrivateKey],
        nonce: u64,
        operation: Operation,
    ) -> Self {
        let account_type = AccountType::Multisig;
        let payload = TransactionPayload::new(nonce, operation);
        let mut signatures: Vec<AccountSignature> = signers
            .iter()
            .map(|signer| AccountSignature::sign(signer, &account_id, account_type, &payload))
            .collect();
        signatures.sort_by_cached_key(|signature| signature.signer.encode().as_ref().to_vec());
        Self {
            account_id,
            account_type,
            payload,
            authorization: Authorization::Multisig { policy, signatures },
        }
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        self.authorization
            .verify(&self.account_id, self.account_type, &self.payload)
    }

    pub fn digest(&self) -> Digest {
        Sha256::hash(&self.encode())
    }
}

impl<Operation: Write> Write for Transaction<Operation> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.account_id.write(buf);
        self.account_type.write(buf);
        self.payload.write(buf);
        self.authorization.write(buf);
    }
}

impl<Operation: Read<Cfg = ()>> Read for Transaction<Operation> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let account_id = PublicKey::read(buf)?;
        let account_type = AccountType::read(buf)?;
        let payload = TransactionPayload::read(buf)?;
        let authorization = Authorization::read(buf)?;

        if let (AccountType::External, Authorization::Single(signature)) =
            (account_type, &authorization)
        {
            if account_id.curve() != signature.curve() {
                return Err(Error::Invalid(
                    "transaction",
                    "signature curve does not match account curve",
                ));
            }
        }

        Ok(Self {
            account_id,
            account_type,
            payload,
            authorization,
        })
    }
}

impl<Operation: EncodeSize> EncodeSize for Transaction<Operation> {
    fn encode_size(&self) -> usize {
        self.account_id.encode_size()
            + self.account_type.encode_size()
            + self.payload.encode_size()
            + self.authorization.encode_size()
    }
}

fn signing_bytes<Operation: EncodeSize + Write>(
    account_id: &PublicKey,
    account_type: AccountType,
    payload: &TransactionPayload<Operation>,
) -> Vec<u8> {
    let mut bytes = account_id.encode().as_ref().to_vec();
    bytes.extend_from_slice(account_type.encode().as_ref());
    bytes.extend_from_slice(payload.encode().as_ref());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestOperation(u8);

    impl Write for TestOperation {
        fn write(&self, buf: &mut impl bytes::BufMut) {
            self.0.write(buf);
        }
    }

    impl Read for TestOperation {
        type Cfg = ();

        fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
            Ok(Self(u8::read(buf)?))
        }
    }

    impl EncodeSize for TestOperation {
        fn encode_size(&self) -> usize {
            self.0.encode_size()
        }
    }

    impl Operation for TestOperation {
        const NAMESPACE: &'static [u8] = b"nunchi-common/test-operation";
    }

    #[test]
    fn ed25519_transaction_signs_verifies_and_roundtrips() {
        let signer = PrivateKey::ed25519_from_seed(7);
        let tx = Transaction::sign(&signer, 3, TestOperation(42));

        assert_eq!(tx.account_id, signer.public_key());
        assert_eq!(tx.account_type, AccountType::External);
        assert_eq!(tx.verify(), Ok(()));
        assert_eq!(Transaction::decode(tx.encode().as_ref()).unwrap(), tx);
    }

    #[test]
    fn secp256r1_transaction_signs_verifies_and_roundtrips() {
        let signer = PrivateKey::secp256r1_from_seed(7);
        let tx = Transaction::sign(&signer, 3, TestOperation(42));

        assert_eq!(tx.account_id, signer.public_key());
        assert_eq!(tx.account_type, AccountType::External);
        assert_eq!(tx.verify(), Ok(()));
        assert_eq!(Transaction::decode(tx.encode().as_ref()).unwrap(), tx);
    }

    #[test]
    fn transaction_verification_rejects_tampered_payload() {
        let signer = PrivateKey::ed25519_from_seed(7);
        let mut tx = Transaction::sign(&signer, 3, TestOperation(42));
        tx.payload.operation = TestOperation(43);

        assert_eq!(tx.verify(), Err(SignatureError::InvalidSignature));
    }

    #[test]
    fn transaction_verification_rejects_mismatched_signature_curve() {
        let signer = PrivateKey::ed25519_from_seed(7);
        let other = PrivateKey::secp256r1_from_seed(9);
        let mut tx = Transaction::sign(&signer, 3, TestOperation(42));
        tx.authorization =
            Authorization::Single(other.sign(TestOperation::NAMESPACE, &tx.payload.encode()));

        assert_eq!(tx.verify(), Err(SignatureError::IncompatibleKey));
    }

    #[test]
    fn transaction_decode_rejects_mismatched_signature_curve() {
        let signer = PrivateKey::ed25519_from_seed(7);
        let other = PrivateKey::secp256r1_from_seed(9);
        let mut tx = Transaction::sign(&signer, 3, TestOperation(42));
        tx.authorization =
            Authorization::Single(other.sign(TestOperation::NAMESPACE, &tx.payload.encode()));

        assert!(Transaction::<TestOperation>::decode(tx.encode().as_ref()).is_err());
    }

    #[test]
    fn multisig_transaction_signs_verifies_and_roundtrips() {
        let alice = PrivateKey::ed25519_from_seed(1);
        let bob = PrivateKey::secp256r1_from_seed(2);
        let account_id = PrivateKey::ed25519_from_seed(99).public_key();
        let policy = MultisigPolicy::new(2, vec![alice.public_key(), bob.public_key()]).unwrap();
        let tx =
            Transaction::sign_multisig(account_id, policy, &[&alice, &bob], 0, TestOperation(42));

        assert_eq!(tx.account_type, AccountType::Multisig);
        assert_eq!(tx.verify(), Ok(()));
        assert_eq!(Transaction::decode(tx.encode().as_ref()).unwrap(), tx);
    }

    #[test]
    fn multisig_authorization_rejects_non_canonical_signature_order() {
        let alice = PrivateKey::ed25519_from_seed(1);
        let bob = PrivateKey::secp256r1_from_seed(2);
        let account_id = PrivateKey::ed25519_from_seed(99).public_key();
        let policy = MultisigPolicy::new(2, vec![alice.public_key(), bob.public_key()]).unwrap();
        let mut tx =
            Transaction::sign_multisig(account_id, policy, &[&alice, &bob], 0, TestOperation(42));

        let Authorization::Multisig { signatures, .. } = &mut tx.authorization else {
            panic!("expected multisig authorization");
        };
        signatures.reverse();

        assert_eq!(tx.verify(), Err(SignatureError::IncompatibleKey));
    }

    #[test]
    fn authorization_rejects_account_type_mismatches() {
        let alice = PrivateKey::ed25519_from_seed(1);
        let bob = PrivateKey::secp256r1_from_seed(2);
        let account_id = PrivateKey::ed25519_from_seed(99).public_key();
        let policy = MultisigPolicy::new(2, vec![alice.public_key(), bob.public_key()]).unwrap();

        let single = Transaction::sign(&alice, 0, TestOperation(42));
        assert_eq!(
            single
                .authorization
                .verify(&single.account_id, AccountType::Multisig, &single.payload),
            Err(SignatureError::IncompatibleKey)
        );

        let multisig =
            Transaction::sign_multisig(account_id, policy, &[&alice, &bob], 0, TestOperation(42));
        assert_eq!(
            multisig.authorization.verify(
                &multisig.account_id,
                AccountType::External,
                &multisig.payload
            ),
            Err(SignatureError::IncompatibleKey)
        );
    }
}
