use crate::{Address, MultisigPolicy, MAX_MULTISIG_SIGNERS};
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
        account_id: &Address,
        payload: &TransactionPayload<Operation>,
    ) -> Self {
        Self {
            signer: signer.public_key(),
            signature: signer.sign(
                Operation::NAMESPACE,
                &signing_bytes(account_id, AUTH_MULTISIG, payload),
            ),
        }
    }

    pub fn verify<Operation: self::Operation>(
        &self,
        account_id: &Address,
        payload: &TransactionPayload<Operation>,
    ) -> Result<(), SignatureError> {
        self.signer.verify(
            Operation::NAMESPACE,
            &signing_bytes(account_id, AUTH_MULTISIG, payload),
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
    Single {
        signer: Box<PublicKey>,
        signature: Signature,
    },
    Multisig {
        policy: MultisigPolicy,
        signatures: Vec<AccountSignature>,
    },
}

impl Authorization {
    pub fn verify<Operation: self::Operation>(
        &self,
        account_id: &Address,
        payload: &TransactionPayload<Operation>,
    ) -> Result<(), SignatureError> {
        match self {
            Self::Single { signer, signature } => {
                if Address::external(signer) != *account_id {
                    return Err(SignatureError::IncompatibleKey);
                }
                signer.verify(
                    Operation::NAMESPACE,
                    &signing_bytes(account_id, AUTH_SINGLE, payload),
                    signature,
                )
            }
            Self::Multisig { policy, signatures } => {
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
                    signature.verify(account_id, payload)?;
                    previous_signer_key = Some(signer_key);
                }

                if seen.len() >= policy.threshold() as usize {
                    Ok(())
                } else {
                    Err(SignatureError::InvalidSignature)
                }
            }
        }
    }
}

impl Write for Authorization {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Single { signer, signature } => {
                AUTH_SINGLE.write(buf);
                signer.write(buf);
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
            AUTH_SINGLE => {
                let signer = PublicKey::read(buf)?;
                let signature = Signature::read(buf)?;
                if signer.curve() != signature.curve() {
                    return Err(Error::Invalid(
                        "authorization",
                        "signature curve does not match signer curve",
                    ));
                }
                Ok(Self::Single {
                    signer: Box::new(signer),
                    signature,
                })
            }
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
            Self::Single { signer, signature } => signer.encode_size() + signature.encode_size(),
            Self::Multisig { policy, signatures } => {
                policy.encode_size() + signatures.encode_size()
            }
        }
    }
}

/// A signed Nunchi transaction over a caller-defined operation enum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction<Operation> {
    pub account_id: Address,
    pub payload: TransactionPayload<Operation>,
    pub authorization: Authorization,
}

impl<Operation: self::Operation> Transaction<Operation> {
    pub fn sign(signer: &PrivateKey, nonce: u64, operation: Operation) -> Self {
        let signer_public = signer.public_key();
        let account_id = Address::external(&signer_public);
        let payload = TransactionPayload::new(nonce, operation);
        let authorization = Authorization::Single {
            signer: Box::new(signer_public),
            signature: signer.sign(
                Operation::NAMESPACE,
                &signing_bytes(&account_id, AUTH_SINGLE, &payload),
            ),
        };
        Self {
            account_id,
            payload,
            authorization,
        }
    }

    pub fn sign_multisig(
        account_id: Address,
        policy: MultisigPolicy,
        signers: &[&PrivateKey],
        nonce: u64,
        operation: Operation,
    ) -> Self {
        let payload = TransactionPayload::new(nonce, operation);
        let mut signatures: Vec<AccountSignature> = signers
            .iter()
            .map(|signer| AccountSignature::sign(signer, &account_id, &payload))
            .collect();
        signatures.sort_by_cached_key(|signature| signature.signer.encode().as_ref().to_vec());
        Self {
            account_id,
            payload,
            authorization: Authorization::Multisig { policy, signatures },
        }
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        self.authorization.verify(&self.account_id, &self.payload)
    }

    pub fn digest(&self) -> Digest {
        Sha256::hash(&self.encode())
    }
}

impl<Operation: Write> Write for Transaction<Operation> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.account_id.write(buf);
        self.payload.write(buf);
        self.authorization.write(buf);
    }
}

impl<Operation: Read<Cfg = ()>> Read for Transaction<Operation> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let account_id = Address::read(buf)?;
        let payload = TransactionPayload::read(buf)?;
        let authorization = Authorization::read(buf)?;

        if let Authorization::Single { signer, signature } = &authorization {
            if signer.curve() != signature.curve() {
                return Err(Error::Invalid(
                    "transaction",
                    "signature curve does not match signer curve",
                ));
            }
        }

        Ok(Self {
            account_id,
            payload,
            authorization,
        })
    }
}

impl<Operation: EncodeSize> EncodeSize for Transaction<Operation> {
    fn encode_size(&self) -> usize {
        self.account_id.encode_size()
            + self.payload.encode_size()
            + self.authorization.encode_size()
    }
}

fn signing_bytes<Operation: EncodeSize + Write>(
    account_id: &Address,
    authorization_tag: u8,
    payload: &TransactionPayload<Operation>,
) -> Vec<u8> {
    let mut bytes = account_id.encode().as_ref().to_vec();
    bytes.push(authorization_tag);
    bytes.extend_from_slice(payload.encode().as_ref());
    bytes
}
