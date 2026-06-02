use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey, Signature},
    sha256::Digest,
    Hasher, Sha256, Signer, Verifier,
};

/// Operation types that can be carried by signed Nunchi transactions.
pub trait Operation: EncodeSize + Read<Cfg = ()> + Write {
    /// Domain separator used when signing and verifying transactions for this operation type.
    const NAMESPACE: &'static [u8];
}

/// Signable transaction payload. The nonce is scoped to the signer account.
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

/// A signed Nunchi transaction over a caller-defined operation enum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction<Operation> {
    pub signer: PublicKey,
    pub payload: TransactionPayload<Operation>,
    pub signature: Signature,
}

impl<Operation: self::Operation> Transaction<Operation> {
    pub fn sign(signer: &PrivateKey, nonce: u64, operation: Operation) -> Self {
        let payload = TransactionPayload::new(nonce, operation);
        let signature = signer.sign(Operation::NAMESPACE, &payload.encode());
        Self {
            signer: signer.public_key(),
            payload,
            signature,
        }
    }

    pub fn verify(&self) -> bool {
        self.signer.verify(
            Operation::NAMESPACE,
            &self.payload.encode(),
            &self.signature,
        )
    }

    pub fn digest(&self) -> Digest {
        Sha256::hash(&self.encode())
    }
}

impl<Operation: Write> Write for Transaction<Operation> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.signer.write(buf);
        self.payload.write(buf);
        self.signature.write(buf);
    }
}

impl<Operation: Read<Cfg = ()>> Read for Transaction<Operation> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            signer: PublicKey::read(buf)?,
            payload: TransactionPayload::read(buf)?,
            signature: Signature::read(buf)?,
        })
    }
}

impl<Operation: EncodeSize> EncodeSize for Transaction<Operation> {
    fn encode_size(&self) -> usize {
        self.signer.encode_size() + self.payload.encode_size() + self.signature.encode_size()
    }
}
