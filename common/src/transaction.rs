use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_crypto::{PrivateKey, PublicKey, Signature, SignatureError};

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

    pub fn verify(&self) -> Result<(), SignatureError> {
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
        let signer = PublicKey::read(buf)?;
        let payload = TransactionPayload::read(buf)?;
        let signature = Signature::read(buf)?;

        if signer.curve() != signature.curve() {
            return Err(Error::Invalid(
                "transaction",
                "signature curve does not match signer curve",
            ));
        }

        Ok(Self {
            signer,
            payload,
            signature,
        })
    }
}

impl<Operation: EncodeSize> EncodeSize for Transaction<Operation> {
    fn encode_size(&self) -> usize {
        self.signer.encode_size() + self.payload.encode_size() + self.signature.encode_size()
    }
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
        let tx = Transaction::sign(&signer, 11, TestOperation(42));

        assert_eq!(tx.verify(), Ok(()));
        assert_eq!(tx.signer, signer.public_key());
        assert_eq!(Transaction::decode(tx.encode().as_ref()).unwrap(), tx);
    }

    #[test]
    fn secp256r1_transaction_signs_verifies_and_roundtrips() {
        let signer = PrivateKey::secp256r1_from_seed(7);
        let tx = Transaction::sign(&signer, 11, TestOperation(42));

        assert_eq!(tx.verify(), Ok(()));
        assert_eq!(tx.signer, signer.public_key());
        assert_eq!(Transaction::decode(tx.encode().as_ref()).unwrap(), tx);
    }

    #[test]
    fn transaction_verification_rejects_tampered_payload() {
        let signer = PrivateKey::ed25519_from_seed(7);
        let mut tx = Transaction::sign(&signer, 11, TestOperation(42));

        tx.payload.operation = TestOperation(43);

        assert_eq!(tx.verify(), Err(SignatureError::InvalidSignature));
    }

    #[test]
    fn transaction_verification_rejects_mismatched_signature_curve() {
        let signer = PrivateKey::ed25519_from_seed(7);
        let secp_signer = PrivateKey::secp256r1_from_seed(7);
        let mut tx = Transaction::sign(&signer, 11, TestOperation(42));
        tx.signature = secp_signer.sign(TestOperation::NAMESPACE, &tx.payload.encode());

        assert_eq!(tx.verify(), Err(SignatureError::IncompatibleKey));
    }

    #[test]
    fn transaction_decode_rejects_mismatched_signature_curve() {
        let signer = PrivateKey::ed25519_from_seed(7);
        let secp_signer = PrivateKey::secp256r1_from_seed(7);
        let mut tx = Transaction::sign(&signer, 11, TestOperation(42));
        tx.signature = secp_signer.sign(TestOperation::NAMESPACE, &tx.payload.encode());

        assert!(matches!(
            Transaction::<TestOperation>::decode(tx.encode().as_ref()),
            Err(Error::Invalid(
                "transaction",
                "signature curve does not match signer curve"
            ))
        ));
    }
}
