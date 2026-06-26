use commonware_codec::EncodeSize;
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Operation, Transaction};
use nunchi_crypto::SignatureError;
use std::{fmt::Debug, hash::Hash};

/// Nonce sequence key for a module transaction.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NonceKey {
    namespace: &'static [u8],
    account: Address,
}

impl NonceKey {
    pub fn new(namespace: &'static [u8], account: Address) -> Self {
        Self { namespace, account }
    }

    pub fn namespace(&self) -> &'static [u8] {
        self.namespace
    }

    pub fn account(&self) -> &Address {
        &self.account
    }
}

/// A transaction that can live in the pool.
///
/// Implemented for any [`nunchi_common::Transaction`] via the blanket impl
/// below; chains with custom transaction types implement it directly.
pub trait PoolTransaction: Clone + Send + 'static {
    /// The exact committed nonce sequence this transaction belongs to.
    type NonceKey: Clone + Ord + Hash + Debug + Send + 'static;
    /// Failure of the stateless validity check.
    type VerifyError: std::error::Error + Send + 'static;

    /// Content-addressed SHA-256 identity of the transaction.
    fn digest(&self) -> Digest;
    fn nonce_key(&self) -> Self::NonceKey;
    /// Nonce within the account's sequence.
    fn nonce(&self) -> u64;
    /// Encoded byte size, used as an admission resource bound.
    fn encoded_size(&self) -> usize;
    /// Stateless cryptographic validity check.
    fn verify(&self) -> Result<(), Self::VerifyError>;
}

impl<Op: Operation + Clone + Send + 'static> PoolTransaction for Transaction<Op> {
    type NonceKey = NonceKey;
    type VerifyError = SignatureError;

    fn digest(&self) -> Digest {
        Transaction::digest(self)
    }

    fn nonce_key(&self) -> Self::NonceKey {
        NonceKey::new(Op::NAMESPACE, self.account_id.clone())
    }

    fn nonce(&self) -> u64 {
        self.payload.nonce
    }

    fn encoded_size(&self) -> usize {
        EncodeSize::encode_size(self)
    }

    fn verify(&self) -> Result<(), Self::VerifyError> {
        Transaction::verify(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
    use nunchi_common::TransactionPayload;
    use nunchi_crypto::PrivateKey;

    /// Minimal [`Operation`] so the blanket `PoolTransaction for Transaction<Op>`
    /// impl can be exercised over a real, signed [`Transaction`].
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestOp(u8);

    impl Write for TestOp {
        fn write(&self, buf: &mut impl bytes::BufMut) {
            self.0.write(buf);
        }
    }

    impl Read for TestOp {
        type Cfg = ();

        fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            Ok(Self(u8::read(buf)?))
        }
    }

    impl EncodeSize for TestOp {
        fn encode_size(&self) -> usize {
            self.0.encode_size()
        }
    }

    impl Operation for TestOp {
        const NAMESPACE: &'static [u8] = b"nunchi-mempool/test-operation";
    }

    fn signed_tx(seed: u64, nonce: u64) -> Transaction<TestOp> {
        Transaction::sign(&PrivateKey::ed25519_from_seed(seed), nonce, TestOp(7))
    }

    // ----- NonceKey -----

    #[test]
    fn nonce_key_exposes_namespace_and_account() {
        let account = Address::external(&PrivateKey::ed25519_from_seed(1).public_key());
        let key = NonceKey::new(b"ns", account.clone());

        assert_eq!(key.namespace(), b"ns");
        assert_eq!(key.account(), &account);
    }

    #[test]
    fn nonce_key_equality_depends_on_namespace_and_account() {
        let a = Address::external(&PrivateKey::ed25519_from_seed(1).public_key());
        let b = Address::external(&PrivateKey::ed25519_from_seed(2).public_key());

        assert_eq!(NonceKey::new(b"ns", a.clone()), NonceKey::new(b"ns", a.clone()));
        // Same account, different namespace -> distinct key.
        assert_ne!(NonceKey::new(b"ns", a.clone()), NonceKey::new(b"other", a.clone()));
        // Same namespace, different account -> distinct key.
        assert_ne!(NonceKey::new(b"ns", a), NonceKey::new(b"ns", b));
    }

    // ----- blanket PoolTransaction impl over Transaction<Op> -----

    #[test]
    fn pool_transaction_digest_matches_transaction_digest() {
        let tx = signed_tx(42, 3);
        assert_eq!(PoolTransaction::digest(&tx), Transaction::digest(&tx));
    }

    #[test]
    fn pool_transaction_nonce_key_carries_namespace_and_account() {
        let tx = signed_tx(42, 3);
        let key = tx.nonce_key();

        assert_eq!(key.namespace(), TestOp::NAMESPACE);
        assert_eq!(key.account(), &tx.account_id);
    }

    #[test]
    fn pool_transaction_nonce_matches_payload() {
        let tx = signed_tx(42, 9);
        assert_eq!(PoolTransaction::nonce(&tx), 9);
        assert_eq!(tx.payload, TransactionPayload::new(9, TestOp(7)));
    }

    #[test]
    fn pool_transaction_encoded_size_matches_codec() {
        let tx = signed_tx(42, 3);
        assert_eq!(tx.encoded_size(), EncodeSize::encode_size(&tx));
    }

    #[test]
    fn pool_transaction_verify_accepts_well_signed_tx() {
        let tx = signed_tx(42, 3);
        assert!(PoolTransaction::verify(&tx).is_ok());
    }

    #[test]
    fn pool_transaction_verify_rejects_tampered_payload() {
        let mut tx = signed_tx(42, 3);
        tx.payload.operation = TestOp(8);
        assert!(PoolTransaction::verify(&tx).is_err());
    }
}
