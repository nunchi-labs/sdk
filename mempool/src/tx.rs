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
