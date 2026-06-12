use commonware_codec::EncodeSize;
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Operation, Transaction};
use nunchi_crypto::SignatureError;
use std::fmt::Debug;
use std::hash::Hash;

/// A transaction that can live in the pool.
///
/// Implemented for any [`nunchi_common::Transaction`] via the blanket impl
/// below; chains with custom transaction types implement it directly.
pub trait PoolTransaction: Clone + Send + 'static {
    /// Content-addressed identity of the transaction.
    type Digest: Copy + Ord + Hash + Debug + Send + 'static;
    /// The account whose nonce sequence this transaction belongs to.
    type AccountId: Clone + Ord + Hash + Debug + Send + 'static;
    /// Failure of the stateless validity check.
    type VerifyError: std::error::Error + Send + 'static;

    fn digest(&self) -> Self::Digest;
    fn account_id(&self) -> &Self::AccountId;
    /// Nonce within the account's sequence.
    fn nonce(&self) -> u64;
    /// Encoded byte size, used as an admission resource bound.
    fn encoded_size(&self) -> usize;
    /// Stateless cryptographic validity check.
    fn verify(&self) -> Result<(), Self::VerifyError>;
}

impl<Op: Operation + Clone + Send + 'static> PoolTransaction for Transaction<Op> {
    type Digest = Digest;
    type AccountId = Address;
    type VerifyError = SignatureError;

    fn digest(&self) -> Self::Digest {
        Transaction::digest(self)
    }

    fn account_id(&self) -> &Self::AccountId {
        &self.account_id
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
