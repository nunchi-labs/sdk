use thiserror::Error;

/// Why a submitted transaction was not admitted to the pool.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AdmissionError {
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("transaction is {size} bytes, above the {max} byte limit")]
    TxTooLarge { size: usize, max: usize },
    #[error("transaction is already pending")]
    Duplicate,
    #[error("nonce {nonce} is below the account's committed nonce {committed}")]
    StaleNonce { nonce: u64, committed: u64 },
    #[error("the account's pending queue is full")]
    AccountQueueFull,
    #[error("the pool is full")]
    PoolFull,
    #[error("the mempool is shut down")]
    Shutdown,
}

/// Why a previously admitted transaction left the pool without finalizing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropReason {
    /// Evicted to make room when the pool was full.
    Evicted,
    /// Replaced by a later submission with the same account and nonce.
    Replaced,
    /// The account's committed nonce advanced past this transaction.
    StaleNonce,
    /// Sat unincluded for more than the pool's TTL in blocks.
    Expired,
}

impl DropReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Evicted => "evicted",
            Self::Replaced => "replaced",
            Self::StaleNonce => "stale_nonce",
            Self::Expired => "expired",
        }
    }
}
