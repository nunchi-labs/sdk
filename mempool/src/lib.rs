//! A reusable, nonce-aware transaction mempool for Nunchi chains.
//!
//! The pool is generic over [`PoolTransaction`] and keeps one nonce-ordered
//! queue per account. Admission is stateful (stale nonces are rejected against
//! a committed-nonce snapshot fed by finalization), same-nonce resubmissions
//! replace the earlier transaction, and proposals only ever return gap-free,
//! executable nonce runs. The pool runs as a single actor; [`MempoolHandle`]
//! is the cloneable ingress used by RPC, block production, and finalization.

mod actor;
mod config;
mod error;
mod pool;
mod status;
#[cfg(test)]
mod testing;
#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
mod tx;

pub use actor::{Mempool, MempoolHandle};
pub use config::PoolConfig;
pub use error::{AdmissionError, DropReason};
pub use status::TxStatus;
pub use tx::PoolTransaction;
