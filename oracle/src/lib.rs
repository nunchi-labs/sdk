//! Oracle state, normalization, and status primitives for Nunchi chains.

mod db;
mod ledger;
#[cfg(test)]
mod tests;
mod transaction;
mod types;

pub use db::OracleDB;
pub use ledger::{OracleError, OracleLedger};
pub use nunchi_common::{AccountSignature, Authorization};
pub use transaction::{OracleOperation, Transaction, TransactionPayload};
pub use types::{
    DivergenceLevel, DivergenceState, FeedId, FeedState, MarkInputs, MarketId, OracleConfig,
    OracleState, OracleStatus, Price, SourceId, UpdaterPolicy,
};

/// Domain separator used for oracle transaction signatures and state keys.
pub const ORACLE_NAMESPACE: &[u8] = b"_NUNCHI_ORACLE";
