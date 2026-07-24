//! Generic interval-aware oracle data store for Nunchi chains.

mod db;
mod genesis;
mod ledger;
#[cfg(test)]
mod tests;
mod transaction;
mod types;

pub use db::OracleDB;
pub use genesis::OracleGenesis;
pub use ledger::{OracleError, OracleLedger};
pub use nunchi_common::{AccountSignature, Authorization};
pub use transaction::{OracleOperation, Transaction, TransactionPayload};
pub use types::{
    IntervalIndexMeta, IntervalKey, NamespaceId, OracleRecord, RecordId, INDEX_PAGE_SIZE,
    MAX_PAYLOAD_SIZE, MAX_PROOF_SIZE, MAX_QUERY_INTERVALS, MAX_QUERY_RECORDS,
    MAX_RECORDS_PER_BUCKET,
};

/// Domain separator used for oracle transaction signatures and state keys.
pub const ORACLE_NAMESPACE: &[u8] = b"_NUNCHI_ORACLE";
