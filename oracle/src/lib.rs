//! Generic interval-aware oracle data store for Nunchi chains.

#[cfg(feature = "state")]
mod db;
#[cfg(feature = "state")]
mod genesis;
#[cfg(feature = "state")]
mod ledger;
#[cfg(test)]
mod tests;
mod transaction;
mod types;

#[cfg(feature = "state")]
pub use db::OracleDB;
#[cfg(feature = "state")]
pub use genesis::OracleGenesis;
#[cfg(feature = "state")]
pub use ledger::{OracleError, OracleLedger};
pub use nunchi_common::{AccountSignature, Authorization};
pub use transaction::{OracleOperation, Transaction, TransactionPayload};
pub use types::{
    IntervalKey, NamespaceId, OracleRecord, RecordId, MAX_PAYLOAD_SIZE, MAX_PROOF_SIZE,
    MAX_QUERY_INTERVALS, MAX_RECORDS_PER_BUCKET,
};

/// Domain separator used for oracle transaction signatures and state keys.
pub const ORACLE_NAMESPACE: &[u8] = b"_NUNCHI_ORACLE";
