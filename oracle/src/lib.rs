//! Generic interval-aware oracle data store for Nunchi chains.
//!
//! # Security Model
//!
//! The oracle is fully permissionless: any account can write to any namespace without access
//! control. There is no per-namespace allowlist, namespace registration, or per-writer quota.
//!
//! Consumers **must** filter records by `writer` against their own trusted-writer set. Relying
//! on unfiltered namespace queries exposes consumers to data pollution, where an attacker submits
//! plausible but manipulated payloads to a namespace.
//!
//! Each `(namespace, interval)` bucket has a fixed capacity of [`MAX_RECORDS_PER_BUCKET`] entries.
//! Once full, no additional records can be appended to that bucket. An attacker can exploit this to
//! permanently block a bucket by filling it with junk records before legitimate writers act.
//! Consumers should account for this when choosing namespace and interval granularity.

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
    IntervalKey, NamespaceId, OracleRecord, RecordId, MAX_PAYLOAD_SIZE, MAX_PROOF_SIZE,
    MAX_QUERY_INTERVALS, MAX_RECORDS_PER_BUCKET,
};

/// Domain separator used for oracle transaction signatures and state keys.
pub const ORACLE_NAMESPACE: &[u8] = b"_NUNCHI_ORACLE";
