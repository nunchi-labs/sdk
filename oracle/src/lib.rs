//! Oracle feed primitives for the Nunchi SDK.
//!
//! The oracle ledger stores feed definitions and the latest submission for each feed while letting
//! publishers carry arbitrarily shaped payloads. JSON helpers are provided for price feeds and
//! other structured payloads, while raw bytes remain available for custom binary formats.

mod db;
mod genesis;
mod ledger;
mod transaction;
mod types;

/// JSON-RPC surface for the oracle module (enabled by the default `rpc` feature).
#[cfg(feature = "rpc")]
pub mod rpc;

pub use db::OracleDB;
pub use genesis::{FeedGenesisEntry, OracleGenesis};
pub use ledger::{OracleError, OracleLedger};
pub use transaction::{OracleOperation, Transaction, TransactionPayload};
pub use types::{
    FeedDefinition, FeedId, FeedIdError, FeedPayload, FeedPayloadEncoding, FeedPayloadError,
    FeedRecord, FeedSubmission, MAX_FEED_ID_BYTES, MAX_FEED_PAYLOAD_BYTES,
};

/// Domain separator used for oracle transaction signatures and state keys.
pub const ORACLE_NAMESPACE: &[u8] = b"_NUNCHI_ORACLE";
