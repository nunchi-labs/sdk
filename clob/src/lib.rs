//! Central limit order book module for spot and derivatives execution.
//!
//! The CLOB owns market metadata, signed order intents, active order snapshots
//! needed for replay, deterministic matcher replay, and fill records. Full open
//! order books live in validator-local runtime state; settlement, margin,
//! funding, liquidation, house liquidity, and batch clearing live in consuming
//! modules.
//!
//! Self-trade prevention is not enforced: orders from the same account may match
//! against each other.

commonware_macros::stability_scope!(ALPHA {
mod actor;
mod db;
mod engine;
mod extension;
mod genesis;
mod ledger;
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(test)]
mod tests;
mod transaction;
mod types;

pub use actor::{ClobActor, ClobConfig, ClobMailbox};
pub use db::ClobDB;
pub(crate) use engine::fills_equivalent;
pub use engine::{MatchEngine, ReplayResult};
pub use extension::ClobExtension;
pub use genesis::{ClobGenesis, ClobMarketGenesis};
pub use ledger::{canonical_asset_pair, market_id, ClobError, ClobLedger};
pub use nunchi_common::{AccountSignature, Authorization};
pub use transaction::{ClobOperation, MatchBatch, Transaction, TransactionPayload};
pub use types::{
    AssetId, Fill, FillId, Market, MarketId, Order, OrderId, OrderStatus, Side, TimeInForce,
    MAX_ACCOUNT_ORDERS, MAX_BOOK_ORDERS, MAX_FILLS_PER_MARKET, MAX_MARKETS,
    MAX_MATCH_BATCH_FILLS, MAX_MATCH_BATCH_ORDERS,
};

/// Domain separator used for CLOB transaction signatures and state keys.
pub const CLOB_NAMESPACE: &[u8] = b"_NUNCHI_CLOB";
});
