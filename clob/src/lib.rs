//! Central limit order book module for spot and derivatives execution.
//!
//! The CLOB owns market metadata, price-time order priority, matching, open
//! order state, and fill records. Settlement, margin, funding, liquidation,
//! house liquidity, and batch clearing live in consuming modules.

commonware_macros::stability_scope!(ALPHA {
mod db;
mod genesis;
mod ledger;
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(test)]
mod tests;
mod transaction;
mod types;

pub use db::ClobDB;
pub use genesis::{ClobGenesis, ClobMarketGenesis};
pub use ledger::{market_id, ClobError, ClobLedger};
pub use nunchi_common::{AccountSignature, Authorization};
pub use transaction::{ClobOperation, Transaction, TransactionPayload};
pub use types::{
    AssetId, Fill, FillId, Market, MarketId, Order, OrderId, OrderStatus, Side, TimeInForce,
    MAX_ACCOUNT_ORDERS, MAX_BOOK_ORDERS, MAX_FILLS_PER_MARKET, MAX_MARKETS,
};

/// Domain separator used for CLOB transaction signatures and state keys.
pub const CLOB_NAMESPACE: &[u8] = b"_NUNCHI_CLOB";
});
