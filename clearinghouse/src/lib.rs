//! Trade settlement layer routing CLOB fills to consumer modules.

commonware_macros::stability_scope!(ALPHA {
mod db;
mod ledger;
mod settlement;
#[cfg(test)]
mod tests;
mod transaction;
mod types;

pub use db::ClearinghouseDB;
pub use ledger::{ClearinghouseError, ClearinghouseLedger};
pub use settlement::commit_and_settle_transactions;
pub use nunchi_common::{Address, Authorization};
pub use transaction::{ClearinghouseOperation, Transaction, TransactionPayload};
pub use types::{
    derive_settlement_market_id, SettlementDomain, SettlementMarket, SettlementMarketId,
};

/// Domain separator used for clearinghouse transaction signatures and state keys.
pub const CLEARINGHOUSE_NAMESPACE: &[u8] = b"_NUNCHI_CLEARINGHOUSE";
});
