//! Cooperative batch clearing module for Nunchi hybrid AMM liquidity.
//!
//! The module accepts signed liquidity-management intents from house vaults
//! and allowlisted market makers, clears them at one deterministic uniform
//! price per market per batch, and settles the fills through the house
//! module's checked clearing API. All valid fills in a batch receive the same
//! price, so a hostile public submitter cannot selectively trade against
//! another participant's price-time edge and no proprietary strategy is
//! revealed beyond the signed intents themselves.
//!
//! Buy intents reserve their worst-case quote cost in the house module at
//! submission, so a vault can never distort a batch price with intents it
//! cannot settle. Sell intents are bounded by per-vault and per-batch
//! notional caps; economic short margining arrives with perps wiring.

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

pub use db::CbcDB;
pub use genesis::{CbcGenesis, CbcMarketGenesis};
pub use ledger::{CbcError, CbcLedger};
pub use nunchi_common::{AccountSignature, Authorization};
pub use transaction::{CbcOperation, Transaction, TransactionPayload};
pub use types::{
    BatchIntent, BatchOutcome, BatchParams, BatchResult, ClearingFill, IntentId, IntentStatus,
    MarketClearingState, MAX_CLEARING_MARKETS, MAX_FILLS_PER_BATCH, MAX_PENDING_INTENTS,
    MAX_REJECTED_PER_BATCH,
};

/// Domain separator used for CBC transaction signatures and state keys.
pub const CBC_NAMESPACE: &[u8] = b"_NUNCHI_CBC";
});
