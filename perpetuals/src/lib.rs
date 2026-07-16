//! Minimal Oracle-consuming perpetual futures module.

#[cfg(feature = "actor")]
pub mod actor;
mod db;
mod genesis;
#[cfg(feature = "actor")]
pub mod ingress;
mod ledger;
/// JSON-RPC surface for the perpetuals module.
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(test)]
mod tests;
mod transaction;
mod types;

pub use db::PerpetualDB;
pub use genesis::{MarketGenesis, PerpetualsGenesis};
pub use ledger::{
    apply_fill_settlement, collateral_escrow_account, insurance_fund_account, PerpetualError,
    PerpetualLedger,
};
pub use nunchi_coins::CoinId;
pub use nunchi_common::{Address, Authorization};
pub use transaction::{PerpetualOperation, Transaction, TransactionPayload};
pub use types::{
    derive_market_id, derive_position_id, derive_position_id_for_side, Market, MarketId,
    OraclePricePayload, Position, PositionId, Side, BPS_DENOMINATOR,
    DEFAULT_LIQUIDATION_REWARD_BPS, MAX_PRICE_DECIMALS, PRICE_SCALE,
};

/// Domain separator used for perpetual transaction signatures and state keys.
pub const PERPETUALS_NAMESPACE: &[u8] = b"_NUNCHI_PERPETUALS";
