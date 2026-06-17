//! Perpetual swap markets and positions for the Nunchi SDK.

mod db;
mod genesis;
mod ledger;
#[cfg(feature = "rpc")]
pub mod rpc;
mod transaction;
mod types;

pub use db::PerpetualDB;
pub use genesis::{MarketGenesis, PerpetualsGenesis};
pub use ledger::{LedgerError, PerpetualLedger};
pub use nunchi_coins::CoinId;
pub use nunchi_common::{Address, Authorization};
pub use transaction::{PerpetualOperation, Transaction, TransactionPayload};
pub use types::{
    derive_market_id, derive_position_id, Market, MarketId, Position, PositionId, Side,
    BPS_DENOMINATOR, PRICE_SCALE,
};

/// Domain separator used for perpetual transaction signatures and state keys.
pub const PERPETUALS_NAMESPACE: &[u8] = b"_NUNCHI_PERPETUALS";
