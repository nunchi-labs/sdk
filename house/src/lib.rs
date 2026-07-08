//! House vault module for Nunchi hybrid AMM liquidity.
//!
//! The house module owns vault capital accounting, per-vault risk policy,
//! operating modes, and the registry of submitter keys authorized to manage a
//! vault's liquidity. Quoting strategy, order matching, and batch clearing live
//! in consuming modules: the off-chain bin manager decides where to quote, the
//! CLOB matches, and the cooperative batch clearing module settles residual
//! inventory through the checked clearing API exported here.
//!
//! Balances are internal accounting units until chain-level wiring connects
//! vault deposits and withdrawals to the coins module.

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

pub use db::HouseDB;
pub use genesis::{genesis_vault_id, HouseGenesis, HouseVaultGenesis};
pub use ledger::{
    authorized_submitter, release_clearing_quote, reserve_clearing_quote, settle_clearing_fill,
    validate_clearing_fill, HouseError, HouseLedger,
};
pub use nunchi_common::{AccountSignature, Authorization};
pub use transaction::{HouseOperation, Transaction, TransactionPayload};
pub use types::{
    Mode, NetInventory, Vault, VaultId, VaultPolicy, BPS_DENOMINATOR, MAX_ALLOWED_MARKETS,
    MAX_SUBMITTERS_PER_VAULT, MAX_VAULTS, MAX_VAULT_MARKETS,
};

/// Domain separator used for house transaction signatures and state keys.
pub const HOUSE_NAMESPACE: &[u8] = b"_NUNCHI_HOUSE";
});
