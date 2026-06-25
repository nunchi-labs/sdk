//! Compiled custom module skeleton for downstream Nunchi modules.
//!
//! This crate is intentionally small but complete: it exercises the public
//! surfaces a custom module normally needs while staying active in the
//! workspace so skeleton drift is caught by `cargo check` and tests.

commonware_macros::stability_scope!(ALPHA {
mod db;
mod genesis;
mod ledger;
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(test)]
mod tests;
mod transaction;

pub use db::CustomDB;
pub use genesis::{CustomAccountGenesis, CustomGenesis};
pub use ledger::{CustomError, CustomLedger};
pub use transaction::{CustomOperation, Transaction, TransactionPayload};

/// Domain separator used for custom transaction signatures and state keys.
pub const CUSTOM_NAMESPACE: &[u8] = b"_NUNCHI_CUSTOM_MODULE";
});
