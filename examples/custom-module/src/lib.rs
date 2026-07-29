//! Compiled custom module skeleton for downstream Nunchi modules.
//!
//! This crate is intentionally small but complete: it exercises the public
//! surfaces a custom module normally needs while staying active in the
//! workspace so skeleton drift is caught by `cargo check` and tests.

commonware_macros::stability_scope!(ALPHA {
mod db;
mod events;
mod genesis;
mod ledger;
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(test)]
mod tests;
mod transaction;

pub use db::CustomDB;
pub use events::{
    value_cleared_event, value_set_event, ValueCleared, ValueSet, VALUE_CLEARED_EVENT,
    VALUE_SET_EVENT,
};
pub use genesis::{CustomAccountGenesis, CustomGenesis};
pub use ledger::{CustomError, CustomLedger};
pub use transaction::{CustomOperation, Transaction, TransactionPayload};

/// Domain separator used for custom transaction signatures and state keys.
///
/// IMPORTANT: The `_NUNCHI_` prefix is reserved for first-party production
/// modules. Third-party and example modules must use a different prefix to
/// avoid cross-module transaction replay and storage-key collisions.
/// Rename this constant to a globally unique value before deploying.
pub const CUSTOM_NAMESPACE: &[u8] = b"_EXAMPLE_CUSTOM_MODULE";
});
