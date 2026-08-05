commonware_macros::stability_scope!(ALPHA {
mod db;
mod genesis;
mod ledger;
#[cfg(test)]
mod tests;
mod transaction;
mod types;

pub use db::AccessControlDB;
pub use genesis::{AccessControlGenesis, RoleGrantGenesis, ScopeGenesis};
pub use ledger::{AccessControlError, AccessControlLedger};
pub use transaction::{
    AccessControlOperation, OperationID, InvalidAccessControlOperationId,
    Transaction, TransactionPayload,
};
pub use types::{RoleId, Scope, ScopeId};

pub const ACCESS_CONTROL_NAMESPACE: &[u8] = b"_NUNCHI_ACCESS_CONTROL";
});
