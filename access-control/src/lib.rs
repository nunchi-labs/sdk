commonware_macros::stability_scope!(ALPHA {
mod db;
mod events;
mod genesis;
mod ledger;
#[cfg(test)]
mod tests;
mod transaction;
mod types;

pub use db::AccessControlDB;
pub use events::{
    ownership_transfer_cancelled_event, ownership_transfer_proposed_event, role_granted_event,
    role_revoked_event, scope_owner_changed_event, scope_registered_event,
    OwnershipTransferCancelled, OwnershipTransferProposed, RoleGranted, RoleRevoked,
    ScopeOwnerChanged, ScopeRegistered, OWNERSHIP_TRANSFER_CANCELLED_EVENT,
    OWNERSHIP_TRANSFER_PROPOSED_EVENT, ROLE_GRANTED_EVENT, ROLE_REVOKED_EVENT,
    SCOPE_OWNER_CHANGED_EVENT, SCOPE_REGISTERED_EVENT,
};
pub use genesis::{AccessControlGenesis, RoleGrantGenesis, ScopeGenesis};
pub use ledger::{AccessControlError, AccessControlLedger};
pub use transaction::{
    AccessControlOperation, OperationID, InvalidAccessControlOperationId,
    Transaction, TransactionPayload,
};
pub use types::{RoleId, Scope, ScopeId};

pub const ACCESS_CONTROL_NAMESPACE: &[u8] = b"_NUNCHI_ACCESS_CONTROL";
});
