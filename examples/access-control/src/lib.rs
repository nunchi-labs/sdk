commonware_macros::stability_scope!(ALPHA {
mod db;
mod events;
mod ledger;
mod runtime;
#[cfg(test)]
mod tests;
mod transaction;

pub use db::CounterDB;
pub use events::{
    counter_incremented_event, counter_reset_event, CounterIncremented, CounterReset,
    COUNTER_INCREMENTED_EVENT, COUNTER_RESET_EVENT,
};
pub use ledger::{CounterError, CounterLedger};
pub use runtime::{
    apply_transaction, initialize, ApplicationTransaction, ExampleRuntime, RuntimeError,
};
pub use transaction::{CounterOperation, CounterOperationId, Transaction, TransactionPayload};

use nunchi_access_control::{RoleId, ScopeId};

pub const COUNTER_NAMESPACE: &[u8] = b"_NUNCHI_ACCESS_CONTROL_EXAMPLE";

pub const RESETTER_ROLE: RoleId = RoleId::new(0);

pub fn counter_scope() -> ScopeId {
    ScopeId::module(COUNTER_NAMESPACE)
}
});
