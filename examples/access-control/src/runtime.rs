//! Example application composition for access-control and counter transactions.

use crate::{counter_scope, CounterError, CounterLedger, Transaction as CounterTransaction};
use nunchi_access_control::{
    AccessControlError, AccessControlLedger, AccessControlOperation, Transaction as AccessTransaction,
};
use nunchi_common::{Address, EventSink, NoopEventSink, Runtime, RuntimeContext, StateStore};
use thiserror::Error;

const TX_ACCESS_CONTROL: u8 = 0;
const TX_COUNTER: u8 = 1;

nunchi_chain::transaction_wrapper! {
    pub enum ApplicationTransaction {
        AccessControl {
            tag: TX_ACCESS_CONTROL,
            transaction: AccessTransaction,
            operation: AccessControlOperation,
        },
        Counter {
            tag: TX_COUNTER,
            transaction: CounterTransaction,
            operation: crate::CounterOperation,
        },
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("access-control module error: {0}")]
    AccessControl(#[from] AccessControlError),
    #[error("counter module error: {0}")]
    Counter(#[from] CounterError),
}

impl RuntimeError {
    fn is_storage(&self) -> bool {
        matches!(
            self,
            Self::AccessControl(AccessControlError::Storage(_))
                | Self::Counter(CounterError::Storage(_))
                | Self::Counter(CounterError::AccessControl(AccessControlError::Storage(_)))
        )
    }
}

pub async fn initialize<S, Events>(
    state: &mut S,
    owner: Address,
    events: Events,
) -> Result<(), RuntimeError>
where
    S: StateStore + Send + Sync,
    Events: EventSink + Send,
{
    AccessControlLedger::new(state)
        .register_scope(counter_scope(), owner, events)
        .await?;
    Ok(())
}

pub async fn apply_transaction<S, Events>(
    state: &mut S,
    transaction: &ApplicationTransaction,
    events: Events,
) -> Result<(), RuntimeError>
where
    S: StateStore + Send + Sync,
    Events: EventSink + Send,
{
    match transaction {
        ApplicationTransaction::AccessControl(transaction) => {
            AccessControlLedger::new(state)
                .apply_transaction(transaction, events)
                .await?;
        }
        ApplicationTransaction::Counter(transaction) => {
            CounterLedger::new(state)
                .apply_transaction(transaction, events)
                .await?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ExampleRuntime;

impl Runtime for ExampleRuntime {
    type Transaction = ApplicationTransaction;
    type Error = RuntimeError;

    async fn validate<S>(
        state: &mut S,
        _context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
    {
        apply_transaction(state, transaction, NoopEventSink).await
    }

    async fn apply<S, Events>(
        state: &mut S,
        _context: RuntimeContext,
        transaction: &Self::Transaction,
        events: &mut Events,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
        Events: EventSink + Send,
    {
        apply_transaction(state, transaction, events).await
    }

    fn is_storage_error(error: &Self::Error) -> bool {
        error.is_storage()
    }
}
