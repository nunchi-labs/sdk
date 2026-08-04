use crate::{
    counter_incremented_event, counter_reset_event, counter_scope, CounterDB, CounterIncremented,
    CounterOperation, CounterReset, Transaction, RESETTER_ROLE,
};
use nunchi_access_control::{AccessControlError, AccessControlLedger};
use nunchi_common::{Address, EventSink, StateStore};
use nunchi_crypto::SignatureError;
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CounterError {
    #[error("bad counter transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("account {0:?} cannot reset the counter")]
    Unauthorized(Box<Address>),
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("counter transaction nonce exhausted")]
    NonceExhausted,
    #[error("counter value exhausted")]
    CounterExhausted,
    #[error("access-control query failed: {0}")]
    AccessControl(#[from] AccessControlError),
    #[error("state storage error: {0}")]
    Storage(String),
}

/// A counter that owns its authorization policy and delegates role management.
pub struct CounterLedger<S> {
    state: S,
}

impl<S: StateStore + Send + Sync> CounterLedger<S> {
    pub fn new(state: S) -> Self {
        Self { state }
    }

    pub fn db(&self) -> &S {
        &self.state
    }

    pub fn into_inner(self) -> S {
        self.state
    }

    pub async fn nonce(&self, account: &Address) -> Result<u64, CounterError> {
        CounterDB::nonce(&self.state, account).await
    }

    pub async fn value(&self) -> Result<u64, CounterError> {
        CounterDB::value(&self.state).await
    }

    pub async fn apply_transaction<Events>(
        &mut self,
        tx: &Transaction,
        mut events: Events,
    ) -> Result<(), CounterError>
    where
        Events: EventSink + Send,
    {
        tx.verify()?;
        self.ensure_authorized(&tx.account_id, &tx.payload.operation)
            .await?;

        let expected = CounterDB::nonce(&self.state, &tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(CounterError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }
        let next_nonce = expected
            .checked_add(1)
            .ok_or(CounterError::NonceExhausted)?;
        let previous = CounterDB::value(&self.state).await?;

        let (value, event) = match &tx.payload.operation {
            CounterOperation::Increment => {
                let value = previous
                    .checked_add(1)
                    .ok_or(CounterError::CounterExhausted)?;
                let event = counter_incremented_event(CounterIncremented {
                    account: tx.account_id.clone(),
                    value,
                });
                (value, event)
            }
            CounterOperation::Reset { value } => {
                let event = counter_reset_event(CounterReset {
                    account: tx.account_id.clone(),
                    previous,
                    value: *value,
                });
                (*value, event)
            }
        };

        CounterDB::set_value(&mut self.state, value);
        CounterDB::set_nonce(&mut self.state, &tx.account_id, next_nonce);
        events.emit(event);
        Ok(())
    }

    async fn ensure_authorized(
        &mut self,
        account: &Address,
        operation: &CounterOperation,
    ) -> Result<(), CounterError> {
        if matches!(operation, CounterOperation::Increment) {
            return Ok(());
        }

        let access_control = AccessControlLedger::new(&mut self.state);
        if access_control
            .has_role(account, &counter_scope(), RESETTER_ROLE)
            .await?
        {
            Ok(())
        } else {
            Err(CounterError::Unauthorized(Box::new(account.clone())))
        }
    }
}
