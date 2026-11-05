use crate::{
    value_cleared_event, value_set_event, CustomDB, CustomOperation, Transaction, ValueCleared,
    ValueSet,
};
use nunchi_common::{Address, Event, EventSink};
use nunchi_crypto::SignatureError;
use thiserror::Error;

/// Deterministic custom state-machine error.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CustomError {
    #[error("bad transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("state storage error: {0}")]
    Storage(String),
}

/// Deterministic state machine for the custom module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomLedger<D> {
    pub(crate) db: D,
}

impl<D: CustomDB> CustomLedger<D> {
    /// Wrap a database backend as a custom ledger.
    pub fn new(db: D) -> Self {
        Self { db }
    }

    /// Borrow the underlying database.
    pub fn db(&self) -> &D {
        &self.db
    }

    /// Consume the ledger, returning the underlying database.
    pub fn into_inner(self) -> D {
        self.db
    }

    pub async fn nonce(&self, account: &Address) -> Result<u64, CustomError> {
        self.db.nonce(account).await
    }

    pub async fn value(&self, account: &Address) -> Result<Option<u64>, CustomError> {
        self.db.value(account).await
    }

    pub async fn apply_transaction<Events>(
        &mut self,
        tx: &Transaction,
        mut events: Events,
    ) -> Result<(), CustomError>
    where
        Events: EventSink + Send,
    {
        tx.verify()?;

        let expected = self.db.nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(CustomError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        let next_nonce = expected.checked_add(1).ok_or(CustomError::NonceOverflow)?;
        let event = self.apply_operation(&tx.account_id, &tx.payload.operation);
        self.db.set_nonce(&tx.account_id, next_nonce);
        events.emit(event);
        Ok(())
    }

    fn apply_operation(&mut self, account_id: &Address, operation: &CustomOperation) -> Event {
        match operation {
            CustomOperation::SetValue { value } => {
                self.db.set_value(account_id, *value);
                value_set_event(ValueSet {
                    account_id: account_id.clone(),
                    value: *value,
                })
            }
            CustomOperation::ClearValue => {
                self.db.remove_value(account_id);
                value_cleared_event(ValueCleared {
                    account_id: account_id.clone(),
                })
            }
        }
    }
}
