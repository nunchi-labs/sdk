//! Coins-chain runtime execution dispatch.

use nunchi_authority::{AuthorityError, AuthorityLedger};
use nunchi_coins::{Ledger, LedgerError};
use nunchi_common::{EventSink, Runtime, RuntimeContext, StateStore};
use nunchi_oracle::{OracleError, OracleLedger};

use crate::Transaction;

#[derive(Clone, Copy, Debug, Default)]
pub struct CoinsRuntime;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("coins module error: {0}")]
    Coins(#[from] LedgerError),
    #[error("authority module error: {0}")]
    Authority(#[from] AuthorityError),
    #[error("oracle module error: {0}")]
    Oracle(#[from] OracleError),
}

impl RuntimeError {
    pub fn is_storage(&self) -> bool {
        matches!(
            self,
            Self::Coins(LedgerError::Storage(_))
                | Self::Authority(AuthorityError::Storage(_))
                | Self::Oracle(OracleError::Storage(_))
        )
    }
}

impl Runtime for CoinsRuntime {
    type Transaction = Transaction;
    type Error = RuntimeError;

    async fn validate<S>(
        state: &mut S,
        context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
    {
        apply_transaction(state, context, transaction).await
    }

    async fn apply<S, Events>(
        state: &mut S,
        context: RuntimeContext,
        transaction: &Self::Transaction,
        _events: &mut Events,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
        Events: EventSink + Send,
    {
        apply_transaction(state, context, transaction).await
    }

    fn is_storage_error(error: &Self::Error) -> bool {
        error.is_storage()
    }
}

async fn apply_transaction<S>(
    state: &mut S,
    context: RuntimeContext,
    transaction: &Transaction,
) -> Result<(), RuntimeError>
where
    S: StateStore + Send + Sync,
{
    match transaction {
        Transaction::Coin(transaction) => {
            let mut ledger = Ledger::new(state);
            ledger.apply_transaction(transaction).await?;
        }
        Transaction::Authority(transaction) => {
            let mut ledger = AuthorityLedger::new(state);
            ledger.apply_transaction(transaction, context.epoch).await?;
        }
        Transaction::Oracle(transaction) => {
            let mut ledger = OracleLedger::new(state);
            ledger.apply_transaction(transaction, context).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_error_classifies_storage_errors() {
        assert!(RuntimeError::Coins(LedgerError::Storage("disk".into())).is_storage());
        assert!(RuntimeError::Authority(AuthorityError::Storage("disk".into())).is_storage());
        assert!(RuntimeError::Oracle(OracleError::Storage("disk".into())).is_storage());

        assert!(!RuntimeError::Authority(AuthorityError::NotConfigured).is_storage());
        assert!(!RuntimeError::Coins(LedgerError::InvalidTokenSpec("bad")).is_storage());
        assert!(!RuntimeError::Oracle(OracleError::Unauthorized).is_storage());
    }
}
