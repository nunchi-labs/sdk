//! Coins-chain runtime execution dispatch.

use commonware_codec::EncodeSize;
use nunchi_authority::{AuthorityError, AuthorityLedger};
use nunchi_clob::{ClobError, ClobLedger};
use nunchi_coins::{Ledger, LedgerError};
use nunchi_common::{EventSink, NoopEventSink, Runtime, RuntimeContext, StateStore};
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
    #[error("clob module error: {0}")]
    Clob(#[from] ClobError),
}

impl RuntimeError {
    pub fn is_storage(&self) -> bool {
        matches!(
            self,
            Self::Coins(LedgerError::Storage(_))
                | Self::Authority(AuthorityError::Storage(_))
                | Self::Oracle(OracleError::Storage(_))
                | Self::Clob(ClobError::Storage(_))
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
        apply_transaction(state, context, transaction, NoopEventSink).await
    }

    async fn apply<S, Events>(
        state: &mut S,
        context: RuntimeContext,
        transaction: &Self::Transaction,
        events: &mut Events,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
        Events: EventSink + Send,
    {
        apply_transaction(state, context, transaction, events).await
    }

    fn is_storage_error(error: &Self::Error) -> bool {
        error.is_storage()
    }
}

async fn apply_transaction<S, Events>(
    state: &mut S,
    context: RuntimeContext,
    transaction: &Transaction,
    mut events: Events,
) -> Result<(), RuntimeError>
where
    S: StateStore + Send + Sync,
    Events: EventSink + Send,
{
    // Fee ante: charge the authorizing account before module dispatch. The fee is staged in the
    // same overlay as the operation, so a failed transaction reverts its fee.
    let mut fees = Ledger::new(&mut *state);
    fees.charge_fee(
        transaction.account_id(),
        transaction.encode_size(),
        &mut events,
    )
    .await?;

    match transaction {
        Transaction::Coin(transaction) => {
            let mut ledger = Ledger::new(state);
            ledger.apply_transaction(transaction, events).await?;
        }
        Transaction::Authority(transaction) => {
            let mut ledger = AuthorityLedger::new(state);
            ledger.apply_transaction(transaction, context.epoch).await?;
        }
        Transaction::Oracle(transaction) => {
            let mut ledger = OracleLedger::new(state);
            ledger.apply_transaction(transaction, context).await?;
        }
        Transaction::Clob(transaction) => {
            let mut ledger = ClobLedger::new(state);
            ledger.apply_transaction(transaction, context).await?;
        }
    }
    Ok(())
}
