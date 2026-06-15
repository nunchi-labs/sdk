//! Runtime module adapter for the authority ledger.

use nunchi_common::{ChainModule, Namespace, RuntimeContext, StateDb, StateStore};

use crate::{AuthorityError, AuthorityLedger, Transaction, AUTHORITY_NAMESPACE};

/// Authority module adapter for generated or hand-written Nunchi runtimes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Authority;

impl ChainModule for Authority {
    const NAME: &'static str = "authority";
    const NAMESPACE: Namespace = Namespace::new(AUTHORITY_NAMESPACE);

    type Transaction = Transaction;
    type Config = ();
    type Event = ();
    type Error = AuthorityError;

    async fn genesis<S>(
        _state: &mut S,
        _config: Self::Config,
    ) -> Result<Vec<Self::Event>, Self::Error>
    where
        S: StateDb + Send + Sync,
    {
        Ok(Vec::new())
    }

    async fn validate<S>(
        state: &mut S,
        context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
    {
        let mut ledger = AuthorityLedger::new(state);
        ledger.apply_transaction(transaction, context.epoch).await
    }

    async fn apply<S>(
        state: &mut S,
        context: RuntimeContext,
        transaction: Self::Transaction,
    ) -> Result<Vec<Self::Event>, Self::Error>
    where
        S: StateStore + Send + Sync,
    {
        let mut ledger = AuthorityLedger::new(state);
        ledger
            .apply_transaction(&transaction, context.epoch)
            .await?;
        Ok(Vec::new())
    }
}
