//! Runtime module adapter for the coin ledger.

use nunchi_common::{ChainModule, Namespace, StateDb, StateStore, Transaction};

use crate::{CoinOperation, Ledger, LedgerError, COINS_NAMESPACE};

/// Coins module adapter for generated or hand-written Nunchi runtimes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Coins;

impl ChainModule for Coins {
    const NAME: &'static str = "coins";
    const NAMESPACE: Namespace = Namespace::new(COINS_NAMESPACE);

    type Transaction = Transaction<CoinOperation>;
    type Config = ();
    type Event = ();
    type Error = LedgerError;

    async fn genesis<S>(
        _state: &mut S,
        _config: Self::Config,
    ) -> Result<Vec<Self::Event>, Self::Error>
    where
        S: StateDb + Send + Sync,
    {
        Ok(Vec::new())
    }

    async fn validate<S>(state: &mut S, transaction: &Self::Transaction) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
    {
        let mut ledger = Ledger::new(state);
        ledger.apply_transaction(transaction).await
    }

    async fn apply<S>(
        state: &mut S,
        transaction: Self::Transaction,
    ) -> Result<Vec<Self::Event>, Self::Error>
    where
        S: StateStore + Send + Sync,
    {
        let mut ledger = Ledger::new(state);
        ledger.apply_transaction(&transaction).await?;
        Ok(Vec::new())
    }
}
