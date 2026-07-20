//! Coins-chain runtime execution dispatch.

use commonware_codec::EncodeSize;
use nunchi_authority::{AuthorityError, AuthorityLedger};
use nunchi_bridge::{escrow_address, BridgeError, BridgeLedger, BridgeOperation};
use nunchi_coins::{CoinId, Ledger, LedgerError};
use nunchi_common::{ChainId, EventSink, NoopEventSink, Overlay, Runtime, RuntimeContext, StateStore};
use nunchi_oracle::{OracleError, OracleLedger};

use crate::Transaction;

/// Default coins-chain runtime for the local-development chain.
pub type CoinsRuntime = ConfiguredCoinsRuntime<{ nunchi_common::DEFAULT_CHAIN_ID }>;

/// Coins-chain runtime parameterized by its consensus chain identifier.
///
/// The default is the local-development chain (`0`). Production chains should use a distinct
/// value, for example `ConfiguredCoinsRuntime<1>`, so a transaction signed for another chain is
/// rejected before any fees or state changes are staged.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConfiguredCoinsRuntime<const ID: ChainId>;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("transaction chain id mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: ChainId, actual: ChainId },
    #[error("coins module error: {0}")]
    Coins(#[from] LedgerError),
    #[error("authority module error: {0}")]
    Authority(#[from] AuthorityError),
    #[error("oracle module error: {0}")]
    Oracle(#[from] OracleError),
    #[error("bridge module error: {0}")]
    Bridge(#[from] BridgeError),
}

impl RuntimeError {
    pub fn is_storage(&self) -> bool {
        matches!(
            self,
            Self::Coins(LedgerError::Storage(_))
                | Self::Authority(AuthorityError::Storage(_))
                | Self::Oracle(OracleError::Storage(_))
                | Self::Bridge(BridgeError::Storage(_))
        )
    }
}

impl<const ID: ChainId> Runtime for ConfiguredCoinsRuntime<ID> {
    type Transaction = Transaction;
    type Error = RuntimeError;

    const CHAIN_ID: ChainId = ID;

    async fn validate<S>(
        state: &mut S,
        context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
    {
        apply_transaction::<ID, _, _>(state, context, transaction, NoopEventSink).await
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
        apply_transaction::<ID, _, _>(state, context, transaction, events).await
    }

    fn is_storage_error(error: &Self::Error) -> bool {
        error.is_storage()
    }
}

async fn apply_transaction<const ID: ChainId, S, Events>(
    state: &mut S,
    context: RuntimeContext,
    transaction: &Transaction,
    mut events: Events,
) -> Result<(), RuntimeError>
where
    S: StateStore + Send + Sync,
    Events: EventSink + Send,
{
    if transaction.chain_id() != ConfiguredCoinsRuntime::<ID>::CHAIN_ID {
        return Err(RuntimeError::ChainIdMismatch {
            expected: ConfiguredCoinsRuntime::<ID>::CHAIN_ID,
            actual: transaction.chain_id(),
        });
    }

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
        Transaction::Bridge(transaction) => {
            // Escrow the locked source coins and record the transfer atomically. Both writes go
            // into an inner overlay that is committed only if the whole lock succeeds, so a bridge
            // validation failure after the escrow move (bad nonce, unconfigured chain, self-bridge,
            // unsupported authorization, ...) reverts everything, without relying on the caller to
            // discard partial writes. The bridge crate itself stays decoupled from coins.
            let mut overlay = Overlay::new(&mut *state);
            match &transaction.payload.operation {
                BridgeOperation::Lock {
                    local_asset,
                    amount,
                    ..
                } => {
                    let mut coins = Ledger::new(&mut overlay);
                    coins
                        .transfer(
                            &transaction.account_id,
                            &escrow_address(),
                            CoinId(*local_asset),
                            *amount,
                        )
                        .await?;
                }
            }
            let mut ledger = BridgeLedger::new(&mut overlay);
            ledger.apply_transaction(transaction, events).await?;
            overlay.commit();
        }
    }
    Ok(())
}
