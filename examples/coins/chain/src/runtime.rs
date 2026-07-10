//! Coins-chain runtime execution dispatch.

use commonware_codec::EncodeSize;
use nunchi_authority::{AuthorityError, AuthorityLedger};
use nunchi_bridge::{escrow_address, BridgeError, BridgeLedger, BridgeOperation, BridgeReceipt};
use nunchi_coins::{CoinId, Ledger, LedgerError};
use nunchi_common::{
    state_db::StateError, EventSink, NoopEventSink, Overlay, Runtime, RuntimeContext, StateStore,
    VecEventSink,
};
use nunchi_oracle::{OracleError, OracleLedger};

use crate::bridge_assets::asset_coin;
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
    #[error("bridge module error: {0}")]
    Bridge(#[from] BridgeError),
    #[error("bridge asset is not mapped to a local coin")]
    UnmappedAsset,
    #[error("state storage error: {0}")]
    Storage(String),
}

impl From<StateError> for RuntimeError {
    fn from(err: StateError) -> Self {
        Self::Storage(err.to_string())
    }
}

impl RuntimeError {
    pub fn is_storage(&self) -> bool {
        matches!(
            self,
            Self::Coins(LedgerError::Storage(_))
                | Self::Authority(AuthorityError::Storage(_))
                | Self::Oracle(OracleError::Storage(_))
                | Self::Bridge(BridgeError::Storage(_))
                | Self::Storage(_)
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
        Transaction::Bridge(transaction) => {
            // Lock, anchor, and claim all commit into one inner overlay so their bridge-state
            // effects and the matching coins settlement are atomic: a failure at any step reverts
            // everything, without relying on the caller to discard partial writes. The bridge crate
            // stays decoupled from coins; escrow (on lock) and mint (on claim) happen here.
            let mut overlay = Overlay::new(&mut *state);

            // Preconditions before any bridge-state change.
            match &transaction.payload.operation {
                BridgeOperation::Lock {
                    local_asset,
                    amount,
                    ..
                } => {
                    // Move the locked coins into the bridge escrow.
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
                BridgeOperation::Claim { record, .. } => {
                    // The mapped destination coin must exist before we consume the record or mint.
                    if asset_coin(&overlay, &record.source_asset).await?.is_none() {
                        return Err(RuntimeError::UnmappedAsset);
                    }
                }
                BridgeOperation::AnchorForeignRoot { .. } => {}
            }

            // Apply the bridge operation (verify, replay guard, consume, ...). Buffer its events
            // locally so they are emitted only if the whole operation — including settlement —
            // succeeds; a later settlement failure reverts state and drops these events with it.
            let mut bridge_events = VecEventSink::new();
            let receipt = {
                let mut ledger = BridgeLedger::new(&mut overlay);
                ledger.apply_transaction(transaction, &mut bridge_events).await?
            };

            // Settle a successful claim by minting the mapped asset to the recipient.
            if let BridgeReceipt::Claimed {
                source_asset,
                recipient,
                amount,
            } = receipt
            {
                let coin = asset_coin(&overlay, &source_asset)
                    .await?
                    .ok_or(RuntimeError::UnmappedAsset)?;
                let mut coins = Ledger::new(&mut overlay);
                coins.bridge_mint(&recipient, coin, amount).await?;
            }

            overlay.commit();
            // Now that state has committed, forward the buffered bridge events.
            for event in bridge_events.into_events() {
                events.emit(event);
            }
        }
    }
    Ok(())
}
