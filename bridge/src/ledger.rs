//! Deterministic bridge state machine for source-chain lock operations.
//!
//! The ledger stays decoupled from any asset module: a lock records an authenticated
//! [`BridgeTransferRecord`] and advances the sender's bridge nonce, but the actual movement of the
//! locked asset into escrow is performed by the chain's integration layer alongside this call, in
//! the same overlay.

use crate::events::{transfer_locked_event, TransferLocked};
use crate::record::{
    bridge_nonce, local_chain_id, put_transfer_record, set_bridge_nonce, AssetId,
    BridgeTransferRecord, TransferRecordId,
};
use crate::transaction::{BridgeOperation, Transaction};
use nunchi_common::{state_db::StateError, Authorization, EventSink, StateStore};
use nunchi_crypto::SignatureError;
use thiserror::Error;

/// Errors surfaced while applying a bridge transaction.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum BridgeError {
    #[error("bad transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("unsupported authorization: bridge operations require single-key signatures")]
    UnsupportedAuthorization,
    #[error("nonce mismatch: expected {expected}, got {actual}")]
    NonceMismatch { expected: u64, actual: u64 },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("invalid zero amount")]
    InvalidAmount,
    #[error("destination chain must differ from the source chain")]
    SelfBridge,
    #[error("bridge chain id is not configured")]
    ChainNotConfigured,
    #[error("state storage error: {0}")]
    Storage(String),
}

impl From<StateError> for BridgeError {
    fn from(err: StateError) -> Self {
        Self::Storage(err.to_string())
    }
}

/// Deterministic state machine for bridge operations over a [`StateStore`] backend.
pub struct BridgeLedger<S> {
    store: S,
}

impl<S: StateStore> BridgeLedger<S> {
    /// Wrap a state backend as a bridge ledger.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Borrow the underlying state backend.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Consume the ledger, returning the underlying state backend.
    pub fn into_inner(self) -> S {
        self.store
    }

    /// Verify, authorize, and apply a signed bridge transaction, returning the id of the recorded
    /// transfer.
    ///
    /// Records are content-addressed and append-only; the sender's monotonic bridge nonce gives
    /// each of their transfers a distinct id even when the other fields are identical.
    pub async fn apply_transaction<Events>(
        &mut self,
        tx: &Transaction,
        mut events: Events,
    ) -> Result<TransferRecordId, BridgeError>
    where
        Events: EventSink + Send,
    {
        tx.verify()?;
        // Only single-key authorization is supported. `tx.verify()` binds the signature(s) to
        // `account_id`, but for multisig it does not bind `account_id` to the policy, so trusting a
        // transaction-supplied policy would let a forged policy authorize spending from an arbitrary
        // account. Safely resolving a multisig account's registered policy is a coins concern; until
        // the bridge does that cross-module lookup, multisig authorization is rejected outright
        // rather than accepted unsoundly.
        if !matches!(tx.authorization, Authorization::Single { .. }) {
            return Err(BridgeError::UnsupportedAuthorization);
        }

        let expected = bridge_nonce(&self.store, &tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(BridgeError::NonceMismatch {
                expected,
                actual: tx.payload.nonce,
            });
        }
        let next_nonce = expected.checked_add(1).ok_or(BridgeError::NonceOverflow)?;

        let record_id = match &tx.payload.operation {
            BridgeOperation::Lock {
                destination_chain_id,
                local_asset,
                amount,
                recipient,
            } => {
                if *amount == 0 {
                    return Err(BridgeError::InvalidAmount);
                }
                let source_chain_id = local_chain_id(&self.store)
                    .await?
                    .ok_or(BridgeError::ChainNotConfigured)?;
                if *destination_chain_id == source_chain_id {
                    return Err(BridgeError::SelfBridge);
                }
                let source_asset = AssetId::derive(&source_chain_id, local_asset);
                let record = BridgeTransferRecord {
                    source_chain_id,
                    destination_chain_id: *destination_chain_id,
                    source_asset,
                    amount: *amount,
                    sender: tx.account_id.clone(),
                    recipient: recipient.clone(),
                    nonce: tx.payload.nonce,
                };
                let record_id = record.record_id();
                put_transfer_record(&mut self.store, &record);
                events.emit(transfer_locked_event(TransferLocked {
                    record_id,
                    source_chain_id,
                    destination_chain_id: *destination_chain_id,
                    source_asset,
                    amount: *amount,
                    sender: tx.account_id.clone(),
                    recipient: recipient.clone(),
                    nonce: tx.payload.nonce,
                }));
                record_id
            }
        };

        set_bridge_nonce(&mut self.store, &tx.account_id, next_nonce);
        Ok(record_id)
    }
}
