//! Deterministic bridge state machine for lock, anchor, and claim operations.
//!
//! The ledger stays decoupled from any asset module. A **lock** records an authenticated
//! [`BridgeTransferRecord`]; an **anchor** pins an attested foreign state root; a **claim** proves a
//! record against an anchored root and marks it consumed exactly once. The actual asset movement
//! (escrow on lock, mint on claim) is performed by the chain's integration layer alongside these
//! calls, in the same overlay, keyed off the returned [`BridgeReceipt`].

use crate::events::{
    foreign_root_anchored_event, transfer_claimed_event, transfer_locked_event, ForeignRootAnchored,
    TransferClaimed, TransferLocked,
};
use crate::record::{
    attestor, bridge_nonce, foreign_root, is_consumed, latest_foreign_view, local_chain_id,
    mark_consumed, put_foreign_root, put_transfer_record, set_bridge_nonce, set_latest_foreign_view,
    transfer_record_key, AssetId, BridgeTransferRecord, ChainId, ForeignRoot, TransferRecordId,
};
use crate::transaction::{BridgeOperation, Transaction};
use commonware_codec::Encode;
use nunchi_common::{
    state_db::{verify_state_update, StateError},
    Address, Authorization, EventSink, StateStore,
};
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
    #[error("anchor attestor is not configured")]
    AttestorNotConfigured,
    #[error("only the configured attestor may anchor foreign roots")]
    NotAttestor,
    #[error("stale anchor: latest view is {latest}, got {submitted}")]
    StaleAnchor { latest: u64, submitted: u64 },
    #[error("claim record does not belong to the claimed source chain")]
    ClaimSourceMismatch,
    #[error("claim record is not destined for this chain")]
    WrongDestination,
    #[error("no anchored foreign root for the claimed (source chain, view)")]
    MissingAnchor,
    #[error("claim proof does not authenticate the record under the anchored root")]
    InvalidProof,
    #[error("transfer record has already been claimed")]
    AlreadyClaimed,
    #[error("state storage error: {0}")]
    Storage(String),
}

impl From<StateError> for BridgeError {
    fn from(err: StateError) -> Self {
        Self::Storage(err.to_string())
    }
}

/// The validated outcome of a bridge operation. The integration layer performs the matching asset
/// movement in the same overlay: escrow the locked coins on [`BridgeReceipt::Locked`], mint the
/// mapped asset to the recipient on [`BridgeReceipt::Claimed`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeReceipt {
    /// A source-chain lock recorded `record_id`.
    Locked(TransferRecordId),
    /// An attested foreign root was anchored for `source_chain_id` at `view`.
    Anchored { source_chain_id: ChainId, view: u64 },
    /// A transfer was claimed and marked consumed; the recipient must be credited `amount` of the
    /// coin mapped from `source_asset`.
    Claimed {
        source_asset: AssetId,
        recipient: Address,
        amount: u128,
    },
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

    /// Verify, authorize, and apply a signed bridge transaction, returning a [`BridgeReceipt`] the
    /// integration layer uses to perform the matching asset movement in the same overlay.
    ///
    /// All operations share single-key authorization and a per-account monotonic bridge nonce.
    pub async fn apply_transaction<Events>(
        &mut self,
        tx: &Transaction,
        mut events: Events,
    ) -> Result<BridgeReceipt, BridgeError>
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

        let receipt = match &tx.payload.operation {
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
                BridgeReceipt::Locked(record_id)
            }

            BridgeOperation::AnchorForeignRoot {
                source_chain_id,
                view,
                state_root,
            } => {
                let attestor = attestor(&self.store)
                    .await?
                    .ok_or(BridgeError::AttestorNotConfigured)?;
                if tx.account_id != attestor {
                    return Err(BridgeError::NotAttestor);
                }
                // Monotonic per source chain so distinct source chains never block one another.
                if let Some(latest) = latest_foreign_view(&self.store, source_chain_id).await? {
                    if *view <= latest {
                        return Err(BridgeError::StaleAnchor {
                            latest,
                            submitted: *view,
                        });
                    }
                }
                let root = ForeignRoot {
                    state_root: *state_root,
                };
                put_foreign_root(&mut self.store, source_chain_id, *view, &root);
                set_latest_foreign_view(&mut self.store, source_chain_id, *view);
                events.emit(foreign_root_anchored_event(ForeignRootAnchored {
                    source_chain_id: *source_chain_id,
                    view: *view,
                    state_root: *state_root,
                }));
                BridgeReceipt::Anchored {
                    source_chain_id: *source_chain_id,
                    view: *view,
                }
            }

            BridgeOperation::Claim {
                source_chain_id,
                source_view,
                record,
                proof,
            } => {
                // The record must belong to the claimed source chain and target this chain.
                if record.source_chain_id != *source_chain_id {
                    return Err(BridgeError::ClaimSourceMismatch);
                }
                let local = local_chain_id(&self.store)
                    .await?
                    .ok_or(BridgeError::ChainNotConfigured)?;
                if record.destination_chain_id != local {
                    return Err(BridgeError::WrongDestination);
                }
                // The foreign root for (source_chain_id, source_view) must be anchored.
                let anchored = foreign_root(&self.store, source_chain_id, *source_view)
                    .await?
                    .ok_or(BridgeError::MissingAnchor)?;
                // The proof must authenticate this exact (content-addressed) record under the root.
                let record_id = record.record_id();
                let key = transfer_record_key(&record_id);
                if !verify_state_update(proof, &anchored.state_root, &key, record.encode().as_ref())
                {
                    return Err(BridgeError::InvalidProof);
                }
                // Exactly-once: a record consumed under its source chain can never be claimed again.
                if is_consumed(&self.store, source_chain_id, &record_id).await? {
                    return Err(BridgeError::AlreadyClaimed);
                }
                mark_consumed(&mut self.store, source_chain_id, &record_id);
                events.emit(transfer_claimed_event(TransferClaimed {
                    record_id,
                    source_chain_id: *source_chain_id,
                    source_view: *source_view,
                    source_asset: record.source_asset,
                    recipient: record.recipient.clone(),
                    amount: record.amount,
                }));
                BridgeReceipt::Claimed {
                    source_asset: record.source_asset,
                    recipient: record.recipient.clone(),
                    amount: record.amount,
                }
            }
        };

        set_bridge_nonce(&mut self.store, &tx.account_id, next_nonce);
        Ok(receipt)
    }
}
