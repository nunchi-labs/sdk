//! Bridge consensus extension for carrying foreign finalization certificates.
//!
//! A caller submits a foreign finalization through [`BridgeMailbox`]. The actor verifies it
//! against the configured foreign consensus scheme, keeps the newest verified certificate, and
//! [`BridgeExtension`] embeds that certificate in the destination chain's consensus extension.
//! Applying the payload stores the certificate's proposal payload as the certified state root
//! for the one configured foreign chain. Claims prove transfer records against that root.

commonware_macros::stability_scope!(ALPHA {
#[cfg(feature = "rpc")]
pub mod rpc;

pub mod record;
pub use record::{
    escrow_address, foreign_chain_id, foreign_root, is_consumed, mark_consumed, put_foreign_root,
    store_certified_root, transfer_record, transfer_record_key, AssetId, BridgeTransferRecord,
    CertifiedRootStatus, ChainId, ForeignRoot, TransferRecordId, BRIDGE_NAMESPACE,
};

pub mod events;
pub use events::{
    foreign_root_anchored_event, transfer_claimed_event, transfer_locked_event, ForeignRootAnchored,
    TransferClaimed, TransferLocked, FOREIGN_ROOT_ANCHORED_EVENT, TRANSFER_CLAIMED_EVENT,
    TRANSFER_LOCKED_EVENT,
};

pub mod genesis;
pub use genesis::BridgeGenesis;

pub mod ledger;
pub use ledger::{BridgeError, BridgeLedger, BridgeReceipt};

pub mod transaction;
pub use transaction::{
    BridgeOperation, BridgeOperationId, Transaction as BridgeTransaction,
    TransactionPayload as BridgeTransactionPayload,
};

use std::future::Future;

use commonware_consensus::Viewable;
use commonware_parallel::Sequential;
use commonware_runtime::{Handle, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use nunchi_chain::{Block, BlockExtension, ConsensusExtension, Finalized, Notarized};
use nunchi_common::{RuntimeContext, StateStore};
use nunchi_dkg::{Finalization, Scheme};
use rand::{CryptoRng, Rng};
use tracing::warn;

/// Consensus-side bridge payload committed into a block.
pub type BridgePayload = Option<Finalization>;

/// Block type for chains that carry bridge finalization payloads.
pub type BridgeBlock<Tx> = Block<Tx, BridgeExtension>;

/// Notarized block type for chains that carry bridge finalization payloads.
pub type BridgeNotarized<Tx> = Notarized<Tx, BridgeExtension>;

/// Finalized block type for chains that carry bridge finalization payloads.
pub type BridgeFinalized<Tx> = Finalized<Tx, BridgeExtension>;

/// Outcome of submitting a foreign finalization certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitResult {
    /// The certificate failed verification for the configured foreign network.
    Rejected,
    /// The certificate verified and replaced the cached latest finalization.
    Updated,
    /// The certificate verified but was not newer than the cached latest finalization.
    Stale,
}

#[derive(Debug)]
struct State {
    latest: BridgePayload,
}

enum Message {
    Latest {
        responder: oneshot::Sender<BridgePayload>,
    },
    Clear,
    VerifyPayload {
        payload: BridgePayload,
        responder: oneshot::Sender<bool>,
    },
    Submit {
        finalization: Finalization,
        responder: oneshot::Sender<SubmitResult>,
    },
}

/// Cloneable ingress mailbox for a running [`BridgeActor`].
#[derive(Clone, Debug)]
pub struct BridgeMailbox {
    sender: mpsc::Sender<Message>,
}

impl BridgeMailbox {
    /// Return the latest accepted foreign finalization certificate, if any.
    pub async fn latest(&self) -> BridgePayload {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender.send(Message::Latest { responder }).await.is_err() {
            return None;
        }
        receiver.await.unwrap_or_default()
    }

    /// Clear the currently cached foreign finalization certificate.
    pub fn clear(&self) {
        let mut sender = self.sender.clone();
        if sender.try_send(Message::Clear).is_err() {
            warn!("bridge mailbox unavailable; dropping clear request");
        }
    }

    /// Verify a bridge payload against the configured foreign network.
    pub async fn verify_payload(&self, payload: BridgePayload) -> bool {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender
            .send(Message::VerifyPayload { payload, responder })
            .await
            .is_err()
        {
            return false;
        }
        receiver.await.unwrap_or_default()
    }

    /// Submit a foreign finalization certificate.
    ///
    /// Invalid certificates are rejected. Valid stale certificates do not replace the cached latest
    /// certificate.
    pub async fn submit(&self, finalization: Finalization) -> SubmitResult {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender
            .send(Message::Submit {
                finalization,
                responder,
            })
            .await
            .is_err()
        {
            return SubmitResult::Rejected;
        }
        receiver.await.unwrap_or(SubmitResult::Rejected)
    }
}

/// Actor that owns accepted foreign finalization state for a bridge.
pub struct BridgeActor {
    foreign_network: Scheme,
    receiver: mpsc::Receiver<Message>,
    state: State,
}

impl BridgeActor {
    /// Create a bridge actor and its mailbox.
    pub fn new(foreign_network: Scheme, mailbox_size: usize) -> (Self, BridgeMailbox) {
        let (sender, receiver) = mpsc::channel(mailbox_size);
        (
            Self {
                foreign_network,
                receiver,
                state: State { latest: None },
            },
            BridgeMailbox { sender },
        )
    }

    /// Spawn the actor's event loop.
    pub fn start<E>(self, context: E) -> Handle<()>
    where
        E: Spawner + CryptoRng + Rng + Send + 'static,
    {
        context.spawn(|context| self.run(context))
    }

    async fn run<E>(mut self, mut context: E)
    where
        E: CryptoRng + Rng,
    {
        while let Some(message) = self.receiver.next().await {
            match message {
                Message::Latest { responder } => {
                    let _ = responder.send(self.state.latest.clone());
                }
                Message::Clear => {
                    self.state.latest = None;
                }
                Message::VerifyPayload { payload, responder } => {
                    let _ = responder.send(self.verify_payload(&mut context, &payload));
                }
                Message::Submit {
                    finalization,
                    responder,
                } => {
                    let _ = responder.send(self.submit(&mut context, finalization));
                }
            }
        }
    }

    fn verify_payload<R>(&self, rng: &mut R, payload: &BridgePayload) -> bool
    where
        R: CryptoRng + Rng,
    {
        let Some(finalization) = payload else {
            return true;
        };
        finalization.verify(rng, &self.foreign_network, &Sequential)
    }

    fn submit<R>(&mut self, rng: &mut R, finalization: Finalization) -> SubmitResult
    where
        R: CryptoRng + Rng,
    {
        if !self.verify_payload(rng, &Some(finalization.clone())) {
            return SubmitResult::Rejected;
        }

        let replace = match &self.state.latest {
            Some(current) => finalization.view() > current.view(),
            None => true,
        };
        if replace {
            self.state.latest = Some(finalization);
            SubmitResult::Updated
        } else {
            SubmitResult::Stale
        }
    }
}

/// Consensus extension that proposes and verifies foreign finalization certificates.
#[derive(Clone, Debug)]
pub struct BridgeExtension {
    mailbox: BridgeMailbox,
    /// Newest certified view loaded by [`ConsensusExtension::preview`].
    ///
    /// `None` means preview has not seen a stored root. Propose then includes the cached
    /// certificate. A certificate at or behind this view is left out of the next block.
    committed_view: Option<u64>,
}

impl BridgeExtension {
    /// Create a bridge extension from an existing mailbox.
    pub const fn new(mailbox: BridgeMailbox) -> Self {
        Self {
            mailbox,
            committed_view: None,
        }
    }

    /// Return the mailbox used to submit and inspect foreign finalization certificates.
    pub fn mailbox(&self) -> BridgeMailbox {
        self.mailbox.clone()
    }
}

impl BlockExtension for BridgeExtension {
    type Payload = BridgePayload;
    type ReadCfg = ();

    fn genesis_payload() -> Self::Payload {
        None
    }
}

impl ConsensusExtension for BridgeExtension {
    async fn preview<S>(&mut self, state: &mut S)
    where
        S: StateStore + Send + Sync,
    {
        self.committed_view = match foreign_chain_id(state).await {
            Ok(Some(chain)) => record::latest_foreign_view(state, &chain).await.ok().flatten(),
            _ => None,
        };
    }

    async fn propose(&mut self, _context: RuntimeContext) -> Self::Payload {
        let latest = self.mailbox.latest().await;
        match (&latest, self.committed_view) {
            // A certificate that is not newer than the committed root must not be required
            // for the next block. An empty payload is a valid extension.
            (Some(certificate), Some(committed)) if certificate.view().get() <= committed => None,
            _ => latest,
        }
    }

    fn verify_payload(&mut self, payload: &Self::Payload) -> impl Future<Output = bool> + Send {
        self.mailbox.verify_payload(payload.clone())
    }

    /// Record the certificate payload as the foreign chain's claim root.
    ///
    /// Verification stays in [`ConsensusExtension::verify_payload`]. Applying a certified block
    /// must not wait on the bridge actor: a stopped mailbox cannot reject history that already
    /// passed validation. An empty payload, a repeat of the stored root, and an older view leave
    /// the stored root unchanged and still succeed. The same view with a different payload conflicts
    /// and is rejected.
    async fn apply_payload<S>(
        &mut self,
        state: &mut S,
        _context: RuntimeContext,
        payload: &Self::Payload,
    ) -> bool
    where
        S: StateStore + Send + Sync,
    {
        let Some(finalization) = payload else {
            return true;
        };
        match store_certified_root(state, finalization.view().get(), finalization.proposal.payload)
            .await
        {
            Ok(
                CertifiedRootStatus::Stored
                | CertifiedRootStatus::Unchanged
                | CertifiedRootStatus::Unconfigured
                | CertifiedRootStatus::Stale,
            ) => true,
            Ok(CertifiedRootStatus::Conflict) => false,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests;
});
