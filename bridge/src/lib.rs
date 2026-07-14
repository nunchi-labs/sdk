//! Bridge consensus extension for carrying foreign finalization certificates.
//!
//! A caller submits verified foreign finalizations through [`BridgeMailbox`],
//! and [`BridgeExtension`] embeds the latest accepted certificate into proposed
//! blocks.

commonware_macros::stability_scope!(ALPHA {
#[cfg(feature = "rpc")]
pub mod rpc;

pub mod record;
pub use record::{
    escrow_address, transfer_record, AssetId, BridgeTransferRecord, ChainId, TransferRecordId,
    BRIDGE_NAMESPACE,
};

pub mod events;
pub use events::{transfer_locked_event, TransferLocked, TRANSFER_LOCKED_EVENT};

pub mod genesis;
pub use genesis::BridgeGenesis;

pub mod ledger;
pub use ledger::{BridgeError, BridgeLedger};

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
use nunchi_dkg::{Finalization, Scheme};
use rand::{CryptoRng, Rng};
use rand_core::CryptoRngCore;
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
        E: Spawner + CryptoRngCore + CryptoRng + Rng + Send + 'static,
    {
        context.spawn(|context| self.run(context))
    }

    async fn run<E>(mut self, mut context: E)
    where
        E: CryptoRngCore + CryptoRng + Rng,
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
        R: CryptoRngCore + CryptoRng + Rng,
    {
        let Some(finalization) = payload else {
            return true;
        };
        finalization.verify(rng, &self.foreign_network, &Sequential)
    }

    fn submit<R>(&mut self, rng: &mut R, finalization: Finalization) -> SubmitResult
    where
        R: CryptoRngCore + CryptoRng + Rng,
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
}

impl BridgeExtension {
    /// Create a bridge extension from an existing mailbox.
    pub const fn new(mailbox: BridgeMailbox) -> Self {
        Self { mailbox }
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
    async fn propose(&mut self) -> Self::Payload {
        self.mailbox.latest().await
    }

    fn verify_payload(&mut self, payload: &Self::Payload) -> impl Future<Output = bool> + Send {
        self.mailbox.verify_payload(payload.clone())
    }
}

#[cfg(test)]
mod tests;
});
