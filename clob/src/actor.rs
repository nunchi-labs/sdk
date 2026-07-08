use std::collections::BTreeMap;

use crate::{ClobError, MatchBatch, MatchEngine, Market, MarketId, Transaction};
use commonware_runtime::{Handle, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use nunchi_common::RuntimeContext;
use tracing::warn;

/// Runtime settings for the validator-local CLOB actor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClobConfig {
    pub mailbox_size: usize,
}

impl Default for ClobConfig {
    fn default() -> Self {
        Self { mailbox_size: 1024 }
    }
}

enum Message {
    SubmitOrder {
        tx: Transaction,
        responder: oneshot::Sender<Result<(), ClobError>>,
    },
    UpsertMarket {
        market: Market,
    },
    Propose {
        responder: oneshot::Sender<MatchBatch>,
    },
}

/// Cloneable ingress handle for a running validator-local CLOB actor.
#[derive(Clone, Debug)]
pub struct ClobMailbox {
    sender: mpsc::Sender<Message>,
}

impl ClobMailbox {
    /// Submit a signed owner order intent to the local off-chain book.
    pub async fn submit_order(&self, tx: Transaction) -> Result<(), ClobError> {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender.send(Message::SubmitOrder { tx, responder }).await.is_err() {
            return Err(ClobError::ActorStopped);
        }
        receiver.await.unwrap_or(Err(ClobError::ActorStopped))
    }

    /// Make market metadata available to local proposer matching.
    pub fn upsert_market(&self, market: Market) {
        let mut sender = self.sender.clone();
        if sender.try_send(Message::UpsertMarket { market }).is_err() {
            warn!("clob mailbox unavailable; dropping market update");
        }
    }

    /// Drain currently matchable signed orders into one proposed batch.
    pub async fn propose(&self) -> MatchBatch {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender.send(Message::Propose { responder }).await.is_err() {
            return MatchBatch::default();
        }
        receiver.await.unwrap_or_default()
    }
}

/// Validator-local off-chain CLOB actor.
pub struct ClobActor {
    receiver: mpsc::Receiver<Message>,
    pending_orders: Vec<Transaction>,
    markets: BTreeMap<MarketId, Market>,
}

impl ClobActor {
    pub fn new(config: ClobConfig) -> (Self, ClobMailbox) {
        let (sender, receiver) = mpsc::channel(config.mailbox_size);
        (
            Self {
                receiver,
                pending_orders: Vec::new(),
                markets: BTreeMap::new(),
            },
            ClobMailbox { sender },
        )
    }

    pub fn start<E>(self, context: E) -> Handle<()>
    where
        E: Spawner + Send + 'static,
    {
        context.spawn(|_| self.run())
    }

    async fn run(mut self) {
        while let Some(message) = self.receiver.next().await {
            match message {
                Message::SubmitOrder { tx, responder } => {
                    let result = tx.verify().map_err(ClobError::from).map(|_| {
                        self.pending_orders.push(tx);
                    });
                    let _ = responder.send(result);
                }
                Message::UpsertMarket { market } => {
                    self.markets.insert(market.id, market);
                }
                Message::Propose { responder } => {
                    let _ = responder.send(self.propose_batch());
                }
            }
        }
    }

    fn propose_batch(&mut self) -> MatchBatch {
        if self.pending_orders.is_empty() {
            return MatchBatch::default();
        }
        let orders = std::mem::take(&mut self.pending_orders);
        let replay = MatchEngine::replay(
            &orders,
            &self.markets,
            BTreeMap::new(),
            RuntimeContext::default(),
        );
        match replay {
            Ok(result) => MatchBatch {
                orders,
                fills: result.fills,
            },
            Err(error) => {
                warn!(?error, "dropping invalid local clob proposal batch");
                MatchBatch::default()
            }
        }
    }
}
