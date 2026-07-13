use commonware_codec::{Encode, Read};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use nunchi_clob::{Fill, FillId, MarketId, Order, Side, Transaction};
use nunchi_common::RuntimeContext;
use tracing::{debug, warn};

use crate::book::MemBookEngine;
use crate::config::MemClobConfig;
use crate::error::MemClobError;

enum Message {
    Submit {
        tx: Box<Transaction>,
        context: RuntimeContext,
        responder: oneshot::Sender<Result<(), MemClobError>>,
    },
    Book {
        market: MarketId,
        side: Side,
        responder: oneshot::Sender<Vec<Order>>,
    },
    PendingFills {
        limit: usize,
        responder: oneshot::Sender<Vec<Fill>>,
    },
    Finalize {
        fills: Vec<FillId>,
    },
}

/// Cloneable ingress handle for a running [`MemClob`].
#[derive(Clone)]
pub struct MemClobHandle {
    sender: mpsc::Sender<Message>,
}

impl MemClobHandle {
    /// Submit a signed order instruction for local matching and P2P gossip.
    pub async fn submit(
        &self,
        tx: Transaction,
        context: RuntimeContext,
    ) -> Result<(), MemClobError> {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender
            .send(Message::Submit {
                tx: Box::new(tx),
                context,
                responder,
            })
            .await
            .is_err()
        {
            return Err(MemClobError::Shutdown);
        }
        receiver.await.unwrap_or(Err(MemClobError::Shutdown))
    }

    /// Read the current in-memory book side for a market.
    pub async fn book(&self, market: MarketId, side: Side) -> Vec<Order> {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender
            .send(Message::Book {
                market,
                side,
                responder,
            })
            .await
            .is_err()
        {
            return Vec::new();
        }
        receiver.await.unwrap_or_default()
    }

    /// Drain fills waiting for on-chain settlement.
    pub async fn pending_fills(&self, limit: usize) -> Vec<Fill> {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender
            .send(Message::PendingFills { limit, responder })
            .await
            .is_err()
        {
            return Vec::new();
        }
        receiver.await.unwrap_or_default()
    }

    /// Mark fills as committed after block finalization.
    pub fn finalize(&self, fills: Vec<FillId>) {
        let mut sender = self.sender.clone();
        if sender.try_send(Message::Finalize { fills }).is_err() {
            warn!("memclob mailbox unavailable; dropping finalization report");
        }
    }
}

/// Single-owner in-memory order book actor.
pub struct MemClob {
    receiver: mpsc::Receiver<Message>,
    engine: MemBookEngine,
}

impl MemClob {
    pub fn new(config: MemClobConfig) -> (Self, MemClobHandle) {
        let (sender, receiver) = mpsc::channel(config.mailbox_size.get());
        (
            Self {
                receiver,
                engine: MemBookEngine::with_dedup_capacity(config.dedup_capacity),
            },
            MemClobHandle { sender },
        )
    }

    pub fn engine(&self) -> &MemBookEngine {
        &self.engine
    }

    pub fn start<E: Spawner>(self, context: E) -> Handle<()> {
        InnerActor {
            context: ContextCell::new(context),
            memclob: self,
        }
        .start()
    }

    pub fn start_p2p<E, S, R>(self, context: E, p2p: (S, R)) -> Handle<()>
    where
        E: Spawner,
        S: Sender + 'static,
        R: Receiver<PublicKey = S::PublicKey> + 'static,
        Transaction: Read<Cfg = ()>,
    {
        InnerActor {
            context: ContextCell::new(context),
            memclob: self,
        }
        .start_p2p(p2p)
    }
}

struct InnerActor<E: Spawner> {
    context: ContextCell<E>,
    memclob: MemClob,
}

impl<E> InnerActor<E>
where
    E: Spawner,
{
    fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    fn start_p2p<S, R>(mut self, p2p: (S, R)) -> Handle<()>
    where
        S: Sender + 'static,
        R: Receiver<PublicKey = S::PublicKey> + 'static,
        Transaction: Read<Cfg = ()>,
    {
        spawn_cell!(self.context, self.run_p2p(p2p))
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {},
            message = self.memclob.receiver.next() => {
                let Some(message) = message else {
                    warn!("memclob mailbox closed, stopping runtime");
                    return;
                };
                self.handle(message);
            },
        }
    }

    async fn run_p2p<S, R>(mut self, (mut sender, mut receiver): (S, R))
    where
        S: Sender,
        R: Receiver<PublicKey = S::PublicKey>,
        Transaction: Read<Cfg = ()>,
    {
        select_loop! {
            self.context,
            on_stopped => {},
            message = self.memclob.receiver.next() => {
                let Some(message) = message else {
                    warn!("memclob mailbox closed, stopping runtime");
                    return;
                };
                self.handle_with_gossip(message, &mut sender);
            },
            message = receiver.recv() => {
                match message {
                    Ok((peer, bytes)) => self.handle_network(peer, bytes),
                    Err(error) => {
                        warn!(?error, "memclob p2p receiver closed; continuing node-local");
                        self.run().await;
                        return;
                    }
                }
            },
        }
    }

    fn handle(&mut self, message: Message) {
        match message {
            Message::Submit {
                tx,
                context,
                responder,
            } => {
                let result = self
                    .memclob
                    .engine
                    .apply_transaction(tx.as_ref(), context)
                    .map_err(MemClobError::from);
                let _ = responder.send(result);
            }
            Message::Book {
                market,
                side,
                responder,
            } => {
                let _ = responder.send(self.memclob.engine.book(&market, side));
            }
            Message::PendingFills { limit, responder } => {
                let _ = responder.send(self.memclob.engine.pending_fills_since(limit));
            }
            Message::Finalize { fills } => {
                self.memclob.engine.finalize_settlement(&fills);
            }
        }
    }

    fn handle_with_gossip<S>(&mut self, message: Message, sender: &mut S)
    where
        S: Sender,
    {
        match message {
            Message::Submit {
                tx,
                context,
                responder,
            } => {
                let gossip = tx.as_ref().clone();
                let result = self
                    .memclob
                    .engine
                    .apply_transaction(tx.as_ref(), context)
                    .map_err(MemClobError::from);
                if result.is_ok() {
                    let sent = sender.send(Recipients::All, gossip.encode(), false);
                    if sent.is_empty() {
                        debug!("memclob p2p broadcast accepted by no peers");
                    }
                }
                let _ = responder.send(result);
            }
            message => self.handle(message),
        }
    }

    fn handle_network<P>(&mut self, peer: P, mut bytes: commonware_runtime::IoBuf)
    where
        P: PublicKey,
        Transaction: Read<Cfg = ()>,
    {
        match Transaction::read_cfg(&mut bytes, &()) {
            Ok(tx) => {
                let context = RuntimeContext {
                    epoch: 0,
                    height: 0,
                    timestamp_ms: 0,
                    block_digest: None,
                };
                match self.memclob.engine.apply_transaction(&tx, context) {
                    Ok(()) => debug!(?peer, "admitted gossiped memclob instruction"),
                    Err(error) => debug!(?peer, ?error, "rejected gossiped memclob instruction"),
                }
            }
            Err(error) => warn!(?peer, ?error, "invalid gossiped memclob frame"),
        }
    }
}
