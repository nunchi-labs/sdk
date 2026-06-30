use crate::config::PoolConfig;
use crate::error::AdmissionError;
use crate::pool::Pool;
use crate::status::TxStatus;
use crate::tx::PoolTransaction;
use commonware_codec::{Encode, Read};
use commonware_cryptography::{sha256::Digest, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use tracing::{debug, warn};

enum Message<T: PoolTransaction> {
    Submit {
        tx: T,
        responder: oneshot::Sender<Result<Digest, AdmissionError>>,
    },
    Pending {
        limit: usize,
        responder: oneshot::Sender<Vec<T>>,
    },
    Finalized {
        digests: Vec<Digest>,
        lane_nonces: Vec<(T::NonceKey, u64)>,
        height: u64,
    },
    Status {
        digest: Digest,
        responder: oneshot::Sender<Option<TxStatus>>,
    },
}

/// Cloneable ingress handle for a running [`Mempool`].
pub struct MempoolHandle<T: PoolTransaction> {
    sender: mpsc::Sender<Message<T>>,
}

impl<T: PoolTransaction> Clone for MempoolHandle<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<T: PoolTransaction> MempoolHandle<T> {
    /// Submit a transaction for admission, returning its digest on success or
    /// the reason it was refused.
    pub async fn submit(&self, tx: T) -> Result<Digest, AdmissionError> {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender
            .send(Message::Submit { tx, responder })
            .await
            .is_err()
        {
            return Err(AdmissionError::Shutdown);
        }
        receiver.await.unwrap_or(Err(AdmissionError::Shutdown))
    }

    /// Fetch up to `limit` executable transactions, gap-free and ordered by
    /// (nonce lane, nonce). Returns an empty list if the pool has shut down.
    pub async fn pending(&self, limit: usize) -> Vec<T> {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender
            .send(Message::Pending { limit, responder })
            .await
            .is_err()
        {
            return Vec::new();
        }
        receiver.await.unwrap_or_default()
    }

    /// Report a finalized block: the digests it included and each touched
    /// lane's new committed nonce. Fire-and-forget so the consensus
    /// finalize hook never blocks on the pool; a dropped report self-heals on
    /// the next one (re-proposed finalized transactions fail the ledger nonce
    /// gate and are pruned then).
    pub fn finalized(
        &self,
        digests: Vec<Digest>,
        lane_nonces: Vec<(T::NonceKey, u64)>,
        height: u64,
    ) {
        let mut sender = self.sender.clone();
        if sender
            .try_send(Message::Finalized {
                digests,
                lane_nonces,
                height,
            })
            .is_err()
        {
            warn!(
                height,
                "mempool mailbox unavailable; dropping finalization report"
            );
        }
    }

    /// Status of a transaction the pool has seen. In-memory only: history is
    /// lost on restart, and old entries are evicted once the status cache is
    /// at capacity.
    pub async fn status(&self, digest: Digest) -> Option<TxStatus> {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender
            .send(Message::Status { digest, responder })
            .await
            .is_err()
        {
            return None;
        }
        receiver.await.unwrap_or_default()
    }
}

/// The mempool actor. All pool state is owned by a single task; every
/// interaction goes through a [`MempoolHandle`].
pub struct Mempool<T: PoolTransaction> {
    receiver: mpsc::Receiver<Message<T>>,
    pool: Pool<T>,
}

impl<T: PoolTransaction> Mempool<T> {
    /// Create the actor and its handle.
    pub fn new(config: PoolConfig) -> (Self, MempoolHandle<T>) {
        let (sender, receiver) = mpsc::channel(config.mailbox_size);
        (
            Self {
                receiver,
                pool: Pool::new(config),
            },
            MempoolHandle { sender },
        )
    }

    /// Spawn the actor's event loop.
    pub fn start<E: Spawner>(self, context: E) -> Handle<()> {
        InnerActor {
            context: ContextCell::new(context),
            mempool: self,
        }
        .start()
    }

    /// Spawn the actor's event loop with p2p transaction propagation.
    ///
    /// Locally submitted transactions are admitted first, then broadcast to the
    /// overlay. Transactions received from the overlay pass through the same
    /// admission checks, but are not re-broadcast.
    pub fn start_p2p<E, S, R>(self, context: E, p2p: (S, R)) -> Handle<()>
    where
        E: Spawner,
        S: Sender + 'static,
        R: Receiver<PublicKey = S::PublicKey> + 'static,
        T: Encode + Read<Cfg = ()>,
    {
        InnerActor {
            context: ContextCell::new(context),
            mempool: self,
        }
        .start_p2p(p2p)
    }
}

struct InnerActor<E: Spawner, T: PoolTransaction> {
    context: ContextCell<E>,
    mempool: Mempool<T>,
}

impl<E, T> InnerActor<E, T>
where
    E: Spawner,
    T: PoolTransaction,
{
    fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    fn start_p2p<S, R>(mut self, p2p: (S, R)) -> Handle<()>
    where
        S: Sender + 'static,
        R: Receiver<PublicKey = S::PublicKey> + 'static,
        T: Encode + Read<Cfg = ()>,
    {
        spawn_cell!(self.context, self.run_p2p(p2p))
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {},
            message = self.mempool.receiver.next() => {
                let Some(message) = message else {
                    warn!("mempool mailbox closed, stopping runtime");
                    self.context.child("shutdown").spawn(|context| async move {
                        let _ = context.stop(1, None).await;
                    });
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
        T: Encode + Read<Cfg = ()>,
    {
        select_loop! {
            self.context,
            on_stopped => {},
            message = self.mempool.receiver.next() => {
                let Some(message) = message else {
                    warn!("mempool mailbox closed, stopping runtime");
                    self.context.child("shutdown").spawn(|context| async move {
                        let _ = context.stop(1, None).await;
                    });
                    return;
                };
                self.handle_with_gossip(message, &mut sender);
            },
            message = receiver.recv() => {
                match message {
                    Ok((peer, bytes)) => self.handle_network(peer, bytes),
                    Err(error) => {
                        warn!(?error, "mempool p2p receiver closed; continuing node-local");
                        self.run().await;
                        return;
                    }
                }
            },
        }
    }

    fn handle(&mut self, message: Message<T>) {
        match message {
            Message::Submit { tx, responder } => {
                let _ = responder.send(self.mempool.pool.admit(tx));
            }
            Message::Pending { limit, responder } => {
                let _ = responder.send(self.mempool.pool.pending(limit));
            }
            Message::Finalized {
                digests,
                lane_nonces,
                height,
            } => {
                self.mempool.pool.finalize(digests, lane_nonces, height);
            }
            Message::Status { digest, responder } => {
                let _ = responder.send(self.mempool.pool.status_of(&digest));
            }
        }
    }

    fn handle_with_gossip<S>(&mut self, message: Message<T>, sender: &mut S)
    where
        S: Sender,
        T: Encode,
    {
        match message {
            Message::Submit { tx, responder } => {
                let gossip = tx.clone();
                let result = self.mempool.pool.admit(tx);
                if result.is_ok() {
                    let sent = sender.send(Recipients::All, gossip.encode(), false);
                    if sent.is_empty() {
                        debug!("mempool p2p broadcast accepted by no peers");
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
        T: Read<Cfg = ()>,
    {
        match T::read_cfg(&mut bytes, &()) {
            Ok(tx) => match self.mempool.pool.admit(tx) {
                Ok(digest) => debug!(?peer, ?digest, "admitted gossiped transaction"),
                Err(error) => debug!(?peer, ?error, "rejected gossiped transaction"),
            },
            Err(error) => warn!(?peer, ?error, "invalid gossiped transaction"),
        }
    }
}
