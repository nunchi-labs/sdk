use crate::config::PoolConfig;
use crate::error::AdmissionError;
use crate::pool::Pool;
use crate::status::TxStatus;
use crate::tx::PoolTransaction;
use commonware_runtime::{Handle, Spawner};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use tracing::warn;

enum Message<T: PoolTransaction> {
    Submit {
        tx: T,
        responder: oneshot::Sender<Result<T::Digest, AdmissionError>>,
    },
    Pending {
        limit: usize,
        responder: oneshot::Sender<Vec<T>>,
    },
    Finalized {
        digests: Vec<T::Digest>,
        lane_nonces: Vec<(T::NonceKey, u64)>,
        height: u64,
    },
    Status {
        digest: T::Digest,
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
    pub async fn submit(&self, tx: T) -> Result<T::Digest, AdmissionError> {
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
        digests: Vec<T::Digest>,
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
    pub async fn status(&self, digest: T::Digest) -> Option<TxStatus> {
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
        context.spawn(|_| self.run())
    }

    async fn run(mut self) {
        while let Some(message) = self.receiver.next().await {
            match message {
                Message::Submit { tx, responder } => {
                    let _ = responder.send(self.pool.admit(tx));
                }
                Message::Pending { limit, responder } => {
                    let _ = responder.send(self.pool.pending(limit));
                }
                Message::Finalized {
                    digests,
                    lane_nonces,
                    height,
                } => {
                    self.pool.finalize(digests, lane_nonces, height);
                }
                Message::Status { digest, responder } => {
                    let _ = responder.send(self.pool.status_of(&digest));
                }
            }
        }
    }
}
