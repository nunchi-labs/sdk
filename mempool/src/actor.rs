use crate::config::PoolConfig;
use crate::error::AdmissionError;
use crate::pool::Pool;
use crate::status::TxStatus;
use crate::tx::PoolTransaction;
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
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
        account_nonces: Vec<(T::AccountId, u64)>,
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
    /// (account, nonce). Returns an empty list if the pool has shut down.
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
    /// account's new committed nonce. Fire-and-forget so the consensus
    /// finalize hook never blocks on the pool; a dropped report self-heals on
    /// the next one (re-proposed finalized transactions fail the ledger nonce
    /// gate and are pruned then).
    pub fn finalized(
        &self,
        digests: Vec<T::Digest>,
        account_nonces: Vec<(T::AccountId, u64)>,
        height: u64,
    ) {
        let mut sender = self.sender.clone();
        if sender
            .try_send(Message::Finalized {
                digests,
                account_nonces,
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
        InnerActor {
            context: ContextCell::new(context),
            mempool: self,
        }
        .start()
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

            match message {
                Message::Submit { tx, responder } => {
                    let _ = responder.send(self.mempool.pool.admit(tx));
                }
                Message::Pending { limit, responder } => {
                    let _ = responder.send(self.mempool.pool.pending(limit));
                }
                Message::Finalized {
                    digests,
                    account_nonces,
                    height,
                } => {
                    self.mempool.pool.finalize(digests, account_nonces, height);
                }
                Message::Status { digest, responder } => {
                    let _ = responder.send(self.mempool.pool.status_of(&digest));
                }
            }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::tx;
    use commonware_runtime::{deterministic, Runner as _};

    #[test]
    fn submit_pending_finalize_status_roundtrip() {
        deterministic::Runner::default().start(|context| async move {
            let (mempool, handle) = Mempool::new(PoolConfig::default());
            mempool.start(context);

            let digest = handle.submit(tx(1, 0, 10)).await.unwrap();
            assert_eq!(digest, 10);
            assert_eq!(handle.status(10).await, Some(TxStatus::Pending));

            let pending = handle.pending(10).await;
            assert_eq!(pending.len(), 1);

            handle.finalized(vec![10], vec![(1, 1)], 5);
            assert_eq!(
                handle.status(10).await,
                Some(TxStatus::Finalized { height: 5 })
            );
            assert!(handle.pending(10).await.is_empty());
        });
    }

    #[test]
    fn submit_reports_rejections() {
        deterministic::Runner::default().start(|context| async move {
            let (mempool, handle) = Mempool::new(PoolConfig::default());
            mempool.start(context);

            handle.submit(tx(1, 0, 10)).await.unwrap();
            assert_eq!(
                handle.submit(tx(1, 0, 10)).await,
                Err(AdmissionError::Duplicate)
            );
        });
    }

    #[test]
    fn status_unknown_digest_is_none() {
        deterministic::Runner::default().start(|context| async move {
            let (mempool, handle) = Mempool::<crate::testing::TestTx>::new(PoolConfig::default());
            mempool.start(context);
            assert_eq!(handle.status(404).await, None);
        });
    }
}
