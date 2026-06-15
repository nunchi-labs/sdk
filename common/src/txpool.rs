//! Generic transaction pool for chain runtimes.
//!
//! The pool is intentionally runtime-agnostic: a transaction only needs a stable digest, signature
//! verification, and account/nonce ordering. Concrete runtimes can use it with their generated
//! transaction type, while existing modules can use it directly with [`crate::Transaction`].

use std::{collections::BTreeMap, fmt::Debug};

use commonware_cryptography::sha256::Digest;
use commonware_runtime::{Handle, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use tracing::debug;

use crate::{Address, Operation, Transaction};

/// Transaction capabilities required by [`TxPool`].
pub trait PoolTransaction: Clone + Send + 'static {
    /// Signature verification error surfaced when ingress drops a transaction.
    type VerificationError: Debug + Send + Sync + 'static;

    /// Stable transaction digest used for de-duplication and pruning.
    fn digest(&self) -> Digest;

    /// Verify the transaction before admitting it to the local pool.
    fn verify(&self) -> Result<(), Self::VerificationError>;

    /// Authorized account used for deterministic proposal ordering.
    fn account_id(&self) -> &Address;

    /// Account-scoped nonce used for deterministic proposal ordering.
    fn nonce(&self) -> u64;
}

impl<O> PoolTransaction for Transaction<O>
where
    O: Operation + Clone + Send + 'static,
{
    type VerificationError = nunchi_crypto::SignatureError;

    fn digest(&self) -> Digest {
        Transaction::digest(self)
    }

    fn verify(&self) -> Result<(), Self::VerificationError> {
        Transaction::verify(self)
    }

    fn account_id(&self) -> &Address {
        &self.account_id
    }

    fn nonce(&self) -> u64 {
        self.payload.nonce
    }
}

enum Message<T> {
    /// A client submitted a transaction to this node.
    Submit(Box<T>),
    /// Remove transactions (identified by digest) that have been finalized and applied.
    Prune(Vec<Digest>),
    /// The proposer is asking for up to `limit` pending transactions.
    Pending {
        limit: usize,
        responder: oneshot::Sender<Vec<T>>,
    },
}

/// Ingress handle for a node's transaction pool.
pub struct Submitter<T: PoolTransaction> {
    sender: mpsc::UnboundedSender<Message<T>>,
}

impl<T: PoolTransaction> Clone for Submitter<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<T: PoolTransaction> Submitter<T> {
    /// Submit a signed transaction to this node.
    pub fn submit(&self, transaction: T) {
        let _ = self
            .sender
            .unbounded_send(Message::Submit(Box::new(transaction)));
    }

    /// Drop the given transactions from the pool.
    ///
    /// Called after they are finalized and applied.
    pub fn prune(&self, digests: Vec<Digest>) {
        if digests.is_empty() {
            return;
        }
        let _ = self.sender.unbounded_send(Message::Prune(digests));
    }

    /// Fetch up to `limit` pending transactions, ordered by `(account, nonce)`.
    pub async fn pending(&self, limit: usize) -> Vec<T> {
        let (responder, receiver) = oneshot::channel();
        if self
            .sender
            .unbounded_send(Message::Pending { limit, responder })
            .is_err()
        {
            return Vec::new();
        }
        receiver.await.unwrap_or_default()
    }
}

/// Transaction pool actor for a single node.
pub struct TxPool<T: PoolTransaction> {
    receiver: mpsc::UnboundedReceiver<Message<T>>,
    pending: BTreeMap<Digest, T>,
}

impl<T: PoolTransaction> TxPool<T> {
    /// Create a pool actor and its [`Submitter`] handle.
    pub fn new() -> (Self, Submitter<T>) {
        let (sender, receiver) = mpsc::unbounded();
        (
            Self {
                receiver,
                pending: BTreeMap::new(),
            },
            Submitter { sender },
        )
    }

    /// Spawn the pool's event loop.
    pub fn start<E: Spawner>(self, context: E) -> Handle<()> {
        context.spawn(|_| self.run())
    }

    async fn run(mut self) {
        while let Some(message) = self.receiver.next().await {
            match message {
                Message::Submit(transaction) => match transaction.verify() {
                    Ok(_) => {
                        self.pending.insert(transaction.digest(), *transaction);
                    }
                    Err(error) => {
                        debug!(
                            txhash = ?transaction.digest(),
                            ?error,
                            "transaction being dropped"
                        );
                    }
                },
                Message::Prune(digests) => {
                    for digest in digests {
                        self.pending.remove(&digest);
                    }
                }
                Message::Pending { limit, responder } => {
                    let mut transactions: Vec<T> = self.pending.values().cloned().collect();
                    transactions.sort_by(|a, b| {
                        a.account_id()
                            .cmp(b.account_id())
                            .then(a.nonce().cmp(&b.nonce()))
                    });
                    transactions.truncate(limit);
                    let _ = responder.send(transactions);
                }
            }
        }
    }
}
