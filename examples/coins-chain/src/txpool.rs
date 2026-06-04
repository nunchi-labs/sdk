//! A node's local pool of submitted transactions.

use commonware_cryptography::sha256::Digest;
use commonware_runtime::{Handle, Spawner};
use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use nunchi_coins::Transaction;
use std::collections::BTreeMap;
use tracing::debug;

enum Message {
    /// A client submitted a transaction to this node.
    Submit(Box<Transaction>),
    /// Remove transactions (identified by digest) that have been finalized and applied.
    Prune(Vec<Digest>),
    /// The proposer is asking for up to `limit` pending transactions.
    Pending {
        limit: usize,
        responder: oneshot::Sender<Vec<Transaction>>,
    },
}

/// Ingress handle for a node's transaction pool.
#[derive(Clone)]
pub struct Submitter {
    sender: mpsc::UnboundedSender<Message>,
}

impl Submitter {
    /// Submit a signed transaction to this node.
    pub fn submit(&self, transaction: Transaction) {
        let _ = self
            .sender
            .unbounded_send(Message::Submit(Box::new(transaction)));
    }

    /// Drop the given transactions from the pool.
    /// Called after they are finalized and applied.
    pub fn prune(&self, digests: Vec<Digest>) {
        if digests.is_empty() {
            return;
        }
        let _ = self.sender.unbounded_send(Message::Prune(digests));
    }

    /// Fetch up to `limit` pending transactions, ordered so each signer's transactions are
    /// nonce-ascending.
    pub async fn pending(&self, limit: usize) -> Vec<Transaction> {
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

/// The transaction pool actor for a single node.
pub struct TxPool {
    receiver: mpsc::UnboundedReceiver<Message>,
    pending: BTreeMap<Digest, Transaction>,
}

impl TxPool {
    /// Create a pool actor and its [`Submitter`] handle.
    pub fn new() -> (Self, Submitter) {
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
                    Err(e) => {
                        debug!(
                            txhash = ?transaction.digest(),
                            err = ?e,
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
                    let mut transactions: Vec<Transaction> =
                        self.pending.values().cloned().collect();
                    // Order by (signer, nonce) so a signer's operations stay in nonce order within a
                    // block and therefore apply without tripping the ledger's nonce gate.
                    transactions.sort_by(|a, b| {
                        a.signer
                            .cmp(&b.signer)
                            .then(a.payload.nonce.cmp(&b.payload.nonce))
                    });
                    transactions.truncate(limit);
                    let _ = responder.send(transactions);
                }
            }
        }
    }
}
