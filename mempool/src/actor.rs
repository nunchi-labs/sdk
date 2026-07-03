use crate::config::PoolConfig;
use crate::error::AdmissionError;
use crate::metrics::{MempoolMetrics, SubmitSource};
use crate::pool::Pool;
use crate::status::TxStatus;
use crate::tx::PoolTransaction;
use commonware_codec::{Encode, Read};
use commonware_cryptography::{sha256::Digest, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, ContextCell, Handle, Metrics as RuntimeMetrics, Spawner};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use std::{
    sync::{Arc, OnceLock},
    time::Instant,
};
use tracing::{debug, warn};

enum Message<T: PoolTransaction> {
    Submit {
        tx: T,
        responder: oneshot::Sender<Result<Digest, AdmissionError>>,
    },
    SubmitMany {
        txs: Vec<(usize, T)>,
        responder: oneshot::Sender<Vec<(usize, Result<Digest, AdmissionError>)>>,
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
    config: PoolConfig,
    metrics: Arc<OnceLock<MempoolMetrics>>,
}

impl<T: PoolTransaction> Clone for MempoolHandle<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            config: self.config.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl<T: PoolTransaction> MempoolHandle<T> {
    /// Submit a transaction for admission, returning its digest on success or
    /// the reason it was refused.
    pub async fn submit(&self, tx: T) -> Result<Digest, AdmissionError> {
        let started = Instant::now();
        if let Some(metrics) = self.metrics.get() {
            metrics.submitted(SubmitSource::Rpc, 1);
        }
        if let Err(error) = Pool::check_stateless(&tx, &self.config) {
            let result = Err(error);
            self.record_submission_result(&result);
            self.record_submit_duration(started);
            return result;
        }
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender
            .send(Message::Submit { tx, responder })
            .await
            .is_err()
        {
            let result = Err(AdmissionError::Shutdown);
            self.record_submission_result(&result);
            self.record_submit_duration(started);
            return result;
        }
        let result = receiver.await.unwrap_or(Err(AdmissionError::Shutdown));
        self.record_submit_duration(started);
        result
    }

    /// Submit many transactions with one mailbox round trip. Statelessly invalid
    /// transactions are rejected before the actor is enqueued.
    pub async fn submit_many(&self, txs: Vec<T>) -> Vec<Result<Digest, AdmissionError>> {
        let started = Instant::now();
        if let Some(metrics) = self.metrics.get() {
            metrics.submitted(SubmitSource::RpcBatch, txs.len() as u64);
        }
        let mut results = vec![None; txs.len()];
        let mut verified = Vec::with_capacity(txs.len());
        for (index, tx) in txs.into_iter().enumerate() {
            match Pool::check_stateless(&tx, &self.config) {
                Ok(()) => verified.push((index, tx)),
                Err(error) => {
                    let result = Err(error);
                    self.record_submission_result(&result);
                    results[index] = Some(result);
                }
            }
        }
        if verified.is_empty() {
            let results = results
                .into_iter()
                .map(|result| result.expect("every result is filled"))
                .collect();
            self.record_submit_duration(started);
            return results;
        }

        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        let submitted = verified.len();
        if sender
            .send(Message::SubmitMany {
                txs: verified,
                responder,
            })
            .await
            .is_err()
        {
            for result in &mut results {
                if result.is_none() {
                    let shutdown = Err(AdmissionError::Shutdown);
                    self.record_submission_result(&shutdown);
                    *result = Some(shutdown);
                }
            }
            let results = results
                .into_iter()
                .map(|result| result.expect("every result is filled"))
                .collect();
            self.record_submit_duration(started);
            return results;
        }

        match receiver.await {
            Ok(admitted) => {
                for (index, result) in admitted {
                    results[index] = Some(result);
                }
            }
            Err(_) => {
                let mut remaining = submitted;
                for result in &mut results {
                    if result.is_none() {
                        let shutdown = Err(AdmissionError::Shutdown);
                        self.record_submission_result(&shutdown);
                        *result = Some(shutdown);
                        remaining -= 1;
                        if remaining == 0 {
                            break;
                        }
                    }
                }
            }
        }
        let results = results
            .into_iter()
            .map(|result| result.expect("every result is filled"))
            .collect();
        self.record_submit_duration(started);
        results
    }

    /// Fetch up to `limit` executable transactions, gap-free within each nonce
    /// lane. Returns an empty list if the pool has shut down.
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

    fn record_submission_result(&self, result: &Result<Digest, AdmissionError>) {
        if let Some(metrics) = self.metrics.get() {
            metrics.submission_result(result);
        }
    }

    fn record_submit_duration(&self, started: Instant) {
        if let Some(metrics) = self.metrics.get() {
            metrics
                .submit_duration
                .observe(started.elapsed().as_secs_f64());
        }
    }
}

/// The mempool actor. All pool state is owned by a single task; every
/// interaction goes through a [`MempoolHandle`].
pub struct Mempool<T: PoolTransaction> {
    receiver: mpsc::Receiver<Message<T>>,
    pool: Pool<T>,
    metrics: Arc<OnceLock<MempoolMetrics>>,
}

impl<T: PoolTransaction> Mempool<T> {
    /// Create the actor and its handle.
    pub fn new(config: PoolConfig) -> (Self, MempoolHandle<T>) {
        let (sender, receiver) = mpsc::channel(config.mailbox_size);
        let metrics = Arc::new(OnceLock::new());
        let mut pool = Pool::new(config.clone());
        pool.set_metrics(metrics.clone());
        (
            Self {
                receiver,
                pool,
                metrics: metrics.clone(),
            },
            MempoolHandle {
                sender,
                config,
                metrics,
            },
        )
    }

    /// Spawn the actor's event loop.
    pub fn start<E: Spawner + RuntimeMetrics>(self, context: E) -> Handle<()> {
        self.register_metrics(&context);
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
        E: Spawner + RuntimeMetrics,
        S: Sender + 'static,
        R: Receiver<PublicKey = S::PublicKey> + 'static,
        T: Encode + Read<Cfg = ()>,
    {
        self.register_metrics(&context);
        InnerActor {
            context: ContextCell::new(context),
            mempool: self,
        }
        .start_p2p(p2p)
    }

    fn register_metrics<E: RuntimeMetrics>(&self, context: &E) {
        let _ = self.metrics.set(MempoolMetrics::register(context));
    }
}

struct InnerActor<E: Spawner + RuntimeMetrics, T: PoolTransaction> {
    context: ContextCell<E>,
    mempool: Mempool<T>,
}

impl<E, T> InnerActor<E, T>
where
    E: Spawner + RuntimeMetrics,
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
                let result = self.mempool.pool.admit_verified(tx);
                self.record_submission_result(&result);
                let _ = responder.send(result);
            }
            Message::SubmitMany { txs, responder } => {
                let results = txs
                    .into_iter()
                    .map(|(index, tx)| {
                        let result = self.mempool.pool.admit_verified(tx);
                        self.record_submission_result(&result);
                        (index, result)
                    })
                    .collect();
                let _ = responder.send(results);
            }
            Message::Pending { limit, responder } => {
                let started = Instant::now();
                let pending = self.mempool.pool.pending(limit);
                if let Some(metrics) = self.mempool.metrics.get() {
                    metrics.pending(pending.len() as u64);
                    metrics
                        .pending_duration
                        .observe(started.elapsed().as_secs_f64());
                }
                let _ = responder.send(pending);
            }
            Message::Finalized {
                digests,
                lane_nonces,
                height,
            } => {
                let started = Instant::now();
                self.mempool.pool.finalize(digests, lane_nonces, height);
                if let Some(metrics) = self.mempool.metrics.get() {
                    metrics
                        .finalize_duration
                        .observe(started.elapsed().as_secs_f64());
                }
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
                let result = self.mempool.pool.admit_verified(tx);
                self.record_submission_result(&result);
                if result.is_ok() {
                    let sent = sender.send(Recipients::All, gossip.encode(), false);
                    if sent.is_empty() {
                        debug!("mempool p2p broadcast accepted by no peers");
                    }
                }
                let _ = responder.send(result);
            }
            Message::SubmitMany { txs, responder } => {
                let results = txs
                    .into_iter()
                    .map(|(index, tx)| {
                        let gossip = tx.clone();
                        let result = self.mempool.pool.admit_verified(tx);
                        self.record_submission_result(&result);
                        if result.is_ok() {
                            let sent = sender.send(Recipients::All, gossip.encode(), false);
                            if sent.is_empty() {
                                debug!("mempool p2p broadcast accepted by no peers");
                            }
                        }
                        (index, result)
                    })
                    .collect();
                let _ = responder.send(results);
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
            Ok(tx) => {
                if let Some(metrics) = self.mempool.metrics.get() {
                    metrics.submitted(SubmitSource::P2p, 1);
                }
                let result = Pool::check_stateless(&tx, &self.mempool.pool.config())
                    .and_then(|()| self.mempool.pool.admit_verified(tx));
                self.record_submission_result(&result);
                match result {
                    Ok(digest) => debug!(?peer, ?digest, "admitted gossiped transaction"),
                    Err(error) => debug!(?peer, ?error, "rejected gossiped transaction"),
                }
            }
            Err(error) => warn!(?peer, ?error, "invalid gossiped transaction"),
        }
    }

    fn record_submission_result(&self, result: &Result<Digest, AdmissionError>) {
        if let Some(metrics) = self.mempool.metrics.get() {
            metrics.submission_result(result);
        }
    }
}
