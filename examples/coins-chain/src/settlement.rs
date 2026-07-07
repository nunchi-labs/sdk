//! Bridges memclob fills into mempool settlement transactions for block inclusion.

use std::collections::HashMap;
use std::time::Duration;

use commonware_cryptography::sha256::Digest;
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Spawner};
use nunchi_clob::{ClobOperation, FillId, Transaction as ClobTransaction};
use nunchi_crypto::PrivateKey;
use nunchi_mempool::{AdmissionError, MempoolHandle, TxStatus};
use nunchi_memclob::MemClobHandle;
use tracing::{debug, warn};

use crate::Transaction;

/// Poll interval for draining memclob fills into the mempool.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Settlement bridge configuration.
#[derive(Clone, Debug)]
pub struct SettlementConfig {
    pub batch_size: usize,
}

impl Default for SettlementConfig {
    fn default() -> Self {
        Self { batch_size: 64 }
    }
}

/// Drains memclob fills into signed [`ClobOperation::CommitFill`] mempool transactions.
pub struct SettlementBridge {
    signer: PrivateKey,
    nonce: u64,
    memclob: MemClobHandle,
    mempool: MempoolHandle<Transaction>,
    config: SettlementConfig,
    queued: HashMap<FillId, Digest>,
}

impl SettlementBridge {
    pub fn new(
        signer: PrivateKey,
        memclob: MemClobHandle,
        mempool: MempoolHandle<Transaction>,
        config: SettlementConfig,
    ) -> Self {
        Self {
            signer,
            nonce: 0,
            memclob,
            mempool,
            config,
            queued: HashMap::new(),
        }
    }

    pub fn start<E: Spawner + Clock>(self, context: E) -> Handle<()> {
        InnerBridge {
            context: ContextCell::new(context),
            bridge: self,
        }
        .start()
    }

    async fn tick(&mut self) {
        self.submit_pending_fills().await;
        self.finalize_settled_fills().await;
    }

    async fn submit_pending_fills(&mut self) {
        let fills = self.memclob.pending_fills(self.config.batch_size).await;
        for fill in fills {
            if self.queued.contains_key(&fill.id) {
                continue;
            }
            let tx = ClobTransaction::sign(
                &self.signer,
                self.nonce,
                ClobOperation::CommitFill { fill: fill.clone() },
            );
            self.nonce = self.nonce.saturating_add(1);
            let wrapped = Transaction::Clob(Box::new(tx));
            match self.mempool.submit(wrapped).await {
                Ok(digest) => {
                    debug!(?fill.id, ?digest, "queued memclob fill for settlement");
                    self.queued.insert(fill.id, digest);
                }
                Err(AdmissionError::Duplicate) => {
                    debug!(?fill.id, "settlement transaction already in mempool");
                }
                Err(error) => {
                    warn!(?fill.id, ?error, "failed to queue memclob fill for settlement");
                }
            }
        }
    }

    async fn finalize_settled_fills(&mut self) {
        let mut committed = Vec::new();
        for (fill_id, digest) in &self.queued {
            if matches!(
                self.mempool.status(*digest).await,
                Some(TxStatus::Finalized { .. })
            ) {
                committed.push(*fill_id);
            }
        }
        if committed.is_empty() {
            return;
        }
        self.queued.retain(|fill_id, _| !committed.contains(fill_id));
        self.memclob.finalize(committed);
    }
}

struct InnerBridge<E: Spawner + Clock> {
    context: ContextCell<E>,
    bridge: SettlementBridge,
}

impl<E: Spawner + Clock> InnerBridge<E> {
    fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {},
            _ = self.context.sleep(POLL_INTERVAL) => {
                self.bridge.tick().await;
            },
        }
    }
}
