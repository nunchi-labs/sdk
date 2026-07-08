use crate::{ClobLedger, ClobMailbox, MatchBatch};
use nunchi_chain::{BlockExtension, ConsensusExtension};
use nunchi_common::{RuntimeContext, StateStore};

/// Consensus extension that carries proposer CLOB matches outside the normal mempool.
#[derive(Clone, Debug)]
pub struct ClobExtension {
    mailbox: ClobMailbox,
}

impl ClobExtension {
    pub const fn new(mailbox: ClobMailbox) -> Self {
        Self { mailbox }
    }

    pub fn mailbox(&self) -> ClobMailbox {
        self.mailbox.clone()
    }
}

impl BlockExtension for ClobExtension {
    type Payload = MatchBatch;
    type ReadCfg = ();

    fn genesis_payload() -> Self::Payload {
        MatchBatch::default()
    }
}

impl ConsensusExtension for ClobExtension {
    async fn propose(&mut self) -> Self::Payload {
        self.mailbox.propose().await
    }

    async fn verify_payload(&mut self, payload: &Self::Payload) -> bool {
        payload.orders.iter().all(|tx| tx.verify().is_ok())
    }

    async fn apply_payload<S>(
        &mut self,
        state: &mut S,
        context: RuntimeContext,
        payload: &Self::Payload,
    ) -> bool
    where
        S: StateStore + Send + Sync,
    {
        if payload.is_empty() {
            return true;
        }
        let mut ledger = ClobLedger::new(state);
        ledger.apply_match_batch(payload, context).await.is_ok()
    }
}
