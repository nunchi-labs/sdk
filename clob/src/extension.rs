use std::collections::BTreeSet;

use crate::{ClobLedger, ClobMailbox, ClobOperation, MatchBatch, MarketId};
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
        if ledger.apply_match_batch(payload, context).await.is_err() {
            return false;
        }
        for market in affected_markets(payload) {
            let Ok(Some(market_info)) = ledger.market(&market).await else {
                continue;
            };
            let Ok(sequence) = ledger.market_sequence(&market).await else {
                continue;
            };
            self.mailbox.upsert_market_state(market_info, sequence);
        }
        true
    }
}

fn affected_markets(payload: &MatchBatch) -> BTreeSet<MarketId> {
    let mut markets = BTreeSet::new();
    for tx in &payload.orders {
        if let ClobOperation::PlaceOrder { market, .. } = &tx.payload.operation {
            markets.insert(*market);
        }
    }
    for fill in &payload.fills {
        markets.insert(fill.market);
    }
    markets
}
