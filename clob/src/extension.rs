use std::collections::BTreeSet;

use crate::{
    ClobDB, ClobError, ClobLedger, ClobMailbox, ClobOperation, MatchBatch, MarketId, Order,
    OrderId,
};
use nunchi_chain::{BlockExtension, ConsensusExtension};
use nunchi_common::{Address, RuntimeContext, StateStore};
use tracing::warn;

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

    async fn propose_from_state<S>(
        &mut self,
        state: &mut S,
        _context: RuntimeContext,
    ) -> Self::Payload
    where
        S: StateStore + Send + Sync,
    {
        // The proposal state already includes create-market nonce accounts. The
        // actor's map does not, until this block commits.
        let indexed = {
            let ledger = ClobLedger::new(&mut *state);
            match ledger.db.nonce_accounts().await {
                Ok(accounts) => Some(accounts),
                Err(error) => {
                    warn!(?error, "failed to read clob nonce index before proposal");
                    None
                }
            }
        };
        self.mailbox.propose_with_indexed(indexed).await
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

    async fn commit_payload<S>(
        &mut self,
        state: &mut S,
        _context: RuntimeContext,
        payload: &Self::Payload,
    ) where
        S: StateStore + Send + Sync,
    {
        let ledger = ClobLedger::new(state);
        // Create-market writes the signer into the nonce index without a match batch.
        // Sync that account or the next proposal spends a slot the ledger already filled.
        match market_creator_nonces(&ledger).await {
            Ok(updates) => {
                if let Err(error) = self.mailbox.sync_nonces(updates).await {
                    warn!(?error, "failed to sync clob market-creator nonces");
                }
            }
            Err(error) => warn!(?error, "failed to read clob market-creator nonces"),
        }
        if payload.is_empty() {
            return;
        }
        let order_updates = order_updates(&ledger, payload).await;
        let nonce_updates = nonce_updates(&ledger, payload).await;
        let accepted_order_ids = accepted_order_ids(payload);
        for market in affected_markets(payload) {
            let Ok(Some(market_info)) = ledger.market(&market).await else {
                continue;
            };
            let Ok(sequence) = ledger.market_sequence(&market).await else {
                continue;
            };
            if let Err(error) = self
                .mailbox
                .sync_accepted(
                    market_info,
                    sequence,
                    accepted_order_ids.clone(),
                    order_updates.clone(),
                    nonce_updates.clone(),
                )
                .await
            {
                warn!(?error, "clob actor unavailable while syncing accepted payload");
            }
        }
    }
}

async fn market_creator_nonces<S>(
    ledger: &ClobLedger<&mut S>,
) -> Result<Vec<(Address, u64)>, ClobError>
where
    S: StateStore + Send + Sync,
{
    let indexed = ledger.db.nonce_accounts().await?;
    if indexed.is_empty() {
        return Ok(Vec::new());
    }
    let indexed = indexed.into_iter().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut updates = Vec::new();
    for id in ledger.db.market_index().await? {
        let Some(market) = ledger.market(&id).await? else {
            continue;
        };
        if !indexed.contains(&market.created_by) || !seen.insert(market.created_by.clone()) {
            continue;
        }
        let nonce = ledger.nonce(&market.created_by).await?;
        updates.push((market.created_by, nonce));
    }
    Ok(updates)
}

async fn order_updates<S>(
    ledger: &ClobLedger<&mut S>,
    payload: &MatchBatch,
) -> Vec<(OrderId, Option<Order>)>
where
    S: StateStore + Send + Sync,
{
    let mut updates = Vec::new();
    for order_id in accepted_order_ids(payload) {
        if let Ok(order) = ledger.order(&order_id).await {
            updates.push((order_id, order));
        }
    }
    updates
}

async fn nonce_updates<S>(ledger: &ClobLedger<&mut S>, payload: &MatchBatch) -> Vec<(Address, u64)>
where
    S: StateStore + Send + Sync,
{
    let mut updates = Vec::new();
    for account in accepted_accounts(payload) {
        if let Ok(nonce) = ledger.nonce(&account).await {
            updates.push((account, nonce));
        }
    }
    updates
}

fn accepted_accounts(payload: &MatchBatch) -> Vec<Address> {
    let mut accounts = BTreeSet::new();
    for tx in &payload.orders {
        accounts.insert(tx.account_id.clone());
    }
    accounts.into_iter().collect()
}

fn accepted_order_ids(payload: &MatchBatch) -> Vec<OrderId> {
    let mut orders = BTreeSet::new();
    for tx in &payload.orders {
        orders.insert(OrderId(tx.digest()));
    }
    for fill in &payload.fills {
        orders.insert(fill.maker_order);
        orders.insert(fill.taker_order);
    }
    orders.into_iter().collect()
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
