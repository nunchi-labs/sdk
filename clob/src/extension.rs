use std::collections::BTreeSet;

use crate::{
    BookSnapshot, ClobLedger, ClobMailbox, ClobOperation, MatchBatch, MarketId, Order, OrderId,
};
use nunchi_chain::{BlockExtension, ConsensusExtension};
use nunchi_common::{Address, RuntimeContext, StateStore};
use tracing::warn;

/// Consensus extension that carries proposer CLOB matches outside the normal mempool.
#[derive(Clone, Debug)]
pub struct ClobExtension {
    mailbox: ClobMailbox,
    /// Book staged by [`ConsensusExtension::preview`] for the next proposal.
    ///
    /// Matching reads it once and then restores the committed actor state.
    preview_book: Option<BookSnapshot>,
}

impl ClobExtension {
    pub const fn new(mailbox: ClobMailbox) -> Self {
        Self {
            mailbox,
            preview_book: None,
        }
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
    async fn prepare<S>(&mut self, state: &mut S)
    where
        S: StateStore + Send + Sync,
    {
        match load_book_snapshot(state).await {
            Ok(snapshot) => {
                if let Err(error) = self.mailbox.hydrate(snapshot).await {
                    warn!(?error, "clob actor unavailable while hydrating the committed book");
                }
            }
            Err(error) => {
                warn!(?error, "failed to read the committed clob book; clearing the local matcher");
                if let Err(error) = self.mailbox.hydrate(BookSnapshot::default()).await {
                    warn!(?error, "clob actor unavailable while clearing the local matcher");
                }
            }
        }
    }

    async fn preview<S>(&mut self, state: &mut S)
    where
        S: StateStore + Send + Sync,
    {
        // The preview is consumed by the following `propose`. It is not installed
        // on the actor, so ingress keeps serving the committed book from `prepare`.
        self.preview_book = match load_book_snapshot(state).await {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                warn!(?error, "failed to read the clob book staged for this proposal");
                None
            }
        };
    }

    async fn propose(&mut self, context: RuntimeContext) -> Self::Payload {
        let book = self.preview_book.take();
        self.mailbox.propose_with_book(context, book).await
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
        if payload.is_empty() {
            return;
        }
        let ledger = ClobLedger::new(state);
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

async fn load_book_snapshot<S>(state: &mut S) -> Result<BookSnapshot, crate::ClobError>
where
    S: StateStore + Send + Sync,
{
    let ledger = ClobLedger::new(&mut *state);
    let markets = ledger.markets().await?;
    let mut snapshot = BookSnapshot::default();
    let mut accounts = BTreeSet::new();
    for market in markets {
        accounts.insert(market.created_by.clone());
        let sequence = ledger.market_sequence(&market.id).await?;
        for side in [crate::Side::Bid, crate::Side::Ask] {
            for order in ledger.book(&market.id, side).await? {
                accounts.insert(order.owner.clone());
                if order.status.is_open() && order.remaining_base > 0 {
                    snapshot.orders.push(order);
                }
            }
        }
        // Filled accounts leave the book. Their fills are the remaining record of
        // the nonce until the fill index drops them.
        for fill in ledger.market_fills(&market.id).await? {
            accounts.insert(fill.maker);
            accounts.insert(fill.taker);
        }
        snapshot.markets.push((market, sequence));
    }
    for account in ledger.tracked_accounts().await? {
        accounts.insert(account);
    }
    for account in accounts {
        let nonce = ledger.nonce(&account).await?;
        if nonce > 0 {
            snapshot.nonces.push((account, nonce));
        }
    }
    Ok(snapshot)
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
