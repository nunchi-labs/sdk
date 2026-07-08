use std::{
    cmp::Ordering,
    collections::BTreeMap,
};

use crate::{
    fills_equivalent, AssetId, ClobDB, ClobOperation, Fill, FillId, Market, MarketId, MatchBatch,
    MatchEngine, Order, OrderId, Side, Transaction, MAX_ACCOUNT_ORDERS, MAX_BOOK_ORDERS,
    MAX_FILLS_PER_MARKET, MAX_MARKETS, CLOB_NAMESPACE,
};
use commonware_codec::Encode;
use commonware_cryptography::{Hasher, Sha256};
use nunchi_common::{Address, RuntimeContext};
use nunchi_crypto::SignatureError;
use thiserror::Error;

/// Deterministic CLOB state-machine errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ClobError {
    #[error("bad CLOB transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("market already exists")]
    MarketAlreadyExists,
    #[error("market not found")]
    MarketNotFound,
    #[error("market index is full")]
    MarketIndexFull,
    #[error("invalid market: {0}")]
    InvalidMarket(&'static str),
    #[error("order not found")]
    OrderNotFound,
    #[error("order is not open")]
    OrderClosed,
    #[error("order book side is full")]
    BookFull,
    #[error("account order index is full")]
    AccountIndexFull,
    #[error("market fill index is full")]
    FillIndexFull,
    #[error("order book index references a missing order")]
    MissingOrder,
    #[error("cannot cancel order owned by another account")]
    UnauthorizedCancel,
    #[error("invalid order: {0}")]
    InvalidOrder(&'static str),
    #[error("signed order intents are off-chain only")]
    OffchainOnly,
    #[error("proposed match batch does not match deterministic replay")]
    MatchBatchMismatch,
    #[error("fill is already committed")]
    FillAlreadyCommitted,
    #[error("clob actor stopped")]
    ActorStopped,
    #[error("market sequence overflow")]
    SequenceOverflow,
    #[error("quote quantity overflow")]
    QuoteOverflow,
    #[error("state storage error: {0}")]
    Storage(String),
}

/// Deterministic state machine for the central limit order book.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClobLedger<D> {
    pub(crate) db: D,
}

impl<D: ClobDB> ClobLedger<D> {
    /// Wrap a database backend as a CLOB ledger.
    pub fn new(db: D) -> Self {
        Self { db }
    }

    /// Borrow the underlying database.
    pub fn db(&self) -> &D {
        &self.db
    }

    /// Consume the ledger, returning the underlying database.
    pub fn into_inner(self) -> D {
        self.db
    }

    pub async fn nonce(&self, account: &Address) -> Result<u64, ClobError> {
        self.db.nonce(account).await
    }

    pub async fn market(&self, id: &MarketId) -> Result<Option<Market>, ClobError> {
        self.db.market(id).await
    }

    pub async fn market_sequence(&self, id: &MarketId) -> Result<u64, ClobError> {
        self.db.market_sequence(id).await
    }

    pub async fn markets(&self) -> Result<Vec<Market>, ClobError> {
        let ids = self.db.market_index().await?;
        let mut markets = Vec::with_capacity(ids.len());
        for id in ids {
            markets.push(self.db.market(&id).await?.ok_or(ClobError::MarketNotFound)?);
        }
        Ok(markets)
    }

    pub async fn order(&self, id: &OrderId) -> Result<Option<Order>, ClobError> {
        self.db.order(id).await
    }

    pub async fn book(&self, market: &MarketId, side: Side) -> Result<Vec<Order>, ClobError> {
        let ids = self.db.side_book(market, side).await?;
        self.load_orders(ids).await
    }

    pub async fn account_orders(&self, account: &Address) -> Result<Vec<Order>, ClobError> {
        let ids = self.db.account_orders(account).await?;
        self.load_orders(ids).await
    }

    pub async fn fill(&self, id: &FillId) -> Result<Option<Fill>, ClobError> {
        self.db.fill(id).await
    }

    pub async fn market_fills(&self, market: &MarketId) -> Result<Vec<Fill>, ClobError> {
        let ids = self.db.market_fills(market).await?;
        let mut fills = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(fill) = self.db.fill(&id).await? {
                fills.push(fill);
            }
        }
        Ok(fills)
    }

    /// Validate and apply a signed CLOB transaction.
    pub async fn apply_transaction(
        &mut self,
        tx: &Transaction,
        context: RuntimeContext,
    ) -> Result<(), ClobError> {
        tx.verify()?;

        let expected = self.db.nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(ClobError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        self.apply_operation(tx, context).await?;
        let next_nonce = expected.checked_add(1).ok_or(ClobError::NonceOverflow)?;
        self.db.set_nonce(&tx.account_id, next_nonce);
        Ok(())
    }

    async fn apply_operation(
        &mut self,
        tx: &Transaction,
        context: RuntimeContext,
    ) -> Result<(), ClobError> {
        match &tx.payload.operation {
            ClobOperation::CreateMarket {
                base_asset,
                quote_asset,
                tick_size,
                lot_size,
            } => {
                self.create_market(
                    &tx.account_id,
                    *base_asset,
                    *quote_asset,
                    *tick_size,
                    *lot_size,
                    context,
                )
                .await
            }
            ClobOperation::PlaceOrder { .. } | ClobOperation::CancelOrder { .. } => {
                Err(ClobError::OffchainOnly)
            }
            ClobOperation::ApplyMatchBatch { batch } => self.apply_match_batch(batch, context).await,
        }
    }

    async fn create_market(
        &mut self,
        signer: &Address,
        base_asset: AssetId,
        quote_asset: AssetId,
        tick_size: u128,
        lot_size: u128,
        context: RuntimeContext,
    ) -> Result<(), ClobError> {
        validate_market(base_asset, quote_asset, tick_size, lot_size)?;

        let (base_asset, quote_asset) = canonical_asset_pair(base_asset, quote_asset);
        let id = market_id(&base_asset, &quote_asset, tick_size, lot_size);
        if self.db.market(&id).await?.is_some() {
            return Err(ClobError::MarketAlreadyExists);
        }

        let mut markets = self.db.market_index().await?;
        if markets.len() == MAX_MARKETS {
            return Err(ClobError::MarketIndexFull);
        }

        let market = Market {
            id,
            base_asset,
            quote_asset,
            tick_size,
            lot_size,
            created_by: signer.clone(),
            created_at_height: context.height,
            created_at_ms: context.timestamp_ms,
        };
        self.db.set_market(&market);
        markets.push(id);
        self.db.set_market_index(&markets);
        self.db.set_market_sequence(&id, 0);
        Ok(())
    }

    /// Verify and record a proposer match batch from signed order intents.
    pub async fn apply_match_batch(
        &mut self,
        batch: &MatchBatch,
        context: RuntimeContext,
    ) -> Result<(), ClobError> {
        if batch.is_empty() {
            return Ok(());
        }

        let mut markets = BTreeMap::new();
        let mut starting_sequences = BTreeMap::new();
        let mut expected_nonces = BTreeMap::<Address, u64>::new();
        for tx in &batch.orders {
            tx.verify()?;
            let ClobOperation::PlaceOrder { market, .. } = &tx.payload.operation else {
                return Err(ClobError::InvalidOrder(
                    "match batches may only carry signed place-order intents",
                ));
            };
            if self.db.order(&OrderId(tx.digest())).await?.is_some() {
                return Err(ClobError::InvalidOrder("duplicate order id"));
            }
            let expected = match expected_nonces.get(&tx.account_id) {
                Some(expected) => *expected,
                None => self.db.nonce(&tx.account_id).await?,
            };
            if tx.payload.nonce != expected {
                return Err(ClobError::NonceMismatch {
                    account: Box::new(tx.account_id.clone()),
                    expected,
                    actual: tx.payload.nonce,
                });
            }
            expected_nonces.insert(
                tx.account_id.clone(),
                expected.checked_add(1).ok_or(ClobError::NonceOverflow)?,
            );
            if !markets.contains_key(market) {
                let market_info = self
                    .db
                    .market(market)
                    .await?
                    .ok_or(ClobError::MarketNotFound)?;
                markets.insert(*market, market_info);
                starting_sequences.insert(*market, self.db.market_sequence(market).await?);
            }
        }
        let resting_orders = self.load_resting_orders(markets.keys().copied().collect()).await?;

        let replay = MatchEngine::replay_with_resting(
            &resting_orders,
            &batch.orders,
            &markets,
            starting_sequences,
            context,
        )?;
        if replay.fills.len() != batch.fills.len() {
            return Err(ClobError::MatchBatchMismatch);
        }
        if replay.fills.is_empty() {
            return Err(ClobError::MatchBatchMismatch);
        }
        for (expected, proposed) in replay.fills.iter().zip(batch.fills.iter()) {
            if !fills_equivalent(expected, proposed) {
                return Err(ClobError::MatchBatchMismatch);
            }
            if self.db.fill(&expected.id).await?.is_some() {
                return Err(ClobError::FillAlreadyCommitted);
            }
        }

        for fill in &replay.fills {
            let mut market_fills = self.db.market_fills(&fill.market).await?;
            self.db.set_fill(fill);
            market_fills.push(fill.id);
            let pruned_fill_ids = prune_oldest_fill_ids(&mut market_fills);
            for fill_id in pruned_fill_ids {
                self.db.remove_fill(&fill_id);
            }
            self.db.set_market_fills(&fill.market, &market_fills);
        }
        for (order_id, order) in replay.orders {
            self.persist_order_update(order_id, &order).await?;
        }
        for (market, sequence) in replay.sequences {
            self.db.set_market_sequence(&market, sequence);
        }
        for (account, nonce) in expected_nonces {
            self.db.set_nonce(&account, nonce);
        }
        Ok(())
    }

    async fn load_orders(&self, ids: Vec<OrderId>) -> Result<Vec<Order>, ClobError> {
        let mut orders = Vec::with_capacity(ids.len());
        for id in ids {
            orders.push(self.db.order(&id).await?.ok_or(ClobError::MissingOrder)?);
        }
        Ok(orders)
    }

    async fn load_resting_orders(&self, markets: Vec<MarketId>) -> Result<Vec<Order>, ClobError> {
        let mut orders = Vec::new();
        for market in markets {
            for side in [Side::Bid, Side::Ask] {
                let ids = self.db.side_book(&market, side).await?;
                for id in ids {
                    let order = self.db.order(&id).await?.ok_or(ClobError::MissingOrder)?;
                    if order.status.is_open() && order.remaining_base > 0 {
                        orders.push(order);
                    }
                }
            }
        }
        Ok(orders)
    }

    async fn persist_order_update(
        &mut self,
        order_id: OrderId,
        order: &Order,
    ) -> Result<(), ClobError> {
        if order.status.is_open() && order.remaining_base > 0 {
            self.db.set_order(order);
            self.upsert_side_book_order(order).await?;
            self.upsert_account_order(order).await?;
        } else {
            self.remove_side_book_order(order).await?;
            self.remove_account_order(order).await?;
            self.db.remove_order(&order_id);
        }
        Ok(())
    }

    async fn upsert_side_book_order(&mut self, order: &Order) -> Result<(), ClobError> {
        let mut ids = self.db.side_book(&order.market, order.side).await?;
        let was_present = ids.iter().any(|id| id == &order.id);
        ids.retain(|id| id != &order.id);
        if !was_present && ids.len() == MAX_BOOK_ORDERS {
            return Err(ClobError::BookFull);
        }
        ids.push(order.id);
        let mut orders = self.load_existing_book_orders(ids, order).await?;
        orders.sort_by(order_priority_cmp);
        let ids = orders.into_iter().map(|order| order.id).collect::<Vec<_>>();
        self.db.set_side_book(&order.market, order.side, &ids);
        Ok(())
    }

    async fn remove_side_book_order(&mut self, order: &Order) -> Result<(), ClobError> {
        let mut ids = self.db.side_book(&order.market, order.side).await?;
        ids.retain(|id| id != &order.id);
        self.db.set_side_book(&order.market, order.side, &ids);
        Ok(())
    }

    async fn load_existing_book_orders(
        &self,
        ids: Vec<OrderId>,
        updated: &Order,
    ) -> Result<Vec<Order>, ClobError> {
        let mut orders = Vec::with_capacity(ids.len());
        for id in ids {
            if id == updated.id {
                orders.push(updated.clone());
            } else if let Some(order) = self.db.order(&id).await? {
                if order.status.is_open() && order.remaining_base > 0 {
                    orders.push(order);
                }
            }
        }
        Ok(orders)
    }

    async fn upsert_account_order(&mut self, order: &Order) -> Result<(), ClobError> {
        let mut ids = self.db.account_orders(&order.owner).await?;
        let was_present = ids.iter().any(|id| id == &order.id);
        ids.retain(|id| id != &order.id);
        if !was_present && ids.len() == MAX_ACCOUNT_ORDERS {
            return Err(ClobError::AccountIndexFull);
        }
        ids.push(order.id);
        self.db.set_account_orders(&order.owner, &ids);
        Ok(())
    }

    async fn remove_account_order(&mut self, order: &Order) -> Result<(), ClobError> {
        let mut ids = self.db.account_orders(&order.owner).await?;
        ids.retain(|id| id != &order.id);
        self.db.set_account_orders(&order.owner, &ids);
        Ok(())
    }
}

fn order_priority_cmp(left: &Order, right: &Order) -> Ordering {
    match left.side {
        Side::Bid => right
            .price
            .cmp(&left.price)
            .then(left.sequence.cmp(&right.sequence))
            .then(left.id.cmp(&right.id)),
        Side::Ask => left
            .price
            .cmp(&right.price)
            .then(left.sequence.cmp(&right.sequence))
            .then(left.id.cmp(&right.id)),
    }
}

/// Return an asset pair in deterministic ascending order.
pub fn canonical_asset_pair(a: AssetId, b: AssetId) -> (AssetId, AssetId) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Derive the deterministic market id from a normalized asset pair and market parameters.
///
/// Asset ids are sorted before hashing so `A/B` and `B/A` resolve to the same market.
/// `tick_size` and `lot_size` are included so permissionless creation cannot be
/// frontrun with incompatible market parameters.
pub fn market_id(
    base_asset: &AssetId,
    quote_asset: &AssetId,
    tick_size: u128,
    lot_size: u128,
) -> MarketId {
    let (base, quote) = canonical_asset_pair(*base_asset, *quote_asset);
    let mut bytes = CLOB_NAMESPACE.to_vec();
    bytes.extend_from_slice(base.encode().as_ref());
    bytes.extend_from_slice(quote.encode().as_ref());
    bytes.extend_from_slice(tick_size.encode().as_ref());
    bytes.extend_from_slice(lot_size.encode().as_ref());
    MarketId(Sha256::hash(&bytes))
}

pub(crate) fn validate_market(
    base_asset: AssetId,
    quote_asset: AssetId,
    tick_size: u128,
    lot_size: u128,
) -> Result<(), ClobError> {
    if base_asset == quote_asset {
        return Err(ClobError::InvalidMarket(
            "base and quote assets must differ",
        ));
    }
    if tick_size == 0 {
        return Err(ClobError::InvalidMarket("tick size must be non-zero"));
    }
    if lot_size == 0 {
        return Err(ClobError::InvalidMarket("lot size must be non-zero"));
    }
    Ok(())
}

fn prune_oldest_fill_ids(fill_ids: &mut Vec<FillId>) -> Vec<FillId> {
    let excess = fill_ids.len().saturating_sub(MAX_FILLS_PER_MARKET);
    if excess == 0 {
        Vec::new()
    } else {
        fill_ids.drain(..excess).collect()
    }
}
