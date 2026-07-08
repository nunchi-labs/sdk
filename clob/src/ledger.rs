use crate::{
    AssetId, ClobDB, ClobOperation, Fill, FillId, Market, MarketId, Order, OrderId, OrderStatus,
    Side, TimeInForce, Transaction, MAX_ACCOUNT_ORDERS, MAX_BOOK_ORDERS, MAX_MARKETS,
    MAX_FILLS_PER_MARKET, CLOB_NAMESPACE,
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

/// Inputs for programmatic order placement by consuming modules such as perps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaceOrderParams {
    pub owner: Address,
    pub order_id: OrderId,
    pub market: MarketId,
    pub side: Side,
    pub price: u128,
    pub base_quantity: u128,
    pub time_in_force: TimeInForce,
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
            fills.push(self.db.fill(&id).await?.ok_or(ClobError::MissingOrder)?);
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
            ClobOperation::PlaceOrder {
                market,
                side,
                price,
                base_quantity,
                time_in_force,
            } => {
                self.place_order(
                    &PlaceOrderParams {
                        owner: tx.account_id.clone(),
                        order_id: OrderId(tx.digest()),
                        market: *market,
                        side: *side,
                        price: *price,
                        base_quantity: *base_quantity,
                        time_in_force: *time_in_force,
                    },
                    context,
                )
                .await
                .map(|_| ())
            }
            ClobOperation::CancelOrder { order } => self.cancel_order(&tx.account_id, order).await,
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

    /// Place and match an order against the current book.
    ///
    /// Self-trade prevention is intentionally not enforced: orders from the same
    /// account may match against each other.
    pub async fn place_order(
        &mut self,
        params: &PlaceOrderParams,
        context: RuntimeContext,
    ) -> Result<Order, ClobError> {
        let PlaceOrderParams {
            owner,
            order_id,
            market: market_id,
            side,
            price,
            base_quantity,
            time_in_force,
        } = params;
        let market = self
            .db
            .market(market_id)
            .await?
            .ok_or(ClobError::MarketNotFound)?;
        validate_order(&market, *price, *base_quantity)?;

        if self.db.order(order_id).await?.is_some() {
            return Err(ClobError::InvalidOrder("duplicate order id"));
        }

        let account_orders = self.db.account_orders(owner).await?;
        if account_orders.len() == MAX_ACCOUNT_ORDERS {
            return Err(ClobError::AccountIndexFull);
        }

        let opposite_side = side.opposite();
        let opposite_ids = self.db.side_book(market_id, opposite_side).await?;
        let opposite_orders = self.load_orders(opposite_ids).await?;
        let simulation = simulate_matches(*side, *price, *base_quantity, &opposite_orders)?;

        let mut market_fill_ids = self.db.market_fills(market_id).await?;

        if *time_in_force == TimeInForce::GoodTilCancelled && simulation.remaining_base > 0 {
            let same_side_book = self.db.side_book(market_id, *side).await?;
            if same_side_book.len() == MAX_BOOK_ORDERS {
                return Err(ClobError::BookFull);
            }
        }

        let sequence = self.next_sequence(market_id).await?;
        let mut taker = Order {
            id: *order_id,
            owner: owner.clone(),
            market: *market_id,
            side: *side,
            price: *price,
            original_base: *base_quantity,
            remaining_base: *base_quantity,
            filled_base: 0,
            status: OrderStatus::Open,
            sequence,
            created_at_height: context.height,
            created_at_ms: context.timestamp_ms,
        };

        let mut updated_opposite_book = Vec::with_capacity(opposite_orders.len());
        for idx in 0..opposite_orders.len() {
            if taker.remaining_base == 0 {
                append_open_orders(&mut updated_opposite_book, &opposite_orders[idx..]);
                break;
            }

            let mut maker = opposite_orders[idx].clone();
            if !maker.status.is_open() || maker.remaining_base == 0 {
                continue;
            }
            if !side.crosses(*price, maker.price) {
                append_open_orders(&mut updated_opposite_book, &opposite_orders[idx..]);
                break;
            }

            let base = taker.remaining_base.min(maker.remaining_base);
            let quote = maker
                .price
                .checked_mul(base)
                .ok_or(ClobError::QuoteOverflow)?;
            let fill_sequence = self.next_sequence(market_id).await?;
            let fill = Fill {
                id: fill_id(&taker.id, &maker.id, fill_sequence),
                market: *market_id,
                maker_order: maker.id,
                taker_order: taker.id,
                maker: maker.owner.clone(),
                taker: taker.owner.clone(),
                taker_side: *side,
                price: maker.price,
                base_quantity: base,
                quote_quantity: quote,
                sequence: fill_sequence,
                written_at_height: context.height,
                written_at_ms: context.timestamp_ms,
            };

            taker.remaining_base -= base;
            taker.filled_base += base;
            maker.remaining_base -= base;
            maker.filled_base += base;
            maker.status = if maker.remaining_base == 0 {
                OrderStatus::Filled
            } else {
                OrderStatus::PartiallyFilled
            };

            self.db.set_fill(&fill);
            market_fill_ids.push(fill.id);
            self.db.set_order(&maker);
            if maker.status.is_open() && maker.remaining_base > 0 {
                updated_opposite_book.push(maker.id);
            } else {
                self.remove_from_account_orders(&maker.owner, &maker.id)
                    .await?;
            }
        }

        let pruned_fill_ids = prune_oldest_fill_ids(&mut market_fill_ids);
        for fill_id in pruned_fill_ids {
            self.db.remove_fill(&fill_id);
        }

        self.db
            .set_side_book(market_id, opposite_side, &updated_opposite_book);
        self.db.set_market_fills(market_id, &market_fill_ids);

        taker.status = if taker.remaining_base == 0 {
            OrderStatus::Filled
        } else if *time_in_force == TimeInForce::ImmediateOrCancel {
            OrderStatus::Expired
        } else if taker.filled_base == 0 {
            OrderStatus::Open
        } else {
            OrderStatus::PartiallyFilled
        };

        self.db.set_order(&taker);
        if taker.status.is_open() {
            let mut account_orders = self.db.account_orders(owner).await?;
            account_orders.push(taker.id);
            self.db.set_account_orders(owner, &account_orders);
            if taker.remaining_base > 0 {
                self.insert_resting_order(&taker).await?;
            }
        } else {
            self.remove_from_account_orders(owner, &taker.id).await?;
        }
        Ok(taker)
    }

    async fn cancel_order(
        &mut self,
        signer: &Address,
        order_id: &OrderId,
    ) -> Result<(), ClobError> {
        let mut order = self
            .db
            .order(order_id)
            .await?
            .ok_or(ClobError::OrderNotFound)?;
        if order.owner != *signer {
            return Err(ClobError::UnauthorizedCancel);
        }
        if !order.status.is_open() || order.remaining_base == 0 {
            return Err(ClobError::OrderClosed);
        }

        let mut book = self.db.side_book(&order.market, order.side).await?;
        book.retain(|id| id != order_id);
        self.db.set_side_book(&order.market, order.side, &book);

        order.status = OrderStatus::Cancelled;
        self.db.set_order(&order);
        self.remove_from_account_orders(&order.owner, order_id).await?;
        Ok(())
    }

    async fn remove_from_account_orders(
        &mut self,
        owner: &Address,
        order_id: &OrderId,
    ) -> Result<(), ClobError> {
        let mut orders = self.db.account_orders(owner).await?;
        let before = orders.len();
        orders.retain(|id| id != order_id);
        if orders.len() != before {
            self.db.set_account_orders(owner, &orders);
        }
        Ok(())
    }

    async fn insert_resting_order(&mut self, order: &Order) -> Result<(), ClobError> {
        let mut book = self.db.side_book(&order.market, order.side).await?;
        if book.len() == MAX_BOOK_ORDERS {
            return Err(ClobError::BookFull);
        }

        let mut insert_at = book.len();
        for (idx, resting_id) in book.iter().enumerate() {
            let resting = self
                .db
                .order(resting_id)
                .await?
                .ok_or(ClobError::MissingOrder)?;
            if has_better_priority(order, &resting) {
                insert_at = idx;
                break;
            }
        }
        book.insert(insert_at, order.id);
        self.db.set_side_book(&order.market, order.side, &book);
        Ok(())
    }

    async fn next_sequence(&mut self, market: &MarketId) -> Result<u64, ClobError> {
        let sequence = self.db.market_sequence(market).await?;
        let next = sequence.checked_add(1).ok_or(ClobError::SequenceOverflow)?;
        self.db.set_market_sequence(market, next);
        Ok(sequence)
    }

    async fn load_orders(&self, ids: Vec<OrderId>) -> Result<Vec<Order>, ClobError> {
        let mut orders = Vec::with_capacity(ids.len());
        for id in ids {
            orders.push(self.db.order(&id).await?.ok_or(ClobError::MissingOrder)?);
        }
        Ok(orders)
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

fn fill_id(taker: &OrderId, maker: &OrderId, sequence: u64) -> FillId {
    let mut bytes = taker.encode().as_ref().to_vec();
    bytes.extend_from_slice(maker.encode().as_ref());
    bytes.extend_from_slice(sequence.encode().as_ref());
    FillId(Sha256::hash(&bytes))
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

fn validate_order(market: &Market, price: u128, base_quantity: u128) -> Result<(), ClobError> {
    if price == 0 {
        return Err(ClobError::InvalidOrder("price must be non-zero"));
    }
    if base_quantity == 0 {
        return Err(ClobError::InvalidOrder("quantity must be non-zero"));
    }
    if !price.is_multiple_of(market.tick_size) {
        return Err(ClobError::InvalidOrder("price is not on the market tick"));
    }
    if !base_quantity.is_multiple_of(market.lot_size) {
        return Err(ClobError::InvalidOrder(
            "quantity is not on the market lot",
        ));
    }
    Ok(())
}

fn has_better_priority(candidate: &Order, resting: &Order) -> bool {
    match candidate.side {
        Side::Bid => {
            candidate.price > resting.price
                || (candidate.price == resting.price && candidate.sequence < resting.sequence)
        }
        Side::Ask => {
            candidate.price < resting.price
                || (candidate.price == resting.price && candidate.sequence < resting.sequence)
        }
    }
}

struct MatchSimulation {
    remaining_base: u128,
}

fn append_open_orders(book: &mut Vec<OrderId>, orders: &[Order]) {
    for order in orders {
        if order.status.is_open() && order.remaining_base > 0 {
            book.push(order.id);
        }
    }
}

fn prune_oldest_fill_ids(fill_ids: &mut Vec<FillId>) -> Vec<FillId> {
    let excess = fill_ids.len().saturating_sub(MAX_FILLS_PER_MARKET);
    if excess == 0 {
        Vec::new()
    } else {
        fill_ids.drain(..excess).collect()
    }
}

fn simulate_matches(
    side: Side,
    price: u128,
    base_quantity: u128,
    opposite_orders: &[Order],
) -> Result<MatchSimulation, ClobError> {
    let mut remaining = base_quantity;
    for maker in opposite_orders {
        if remaining == 0 {
            break;
        }
        if !maker.status.is_open() || maker.remaining_base == 0 {
            continue;
        }
        if !side.crosses(price, maker.price) {
            break;
        }
        maker
            .price
            .checked_mul(remaining.min(maker.remaining_base))
            .ok_or(ClobError::QuoteOverflow)?;
        remaining -= remaining.min(maker.remaining_base);
    }
    Ok(MatchSimulation {
        remaining_base: remaining,
    })
}
