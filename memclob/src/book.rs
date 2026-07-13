use std::collections::{HashMap, HashSet, VecDeque};

use commonware_codec::Encode;
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use nunchi_clob::{
    canonical_asset_pair, market_id, ClobError, ClobOperation, Fill, FillId, Market, MarketId, Order,
    OrderId, OrderStatus, PlaceOrderParams, Side, TimeInForce, Transaction, MAX_ACCOUNT_ORDERS,
    MAX_BOOK_ORDERS, MAX_FILLS_PER_MARKET, MAX_MARKETS, CLOB_NAMESPACE,
};
use nunchi_common::{Address, RuntimeContext};

/// In-memory replica of the CLOB matching engine kept in validator RAM.
///
/// Deterministic given the same stream of signed order instructions and runtime
/// context (height/timestamp), matching the on-chain `ClobLedger` semantics.
#[derive(Clone, Debug, Default)]
pub struct MemBookEngine {
    nonces: HashMap<Address, u64>,
    markets: HashMap<MarketId, Market>,
    market_index: Vec<MarketId>,
    orders: HashMap<OrderId, Order>,
    bid_books: HashMap<MarketId, Vec<OrderId>>,
    ask_books: HashMap<MarketId, Vec<OrderId>>,
    account_orders: HashMap<Address, Vec<OrderId>>,
    market_fill_ids: HashMap<MarketId, Vec<FillId>>,
    fills: HashMap<FillId, Fill>,
    market_sequences: HashMap<MarketId, u64>,
    pending_settlement: VecDeque<Fill>,
    seen_digests: HashSet<Digest>,
    dedup_order: VecDeque<Digest>,
    dedup_capacity: usize,
}

impl MemBookEngine {
    pub fn with_dedup_capacity(capacity: usize) -> Self {
        Self {
            dedup_capacity: capacity.max(1),
            ..Self::default()
        }
    }

    pub fn seed_market(&mut self, market: Market) {
        let id = market.id;
        if self.markets.contains_key(&id) {
            return;
        }
        self.markets.insert(id, market);
        if !self.market_index.contains(&id) {
            self.market_index.push(id);
        }
        self.market_sequences.entry(id).or_insert(0);
    }

    pub fn market(&self, id: &MarketId) -> Option<&Market> {
        self.markets.get(id)
    }

    pub fn order(&self, id: &OrderId) -> Option<&Order> {
        self.orders.get(id)
    }

    pub fn book(&self, market: &MarketId, side: Side) -> Vec<Order> {
        self.book_ids(market, side)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|id| self.orders.get(&id).cloned())
            .collect()
    }

    fn book_ids(&self, market: &MarketId, side: Side) -> Option<&Vec<OrderId>> {
        match side {
            Side::Bid => self.bid_books.get(market),
            Side::Ask => self.ask_books.get(market),
        }
    }

    fn book_ids_mut(&mut self, market: MarketId, side: Side) -> &mut Vec<OrderId> {
        match side {
            Side::Bid => self.bid_books.entry(market).or_default(),
            Side::Ask => self.ask_books.entry(market).or_default(),
        }
    }

    fn set_book_ids(&mut self, market: MarketId, side: Side, ids: Vec<OrderId>) {
        match side {
            Side::Bid => {
                self.bid_books.insert(market, ids);
            }
            Side::Ask => {
                self.ask_books.insert(market, ids);
            }
        }
    }

    pub fn pending_fills(&self) -> &[Fill] {
        self.pending_settlement.as_slices().0
    }

    pub fn pending_fills_since(&self, limit: usize) -> Vec<Fill> {
        self.pending_settlement.iter().take(limit).cloned().collect()
    }

    pub fn finalize_settlement(&mut self, committed: &[FillId]) {
        if committed.is_empty() {
            return;
        }
        let committed: HashSet<_> = committed.iter().copied().collect();
        self.pending_settlement
            .retain(|fill| !committed.contains(&fill.id));
    }

    pub fn apply_transaction(
        &mut self,
        tx: &Transaction,
        context: RuntimeContext,
    ) -> Result<(), ClobError> {
        tx.verify()?;
        let digest = tx.digest();
        if self.seen_digests.contains(&digest) {
            return Ok(());
        }
        self.remember_digest(digest);

        let expected = self.nonces.get(&tx.account_id).copied().unwrap_or(0);
        if tx.payload.nonce != expected {
            return Err(ClobError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        self.apply_operation(tx, context)?;
        self.nonces.insert(
            tx.account_id.clone(),
            expected.checked_add(1).ok_or(ClobError::NonceOverflow)?,
        );
        Ok(())
    }

    fn apply_operation(
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
            } => self.create_market(
                &tx.account_id,
                *base_asset,
                *quote_asset,
                *tick_size,
                *lot_size,
                context,
            ),
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
                )?;
                Ok(())
            }
            ClobOperation::CancelOrder { order } => self.cancel_order(&tx.account_id, order),
        }
    }

    fn create_market(
        &mut self,
        signer: &Address,
        base_asset: nunchi_clob::AssetId,
        quote_asset: nunchi_clob::AssetId,
        tick_size: u128,
        lot_size: u128,
        context: RuntimeContext,
    ) -> Result<(), ClobError> {
        validate_market(base_asset, quote_asset, tick_size, lot_size)?;
        let (base_asset, quote_asset) = canonical_asset_pair(base_asset, quote_asset);
        let id = market_id(&base_asset, &quote_asset, tick_size, lot_size);
        if self.markets.contains_key(&id) {
            return Err(ClobError::MarketAlreadyExists);
        }
        if self.market_index.len() == MAX_MARKETS {
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
        self.markets.insert(id, market);
        self.market_index.push(id);
        self.market_sequences.insert(id, 0);
        Ok(())
    }

    fn place_order(
        &mut self,
        params: &PlaceOrderParams,
        context: RuntimeContext,
    ) -> Result<Order, ClobError> {
        let market = self
            .markets
            .get(&params.market)
            .ok_or(ClobError::MarketNotFound)?
            .clone();
        validate_order(&market, params.price, params.base_quantity)?;

        if self.orders.contains_key(&params.order_id) {
            return Err(ClobError::InvalidOrder("duplicate order id"));
        }

        let account_orders = self
            .account_orders
            .get(&params.owner)
            .cloned()
            .unwrap_or_default();
        if account_orders.len() == MAX_ACCOUNT_ORDERS {
            return Err(ClobError::AccountIndexFull);
        }

        let opposite_side = params.side.opposite();
        let opposite_orders = self.load_orders(
            self.book_ids(&params.market, opposite_side)
                .cloned()
                .unwrap_or_default(),
        )?;
        let simulation = simulate_matches(
            params.side,
            params.price,
            params.base_quantity,
            &opposite_orders,
        )?;

        let market_fill_ids = self
            .market_fill_ids
            .get(&params.market)
            .cloned()
            .unwrap_or_default();
        if market_fill_ids.len().saturating_add(simulation.fills) > MAX_FILLS_PER_MARKET {
            return Err(ClobError::FillIndexFull);
        }

        if params.time_in_force == TimeInForce::GoodTilCancelled && simulation.remaining_base > 0 {
            let same_side_book = self.book_ids(&params.market, params.side).map(Vec::len).unwrap_or(0);
            if same_side_book == MAX_BOOK_ORDERS {
                return Err(ClobError::BookFull);
            }
        }

        let sequence = self.next_sequence(&params.market)?;
        let mut taker = Order {
            id: params.order_id,
            owner: params.owner.clone(),
            market: params.market,
            side: params.side,
            price: params.price,
            original_base: params.base_quantity,
            remaining_base: params.base_quantity,
            filled_base: 0,
            status: OrderStatus::Open,
            sequence,
            created_at_height: context.height,
            created_at_ms: context.timestamp_ms,
        };

        let mut updated_opposite_book = Vec::with_capacity(opposite_orders.len());
        let mut market_fill_ids = market_fill_ids;
        for idx in 0..opposite_orders.len() {
            if taker.remaining_base == 0 {
                append_open_orders(&mut updated_opposite_book, &opposite_orders[idx..]);
                break;
            }

            let mut maker = opposite_orders[idx].clone();
            if !maker.status.is_open() || maker.remaining_base == 0 {
                continue;
            }
            if !params.side.crosses(params.price, maker.price) {
                append_open_orders(&mut updated_opposite_book, &opposite_orders[idx..]);
                break;
            }

            let base = taker.remaining_base.min(maker.remaining_base);
            let quote = maker
                .price
                .checked_mul(base)
                .ok_or(ClobError::QuoteOverflow)?;
            let fill_sequence = self.next_sequence(&params.market)?;
            let fill = Fill {
                id: fill_id(&taker.id, &maker.id, fill_sequence),
                market: params.market,
                maker_order: maker.id,
                taker_order: taker.id,
                maker: maker.owner.clone(),
                taker: taker.owner.clone(),
                taker_side: params.side,
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

            self.fills.insert(fill.id, fill.clone());
            market_fill_ids.push(fill.id);
            self.pending_settlement.push_back(fill);
            self.orders.insert(maker.id, maker.clone());
            if maker.status.is_open() && maker.remaining_base > 0 {
                updated_opposite_book.push(maker.id);
            } else {
                self.remove_from_account_orders(&maker.owner, &maker.id);
            }
        }

        self.set_book_ids(params.market, opposite_side, updated_opposite_book);
        self.market_fill_ids.insert(params.market, market_fill_ids);

        taker.status = if taker.remaining_base == 0 {
            OrderStatus::Filled
        } else if params.time_in_force == TimeInForce::ImmediateOrCancel {
            OrderStatus::Expired
        } else if taker.filled_base == 0 {
            OrderStatus::Open
        } else {
            OrderStatus::PartiallyFilled
        };

        self.orders.insert(taker.id, taker.clone());
        if taker.status.is_open() {
            let mut account_orders = self
                .account_orders
                .get(&params.owner)
                .cloned()
                .unwrap_or_default();
            account_orders.push(taker.id);
            self.account_orders.insert(params.owner.clone(), account_orders);
            if taker.remaining_base > 0 {
                self.insert_resting_order(&taker)?;
            }
        } else {
            self.remove_from_account_orders(&params.owner, &taker.id);
        }
        Ok(taker)
    }

    fn cancel_order(&mut self, signer: &Address, order_id: &OrderId) -> Result<(), ClobError> {
        let mut order = self
            .orders
            .get(order_id)
            .cloned()
            .ok_or(ClobError::OrderNotFound)?;
        if order.owner != *signer {
            return Err(ClobError::UnauthorizedCancel);
        }
        if !order.status.is_open() || order.remaining_base == 0 {
            return Err(ClobError::OrderClosed);
        }

        if let Some(book) = match order.side {
            Side::Bid => self.bid_books.get_mut(&order.market),
            Side::Ask => self.ask_books.get_mut(&order.market),
        } {
            book.retain(|id| id != order_id);
        }

        order.status = OrderStatus::Cancelled;
        self.orders.insert(*order_id, order.clone());
        self.remove_from_account_orders(&order.owner, order_id);
        Ok(())
    }

    fn remove_from_account_orders(&mut self, owner: &Address, order_id: &OrderId) {
        if let Some(orders) = self.account_orders.get_mut(owner) {
            let before = orders.len();
            orders.retain(|id| id != order_id);
            if orders.is_empty() && before != 0 {
                self.account_orders.remove(owner);
            }
        }
    }

    fn insert_resting_order(&mut self, order: &Order) -> Result<(), ClobError> {
        let book_ids = self
            .book_ids(&order.market, order.side)
            .cloned()
            .unwrap_or_default();
        if book_ids.len() == MAX_BOOK_ORDERS {
            return Err(ClobError::BookFull);
        }

        let mut insert_at = book_ids.len();
        for (idx, resting_id) in book_ids.iter().enumerate() {
            let resting = self
                .orders
                .get(resting_id)
                .ok_or(ClobError::MissingOrder)?;
            if has_better_priority(order, resting) {
                insert_at = idx;
                break;
            }
        }
        let book = self.book_ids_mut(order.market, order.side);
        if book.len() == MAX_BOOK_ORDERS {
            return Err(ClobError::BookFull);
        }
        book.insert(insert_at, order.id);
        Ok(())
    }

    fn next_sequence(&mut self, market: &MarketId) -> Result<u64, ClobError> {
        let sequence = *self.market_sequences.get(market).unwrap_or(&0);
        let next = sequence.checked_add(1).ok_or(ClobError::SequenceOverflow)?;
        self.market_sequences.insert(*market, next);
        Ok(sequence)
    }

    fn load_orders(&self, ids: Vec<OrderId>) -> Result<Vec<Order>, ClobError> {
        ids.into_iter()
            .map(|id| self.orders.get(&id).cloned().ok_or(ClobError::MissingOrder))
            .collect()
    }

    fn remember_digest(&mut self, digest: Digest) {
        if !self.seen_digests.insert(digest) {
            return;
        }
        self.dedup_order.push_back(digest);
        while self.dedup_order.len() > self.dedup_capacity {
            if let Some(old) = self.dedup_order.pop_front() {
                self.seen_digests.remove(&old);
            }
        }
    }
}

fn fill_id(taker: &OrderId, maker: &OrderId, sequence: u64) -> FillId {
    let mut bytes = taker.encode().as_ref().to_vec();
    bytes.extend_from_slice(maker.encode().as_ref());
    bytes.extend_from_slice(sequence.encode().as_ref());
    FillId(Sha256::hash(&bytes))
}

fn validate_market(
    base_asset: nunchi_clob::AssetId,
    quote_asset: nunchi_clob::AssetId,
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
    fills: usize,
    remaining_base: u128,
}

fn append_open_orders(book: &mut Vec<OrderId>, orders: &[Order]) {
    for order in orders {
        if order.status.is_open() && order.remaining_base > 0 {
            book.push(order.id);
        }
    }
}

fn simulate_matches(
    side: Side,
    price: u128,
    base_quantity: u128,
    opposite_orders: &[Order],
) -> Result<MatchSimulation, ClobError> {
    let mut remaining = base_quantity;
    let mut fills = 0;
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
        fills += 1;
    }
    Ok(MatchSimulation {
        fills,
        remaining_base: remaining,
    })
}

/// Deterministic digest for a memclob P2P frame prefix.
pub const MEMCLOB_NAMESPACE: &[u8] = b"_NUNCHI_MEMCLOB";

/// Hash helper used by tests and future snapshot sync.
pub fn snapshot_digest(engine: &MemBookEngine) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(MEMCLOB_NAMESPACE);
    hasher.update(CLOB_NAMESPACE);
    hasher.update(engine.market_index.len().encode().as_ref());
    for market in &engine.market_index {
        hasher.update(market.encode().as_ref());
        if let Some(book) = engine.book_ids(market, Side::Bid) {
            encode_order_ids(&mut hasher, book);
        }
        if let Some(book) = engine.book_ids(market, Side::Ask) {
            encode_order_ids(&mut hasher, book);
        }
    }
    hasher.finalize()
}

fn encode_order_ids(hasher: &mut Sha256, ids: &[OrderId]) {
    hasher.update(ids.len().encode().as_ref());
    for id in ids {
        hasher.update(id.encode().as_ref());
    }
}
