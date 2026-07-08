use std::collections::BTreeMap;

use crate::{
    ClobError, ClobOperation, Fill, FillId, Market, MarketId, Order, OrderId, OrderStatus, Side,
    TimeInForce, Transaction, CLOB_NAMESPACE,
};
use commonware_codec::Encode;
use commonware_cryptography::{Hasher, Sha256};
use nunchi_common::RuntimeContext;

/// Deterministic in-memory matcher used by proposers and validator replay.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MatchEngine {
    books: BTreeMap<MarketId, Book>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Book {
    bids: Vec<Order>,
    asks: Vec<Order>,
}

/// Output from replaying signed order intents through the matcher.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReplayResult {
    pub fills: Vec<Fill>,
    pub sequences: BTreeMap<MarketId, u64>,
}

impl MatchEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replay signed `PlaceOrder` intents in order, starting each market at the supplied sequence.
    pub fn replay(
        orders: &[Transaction],
        markets: &BTreeMap<MarketId, Market>,
        sequences: BTreeMap<MarketId, u64>,
        context: RuntimeContext,
    ) -> Result<ReplayResult, ClobError> {
        let mut engine = Self::new();
        let mut sequences = sequences;
        let mut fills = Vec::new();

        for tx in orders {
            tx.verify()?;
            let order_id = OrderId(tx.digest());
            let ClobOperation::PlaceOrder {
                market,
                side,
                price,
                base_quantity,
                time_in_force,
            } = &tx.payload.operation
            else {
                return Err(ClobError::InvalidOrder(
                    "match batches may only carry signed place-order intents",
                ));
            };
            let market_info = markets.get(market).ok_or(ClobError::MarketNotFound)?;
            validate_order(market_info, *price, *base_quantity)?;
            let sequence = next_sequence(&mut sequences, market)?;
            let order = Order {
                id: order_id,
                owner: tx.account_id.clone(),
                market: *market,
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
            engine.place_order(order, *time_in_force, context, &mut sequences, &mut fills)?;
        }

        Ok(ReplayResult { fills, sequences })
    }

    fn place_order(
        &mut self,
        mut taker: Order,
        time_in_force: TimeInForce,
        context: RuntimeContext,
        sequences: &mut BTreeMap<MarketId, u64>,
        fills: &mut Vec<Fill>,
    ) -> Result<(), ClobError> {
        let book = self.books.entry(taker.market).or_default();
        let opposite = book.side_mut(taker.side.opposite());
        let mut remaining_makers = Vec::with_capacity(opposite.len());

        for mut maker in opposite.drain(..) {
            if taker.remaining_base == 0 {
                remaining_makers.push(maker);
                continue;
            }
            if !maker.status.is_open() || maker.remaining_base == 0 {
                continue;
            }
            if !taker.side.crosses(taker.price, maker.price) {
                remaining_makers.push(maker);
                continue;
            }

            let base = taker.remaining_base.min(maker.remaining_base);
            let quote = maker
                .price
                .checked_mul(base)
                .ok_or(ClobError::QuoteOverflow)?;
            let fill_sequence = next_sequence(sequences, &taker.market)?;
            let fill = Fill {
                id: fill_id(&taker.id, &maker.id, fill_sequence),
                market: taker.market,
                maker_order: maker.id,
                taker_order: taker.id,
                maker: maker.owner.clone(),
                taker: taker.owner.clone(),
                taker_side: taker.side,
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
            fills.push(fill);

            if maker.status.is_open() && maker.remaining_base > 0 {
                remaining_makers.push(maker);
            }
        }

        *opposite = remaining_makers;
        taker.status = if taker.remaining_base == 0 {
            OrderStatus::Filled
        } else if time_in_force == TimeInForce::ImmediateOrCancel {
            OrderStatus::Expired
        } else if taker.filled_base == 0 {
            OrderStatus::Open
        } else {
            OrderStatus::PartiallyFilled
        };
        if taker.status.is_open() && taker.remaining_base > 0 {
            let same_side = book.side_mut(taker.side);
            insert_resting(same_side, taker);
        }
        Ok(())
    }
}

impl Book {
    fn side_mut(&mut self, side: Side) -> &mut Vec<Order> {
        match side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        }
    }
}

fn insert_resting(book: &mut Vec<Order>, order: Order) {
    let insert_at = book
        .iter()
        .position(|resting| has_better_priority(&order, resting))
        .unwrap_or(book.len());
    book.insert(insert_at, order);
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

fn next_sequence(
    sequences: &mut BTreeMap<MarketId, u64>,
    market: &MarketId,
) -> Result<u64, ClobError> {
    let current = *sequences.get(market).unwrap_or(&0);
    let next = current.checked_add(1).ok_or(ClobError::SequenceOverflow)?;
    sequences.insert(*market, next);
    Ok(current)
}

pub(crate) fn fill_id(taker: &OrderId, maker: &OrderId, sequence: u64) -> FillId {
    let mut bytes = CLOB_NAMESPACE.to_vec();
    bytes.extend_from_slice(taker.encode().as_ref());
    bytes.extend_from_slice(maker.encode().as_ref());
    bytes.extend_from_slice(sequence.encode().as_ref());
    FillId(Sha256::hash(&bytes))
}

pub(crate) fn validate_order(
    market: &Market,
    price: u128,
    base_quantity: u128,
) -> Result<(), ClobError> {
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

pub(crate) fn fills_equivalent(expected: &Fill, actual: &Fill) -> bool {
    expected.id == actual.id
        && expected.market == actual.market
        && expected.maker_order == actual.maker_order
        && expected.taker_order == actual.taker_order
        && expected.maker == actual.maker
        && expected.taker == actual.taker
        && expected.taker_side == actual.taker_side
        && expected.price == actual.price
        && expected.base_quantity == actual.base_quantity
        && expected.quote_quantity == actual.quote_quantity
        && expected.sequence == actual.sequence
}
