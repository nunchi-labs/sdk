//! Persistence layer for the CLOB module.

use crate::{
    ClobError, Fill, FillId, Market, MarketId, Order, OrderId, Side, MAX_ACCOUNT_ORDERS,
    MAX_BOOK_ORDERS, MAX_FILLS_PER_MARKET, MAX_MARKETS, CLOB_NAMESPACE,
};
use async_trait::async_trait;
use commonware_codec::{Encode, RangeCfg, Read, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Namespace, StateStore};

const NS: Namespace = Namespace::new(CLOB_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    Nonce = 0,
    Market = 1,
    MarketIndex = 2,
    Order = 3,
    SideBook = 4,
    AccountOrders = 5,
    Fill = 6,
    MarketFills = 7,
    MarketSequence = 8,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, ClobError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| ClobError::Storage(err.to_string()))
}

fn nonce_key(account: &Address) -> Digest {
    NS.key(Table::Nonce, account.encode().as_ref())
}

fn market_key(market: &MarketId) -> Digest {
    NS.key(Table::Market, market.encode().as_ref())
}

fn market_index_key() -> Digest {
    NS.key(Table::MarketIndex, b"all")
}

fn order_key(order: &OrderId) -> Digest {
    NS.key(Table::Order, order.encode().as_ref())
}

fn side_book_key(market: &MarketId, side: Side) -> Digest {
    let mut logical = market.encode().as_ref().to_vec();
    logical.extend_from_slice(side.encode().as_ref());
    NS.key(Table::SideBook, &logical)
}

fn account_orders_key(account: &Address) -> Digest {
    NS.key(Table::AccountOrders, account.encode().as_ref())
}

fn fill_key(fill: &FillId) -> Digest {
    NS.key(Table::Fill, fill.encode().as_ref())
}

fn market_fills_key(market: &MarketId) -> Digest {
    NS.key(Table::MarketFills, market.encode().as_ref())
}

fn market_sequence_key(market: &MarketId) -> Digest {
    NS.key(Table::MarketSequence, market.encode().as_ref())
}

/// Storage backend for CLOB ledger state.
///
/// # Write model
///
/// All `set_*` and `remove_*` methods are synchronous and infallible because
/// they buffer writes locally. Writes are made durable only when the
/// underlying [`StateStore::commit`] is called. Callers must not assume that
/// a `set_*` call persists the value before the next commit.
///
/// Async `get` methods (`nonce`, `market`, `order`, etc.) read from the
/// current overlay and fall back to persistent storage if no buffered value
/// is present.
#[async_trait]
pub trait ClobDB {
    /// Returns the current nonce for `account`, or 0 if it has never transacted.
    async fn nonce(&self, account: &Address) -> Result<u64, ClobError>;

    /// Buffer a nonce update. The change is not durable until `commit` is called.
    fn set_nonce(&mut self, account: &Address, nonce: u64);

    /// Look up a market definition by id.
    async fn market(&self, id: &MarketId) -> Result<Option<Market>, ClobError>;

    /// Buffer a market definition (insert or update). Not durable until `commit`.
    fn set_market(&mut self, market: &Market);

    /// Return the list of all registered market ids.
    async fn market_index(&self) -> Result<Vec<MarketId>, ClobError>;

    /// Buffer an update to the market index. Not durable until `commit`.
    fn set_market_index(&mut self, markets: &[MarketId]);

    /// Look up an order by id.
    async fn order(&self, id: &OrderId) -> Result<Option<Order>, ClobError>;

    /// Buffer an order (insert or update). Not durable until `commit`.
    fn set_order(&mut self, order: &Order);

    /// Buffer the removal of an order. Not durable until `commit`.
    fn remove_order(&mut self, order: &OrderId);

    /// Return the order ids on one side of a market's book.
    async fn side_book(&self, market: &MarketId, side: Side) -> Result<Vec<OrderId>, ClobError>;

    /// Buffer an update to a side of the order book. Not durable until `commit`.
    fn set_side_book(&mut self, market: &MarketId, side: Side, orders: &[OrderId]);

    /// Return the order ids associated with an account.
    async fn account_orders(&self, account: &Address) -> Result<Vec<OrderId>, ClobError>;

    /// Buffer an update to the account's order index. Not durable until `commit`.
    fn set_account_orders(&mut self, account: &Address, orders: &[OrderId]);

    /// Look up a fill by id.
    async fn fill(&self, id: &FillId) -> Result<Option<Fill>, ClobError>;

    /// Buffer a fill record. Not durable until `commit`.
    fn set_fill(&mut self, fill: &Fill);

    /// Buffer the removal of a fill. Not durable until `commit`.
    fn remove_fill(&mut self, fill: &FillId);

    /// Return the fill ids for a market.
    async fn market_fills(&self, market: &MarketId) -> Result<Vec<FillId>, ClobError>;

    /// Buffer an update to the market's fill index. Not durable until `commit`.
    fn set_market_fills(&mut self, market: &MarketId, fills: &[FillId]);

    /// Return the current sequence number for a market, or 0 if not yet set.
    async fn market_sequence(&self, market: &MarketId) -> Result<u64, ClobError>;

    /// Buffer a market sequence number update. Not durable until `commit`.
    fn set_market_sequence(&mut self, market: &MarketId, sequence: u64);
}

#[async_trait]
impl<S: StateStore + Send + Sync> ClobDB for S {
    async fn nonce(&self, account: &Address) -> Result<u64, ClobError> {
        match StateStore::get(self, &nonce_key(account))
            .await
            .map_err(|err| ClobError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_nonce(&mut self, account: &Address, nonce: u64) {
        StateStore::set(self, nonce_key(account), encoded(&nonce));
    }

    async fn market(&self, id: &MarketId) -> Result<Option<Market>, ClobError> {
        match StateStore::get(self, &market_key(id))
            .await
            .map_err(|err| ClobError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_market(&mut self, market: &Market) {
        StateStore::set(self, market_key(&market.id), encoded(market));
    }

    async fn market_index(&self) -> Result<Vec<MarketId>, ClobError> {
        match StateStore::get(self, &market_index_key())
            .await
            .map_err(|err| ClobError::Storage(err.to_string()))?
        {
            Some(bytes) => {
                let mut buf = bytes.as_ref();
                Vec::read_cfg(&mut buf, &(RangeCfg::new(0..=MAX_MARKETS), ()))
                    .map_err(|err| ClobError::Storage(err.to_string()))
            }
            None => Ok(Vec::new()),
        }
    }

    fn set_market_index(&mut self, markets: &[MarketId]) {
        StateStore::set(self, market_index_key(), encoded(&markets.to_vec()));
    }

    async fn order(&self, id: &OrderId) -> Result<Option<Order>, ClobError> {
        match StateStore::get(self, &order_key(id))
            .await
            .map_err(|err| ClobError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_order(&mut self, order: &Order) {
        StateStore::set(self, order_key(&order.id), encoded(order));
    }

    fn remove_order(&mut self, order: &OrderId) {
        StateStore::remove(self, order_key(order));
    }

    async fn side_book(&self, market: &MarketId, side: Side) -> Result<Vec<OrderId>, ClobError> {
        match StateStore::get(self, &side_book_key(market, side))
            .await
            .map_err(|err| ClobError::Storage(err.to_string()))?
        {
            Some(bytes) => {
                let mut buf = bytes.as_ref();
                Vec::read_cfg(&mut buf, &(RangeCfg::new(0..=MAX_BOOK_ORDERS), ()))
                    .map_err(|err| ClobError::Storage(err.to_string()))
            }
            None => Ok(Vec::new()),
        }
    }

    fn set_side_book(&mut self, market: &MarketId, side: Side, orders: &[OrderId]) {
        StateStore::set(self, side_book_key(market, side), encoded(&orders.to_vec()));
    }

    async fn account_orders(&self, account: &Address) -> Result<Vec<OrderId>, ClobError> {
        match StateStore::get(self, &account_orders_key(account))
            .await
            .map_err(|err| ClobError::Storage(err.to_string()))?
        {
            Some(bytes) => {
                let mut buf = bytes.as_ref();
                Vec::read_cfg(&mut buf, &(RangeCfg::new(0..=MAX_ACCOUNT_ORDERS), ()))
                    .map_err(|err| ClobError::Storage(err.to_string()))
            }
            None => Ok(Vec::new()),
        }
    }

    fn set_account_orders(&mut self, account: &Address, orders: &[OrderId]) {
        StateStore::set(
            self,
            account_orders_key(account),
            encoded(&orders.to_vec()),
        );
    }

    async fn fill(&self, id: &FillId) -> Result<Option<Fill>, ClobError> {
        match StateStore::get(self, &fill_key(id))
            .await
            .map_err(|err| ClobError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_fill(&mut self, fill: &Fill) {
        StateStore::set(self, fill_key(&fill.id), encoded(fill));
    }

    fn remove_fill(&mut self, fill: &FillId) {
        StateStore::remove(self, fill_key(fill));
    }

    async fn market_fills(&self, market: &MarketId) -> Result<Vec<FillId>, ClobError> {
        match StateStore::get(self, &market_fills_key(market))
            .await
            .map_err(|err| ClobError::Storage(err.to_string()))?
        {
            Some(bytes) => {
                let mut buf = bytes.as_ref();
                Vec::read_cfg(&mut buf, &(RangeCfg::new(0..=MAX_FILLS_PER_MARKET), ()))
                    .map_err(|err| ClobError::Storage(err.to_string()))
            }
            None => Ok(Vec::new()),
        }
    }

    fn set_market_fills(&mut self, market: &MarketId, fills: &[FillId]) {
        StateStore::set(self, market_fills_key(market), encoded(&fills.to_vec()));
    }

    async fn market_sequence(&self, market: &MarketId) -> Result<u64, ClobError> {
        match StateStore::get(self, &market_sequence_key(market))
            .await
            .map_err(|err| ClobError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_market_sequence(&mut self, market: &MarketId, sequence: u64) {
        StateStore::set(self, market_sequence_key(market), encoded(&sequence));
    }
}
