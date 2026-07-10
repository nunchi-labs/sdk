//! JSON-RPC surface for the CLOB module.

use std::sync::Arc;

use commonware_cryptography::sha256::Digest;
use futures::lock::Mutex as AsyncMutex;
use jsonrpsee::{
    core::{async_trait, RegisterMethodError, RpcResult},
    proc_macros::rpc,
};
use nunchi_common::{Address, CommitState};
use nunchi_rpc::{decode_hex, encode_hex, invalid_params, module_error, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::{
    ClobDB, ClobError, ClobLedger, Fill, FillId, Market, MarketId, Order, OrderId, OrderStatus,
    Side,
};

/// Read-only CLOB state required by the CLOB RPC server.
#[async_trait]
pub trait ClobQuery: Clone + Send + Sync + 'static {
    async fn nonce(&self, account: Address) -> Result<u64, ClobError>;

    async fn market(&self, market: MarketId) -> Result<Option<Market>, ClobError>;

    async fn markets(&self) -> Result<Vec<Market>, ClobError>;

    async fn order(&self, order: OrderId) -> Result<Option<Order>, ClobError>;

    async fn book(&self, market: MarketId, side: Side) -> Result<Vec<Order>, ClobError>;

    async fn account_orders(&self, account: Address) -> Result<Vec<Order>, ClobError>;

    async fn fill(&self, fill: FillId) -> Result<Option<Fill>, ClobError>;

    async fn fills(&self, market: MarketId) -> Result<Vec<Fill>, ClobError>;

    async fn state_root(&self) -> Result<Digest, ClobError>;
}

/// Shared committed CLOB ledger handle suitable for RPC query servers.
pub struct SharedLedger<D> {
    ledger: Arc<AsyncMutex<ClobLedger<D>>>,
}

impl<D> SharedLedger<D> {
    pub fn new(ledger: ClobLedger<D>) -> Self {
        Self {
            ledger: Arc::new(AsyncMutex::new(ledger)),
        }
    }

    pub async fn lock(&self) -> futures::lock::MutexGuard<'_, ClobLedger<D>> {
        self.ledger.lock().await
    }
}

impl<D> Clone for SharedLedger<D> {
    fn clone(&self) -> Self {
        Self {
            ledger: self.ledger.clone(),
        }
    }
}

#[async_trait]
impl<D> ClobQuery for SharedLedger<D>
where
    D: ClobDB + CommitState + Send + Sync + 'static,
{
    async fn nonce(&self, account: Address) -> Result<u64, ClobError> {
        self.lock().await.nonce(&account).await
    }

    async fn market(&self, market: MarketId) -> Result<Option<Market>, ClobError> {
        self.lock().await.market(&market).await
    }

    async fn markets(&self) -> Result<Vec<Market>, ClobError> {
        self.lock().await.markets().await
    }

    async fn order(&self, order: OrderId) -> Result<Option<Order>, ClobError> {
        self.lock().await.order(&order).await
    }

    async fn book(&self, market: MarketId, side: Side) -> Result<Vec<Order>, ClobError> {
        self.lock().await.book(&market, side).await
    }

    async fn account_orders(&self, account: Address) -> Result<Vec<Order>, ClobError> {
        self.lock().await.account_orders(&account).await
    }

    async fn fill(&self, fill: FillId) -> Result<Option<Fill>, ClobError> {
        self.lock().await.fill(&fill).await
    }

    async fn fills(&self, market: MarketId) -> Result<Vec<Fill>, ClobError> {
        self.lock().await.market_fills(&market).await
    }

    async fn state_root(&self) -> Result<Digest, ClobError> {
        Ok(self.lock().await.db().root())
    }
}

/// Concrete CLOB RPC server over a query backend.
#[derive(Clone)]
pub struct ClobRpc<Q> {
    query: Q,
}

impl<Q> ClobRpc<Q> {
    pub fn new(query: Q) -> Self {
        Self { query }
    }
}

#[rpc(server, namespace = "clob", namespace_separator = ".")]
pub trait Clob {
    #[method(name = "nonce", param_kind = map)]
    async fn nonce(&self, account: String) -> RpcResult<NonceResponse>;

    #[method(name = "market", param_kind = map)]
    async fn market(&self, market: String) -> RpcResult<Option<MarketResponse>>;

    #[method(name = "markets")]
    async fn markets(&self) -> RpcResult<MarketsResponse>;

    #[method(name = "order", param_kind = map)]
    async fn order(&self, order: String) -> RpcResult<Option<OrderResponse>>;

    #[method(name = "book", param_kind = map)]
    async fn book(&self, market: String, side: String) -> RpcResult<BookResponse>;

    #[method(name = "account_orders", param_kind = map)]
    async fn account_orders(&self, account: String) -> RpcResult<OrdersResponse>;

    #[method(name = "fill", param_kind = map)]
    async fn fill(&self, fill: String) -> RpcResult<Option<FillResponse>>;

    #[method(name = "fills", param_kind = map)]
    async fn fills(&self, market: String) -> RpcResult<FillsResponse>;

    #[method(name = "state_root")]
    async fn state_root(&self) -> RpcResult<RootResponse>;
}

#[async_trait]
impl<Q> ClobServer for ClobRpc<Q>
where
    Q: ClobQuery,
{
    async fn nonce(&self, account: String) -> RpcResult<NonceResponse> {
        let account = decode_account(&account)?;
        let nonce = self.query.nonce(account.clone()).await.map_err(rpc_error)?;
        Ok(NonceResponse {
            account: account.to_bech32(),
            nonce,
        })
    }

    async fn market(&self, market: String) -> RpcResult<Option<MarketResponse>> {
        let market = decode_hex(&market, "market")?;
        Ok(self
            .query
            .market(market)
            .await
            .map_err(rpc_error)?
            .map(MarketResponse::from))
    }

    async fn markets(&self) -> RpcResult<MarketsResponse> {
        let markets = self
            .query
            .markets()
            .await
            .map_err(rpc_error)?
            .into_iter()
            .map(MarketResponse::from)
            .collect();
        Ok(MarketsResponse { markets })
    }

    async fn order(&self, order: String) -> RpcResult<Option<OrderResponse>> {
        let order = decode_hex(&order, "order")?;
        Ok(self
            .query
            .order(order)
            .await
            .map_err(rpc_error)?
            .map(OrderResponse::from))
    }

    async fn book(&self, market: String, side: String) -> RpcResult<BookResponse> {
        let market = decode_hex(&market, "market")?;
        let side = decode_side(&side)?;
        let orders = self
            .query
            .book(market, side)
            .await
            .map_err(rpc_error)?
            .into_iter()
            .map(OrderResponse::from)
            .collect();
        Ok(BookResponse {
            market: encode_hex(&market),
            side: side_name(side).to_string(),
            orders,
        })
    }

    async fn account_orders(&self, account: String) -> RpcResult<OrdersResponse> {
        let account = decode_account(&account)?;
        let orders = self
            .query
            .account_orders(account)
            .await
            .map_err(rpc_error)?
            .into_iter()
            .map(OrderResponse::from)
            .collect();
        Ok(OrdersResponse { orders })
    }

    async fn fill(&self, fill: String) -> RpcResult<Option<FillResponse>> {
        let fill = decode_hex(&fill, "fill")?;
        Ok(self
            .query
            .fill(fill)
            .await
            .map_err(rpc_error)?
            .map(FillResponse::from))
    }

    async fn fills(&self, market: String) -> RpcResult<FillsResponse> {
        let market = decode_hex(&market, "market")?;
        let fills = self
            .query
            .fills(market)
            .await
            .map_err(rpc_error)?
            .into_iter()
            .map(FillResponse::from)
            .collect();
        Ok(FillsResponse {
            market: encode_hex(&market),
            fills,
        })
    }

    async fn state_root(&self) -> RpcResult<RootResponse> {
        let root = self.query.state_root().await.map_err(rpc_error)?;
        Ok(RootResponse {
            root: encode_hex(&root),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NonceResponse {
    pub account: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarketResponse {
    pub id: String,
    pub base_asset: String,
    pub quote_asset: String,
    pub tick_size: String,
    pub lot_size: String,
    pub created_by: String,
    pub created_at_height: u64,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarketsResponse {
    pub markets: Vec<MarketResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrderResponse {
    pub id: String,
    pub owner: String,
    pub market: String,
    pub side: String,
    pub price: String,
    pub original_base: String,
    pub remaining_base: String,
    pub filled_base: String,
    pub status: String,
    pub sequence: u64,
    pub created_at_height: u64,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BookResponse {
    pub market: String,
    pub side: String,
    pub orders: Vec<OrderResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrdersResponse {
    pub orders: Vec<OrderResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FillResponse {
    pub id: String,
    pub market: String,
    pub maker_order: String,
    pub taker_order: String,
    pub maker: String,
    pub taker: String,
    pub taker_side: String,
    pub price: String,
    pub base_quantity: String,
    pub quote_quantity: String,
    pub sequence: u64,
    pub written_at_height: u64,
    pub written_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FillsResponse {
    pub market: String,
    pub fills: Vec<FillResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootResponse {
    pub root: String,
}

/// Register the CLOB module's query RPC methods into a downstream router.
pub fn register<Context, Q>(
    router: &mut RpcRouter<Context>,
    rpc: ClobRpc<Q>,
) -> Result<(), RegisterMethodError>
where
    Q: ClobQuery,
{
    router.merge(rpc.into_rpc())
}

fn decode_account(value: &str) -> RpcResult<Address> {
    Address::from_bech32(value)
        .map_err(|err| invalid_params(format!("invalid account address: {err}")))
}

fn decode_side(value: &str) -> RpcResult<Side> {
    match value {
        "bid" | "Bid" | "BID" => Ok(Side::Bid),
        "ask" | "Ask" | "ASK" => Ok(Side::Ask),
        side => Err(invalid_params(format!("invalid side: {side}"))),
    }
}

fn side_name(side: Side) -> &'static str {
    match side {
        Side::Bid => "bid",
        Side::Ask => "ask",
    }
}

fn status_name(status: OrderStatus) -> &'static str {
    match status {
        OrderStatus::Open => "open",
        OrderStatus::PartiallyFilled => "partially_filled",
        OrderStatus::Filled => "filled",
        OrderStatus::Cancelled => "cancelled",
        OrderStatus::Expired => "expired",
    }
}

fn rpc_error(error: ClobError) -> jsonrpsee::types::ErrorObjectOwned {
    module_error(error.to_string())
}

impl From<Market> for MarketResponse {
    fn from(market: Market) -> Self {
        Self {
            id: encode_hex(&market.id),
            base_asset: encode_hex(&market.base_asset),
            quote_asset: encode_hex(&market.quote_asset),
            tick_size: market.tick_size.to_string(),
            lot_size: market.lot_size.to_string(),
            created_by: market.created_by.to_bech32(),
            created_at_height: market.created_at_height,
            created_at_ms: market.created_at_ms,
        }
    }
}

impl From<Order> for OrderResponse {
    fn from(order: Order) -> Self {
        Self {
            id: encode_hex(&order.id),
            owner: order.owner.to_bech32(),
            market: encode_hex(&order.market),
            side: side_name(order.side).to_string(),
            price: order.price.to_string(),
            original_base: order.original_base.to_string(),
            remaining_base: order.remaining_base.to_string(),
            filled_base: order.filled_base.to_string(),
            status: status_name(order.status).to_string(),
            sequence: order.sequence,
            created_at_height: order.created_at_height,
            created_at_ms: order.created_at_ms,
        }
    }
}

impl From<Fill> for FillResponse {
    fn from(fill: Fill) -> Self {
        Self {
            id: encode_hex(&fill.id),
            market: encode_hex(&fill.market),
            maker_order: encode_hex(&fill.maker_order),
            taker_order: encode_hex(&fill.taker_order),
            maker: fill.maker.to_bech32(),
            taker: fill.taker.to_bech32(),
            taker_side: side_name(fill.taker_side).to_string(),
            price: fill.price.to_string(),
            base_quantity: fill.base_quantity.to_string(),
            quote_quantity: fill.quote_quantity.to_string(),
            sequence: fill.sequence,
            written_at_height: fill.written_at_height,
            written_at_ms: fill.written_at_ms,
        }
    }
}
