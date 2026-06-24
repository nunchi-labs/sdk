//! JSON-RPC surface for the perpetuals module.

#[cfg(feature = "mempool")]
mod mempool;
#[cfg(feature = "mempool")]
pub use mempool::{
    register_mempool, MempoolIngress, PerpetualMempoolServer, PerpetualsMempoolRpc,
    SubmitTransactionParams, SubmitTransactionResponse, TransactionStatusResponse,
};

use std::sync::Arc;

use commonware_cryptography::sha256::Digest;
use futures::lock::Mutex as AsyncMutex;
use jsonrpsee::{
    core::{async_trait, RegisterMethodError, RpcResult},
    proc_macros::rpc,
};
use nunchi_common::CommitState;
use nunchi_rpc::{decode_hex, encode_hex, module_error, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::{Address, Market, MarketId, PerpetualDB, PerpetualError, PerpetualLedger, Position};

/// Read-only perpetuals state required by the perps RPC server.
#[async_trait]
pub trait PerpetualQuery: Clone + Send + Sync + 'static {
    async fn nonce(&self, account: Address) -> Result<u64, PerpetualError>;

    async fn market(&self, market: MarketId) -> Result<Option<Market>, PerpetualError>;

    async fn position(
        &self,
        position: crate::PositionId,
    ) -> Result<Option<Position>, PerpetualError>;

    async fn state_root(&self) -> Result<Digest, PerpetualError>;
}

/// Shared committed perpetuals ledger handle suitable for RPC query servers.
pub struct SharedLedger<D> {
    ledger: Arc<AsyncMutex<PerpetualLedger<D>>>,
}

impl<D> SharedLedger<D> {
    pub fn new(ledger: PerpetualLedger<D>) -> Self {
        Self {
            ledger: Arc::new(AsyncMutex::new(ledger)),
        }
    }

    pub async fn lock(&self) -> futures::lock::MutexGuard<'_, PerpetualLedger<D>> {
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
impl<D> PerpetualQuery for SharedLedger<D>
where
    D: PerpetualDB + CommitState + nunchi_common::StateStore + Send + Sync + 'static,
{
    async fn nonce(&self, account: Address) -> Result<u64, PerpetualError> {
        self.lock().await.nonce(&account).await
    }

    async fn market(&self, market: MarketId) -> Result<Option<Market>, PerpetualError> {
        self.lock().await.market(&market).await
    }

    async fn position(
        &self,
        position: crate::PositionId,
    ) -> Result<Option<Position>, PerpetualError> {
        self.lock().await.position(&position).await
    }

    async fn state_root(&self) -> Result<Digest, PerpetualError> {
        Ok(self.lock().await.root())
    }
}

/// Concrete perpetuals RPC server over a query backend.
#[derive(Clone)]
pub struct PerpetualsRpc<Q> {
    query: Q,
}

impl<Q> PerpetualsRpc<Q> {
    pub fn new(query: Q) -> Self {
        Self { query }
    }
}

#[rpc(server, namespace = "perpetuals", namespace_separator = ".")]
pub trait Perpetuals {
    #[method(name = "nonce", param_kind = map)]
    async fn nonce(&self, account: String) -> RpcResult<NonceResponse>;

    #[method(name = "market", param_kind = map)]
    async fn market(&self, market: String) -> RpcResult<Option<MarketResponse>>;

    #[method(name = "position", param_kind = map)]
    async fn position(&self, position: String) -> RpcResult<Option<PositionResponse>>;

    #[method(name = "state_root")]
    async fn state_root(&self) -> RpcResult<RootResponse>;
}

#[async_trait]
impl<Q> PerpetualsServer for PerpetualsRpc<Q>
where
    Q: PerpetualQuery,
{
    async fn nonce(&self, account: String) -> RpcResult<NonceResponse> {
        let account: Address = decode_hex(&account, "account")?;
        let nonce = self.query.nonce(account.clone()).await.map_err(rpc_error)?;
        Ok(NonceResponse {
            account: encode_hex(&account),
            nonce,
        })
    }

    async fn market(&self, market: String) -> RpcResult<Option<MarketResponse>> {
        let market: MarketId = decode_hex(&market, "market")?;
        let market = self.query.market(market).await.map_err(rpc_error)?;
        Ok(market.map(MarketResponse::from))
    }

    async fn position(&self, position: String) -> RpcResult<Option<PositionResponse>> {
        let position: crate::PositionId = decode_hex(&position, "position")?;
        let position = self.query.position(position).await.map_err(rpc_error)?;
        Ok(position.map(PositionResponse::from))
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
    pub collateral_asset: String,
    pub oracle_namespace: String,
    pub oracle_interval_ms: u64,
    pub max_oracle_staleness_ms: u64,
    pub price_decimals: u8,
    pub max_leverage_bps: u32,
    pub maintenance_margin_bps: u32,
    pub funding_interval_ms: u64,
    pub max_funding_rate_bps: u32,
    pub mark_price: String,
    pub index_price: String,
    pub open_interest: String,
    pub last_oracle_interval: u64,
    pub last_oracle_update_ms: u64,
    pub last_funding_ms: u64,
    pub cumulative_funding_long: String,
    pub cumulative_funding_short: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PositionResponse {
    pub id: String,
    pub market: String,
    pub owner: String,
    pub side: String,
    pub quantity: String,
    pub entry_price: String,
    pub collateral: String,
    pub entry_funding_index: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootResponse {
    pub root: String,
}

/// Register the perpetuals module's query RPC methods into a downstream router.
pub fn register<Context, Q>(
    router: &mut RpcRouter<Context>,
    rpc: PerpetualsRpc<Q>,
) -> Result<(), RegisterMethodError>
where
    Q: PerpetualQuery,
{
    router.merge(rpc.into_rpc())
}

fn rpc_error(error: PerpetualError) -> jsonrpsee::types::ErrorObjectOwned {
    module_error(error.to_string())
}

impl From<Market> for MarketResponse {
    fn from(market: Market) -> Self {
        Self {
            id: encode_hex(&market.id),
            base_asset: encode_hex(&market.base_asset),
            quote_asset: encode_hex(&market.quote_asset),
            collateral_asset: encode_hex(&market.collateral_asset),
            oracle_namespace: encode_hex(&market.oracle_namespace),
            oracle_interval_ms: market.oracle_interval_ms,
            max_oracle_staleness_ms: market.max_oracle_staleness_ms,
            price_decimals: market.price_decimals,
            max_leverage_bps: market.max_leverage_bps,
            maintenance_margin_bps: market.maintenance_margin_bps,
            funding_interval_ms: market.funding_interval_ms,
            max_funding_rate_bps: market.max_funding_rate_bps,
            mark_price: market.mark_price.to_string(),
            index_price: market.index_price.to_string(),
            open_interest: market.open_interest.to_string(),
            last_oracle_interval: market.last_oracle_interval,
            last_oracle_update_ms: market.last_oracle_update_ms,
            last_funding_ms: market.last_funding_ms,
            cumulative_funding_long: market.cumulative_funding_long.to_string(),
            cumulative_funding_short: market.cumulative_funding_short.to_string(),
        }
    }
}

impl From<Position> for PositionResponse {
    fn from(position: Position) -> Self {
        Self {
            id: encode_hex(&position.id),
            market: encode_hex(&position.market),
            owner: encode_hex(&position.owner),
            side: match position.side {
                crate::Side::Long => "long",
                crate::Side::Short => "short",
            }
            .to_string(),
            quantity: position.quantity.to_string(),
            entry_price: position.entry_price.to_string(),
            collateral: position.collateral.to_string(),
            entry_funding_index: position.entry_funding_index.to_string(),
        }
    }
}
