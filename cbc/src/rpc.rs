//! JSON-RPC surface for the CBC module.

use std::sync::Arc;

use commonware_cryptography::sha256::Digest;
use futures::lock::Mutex as AsyncMutex;
use jsonrpsee::{
    core::{async_trait, RegisterMethodError, RpcResult},
    proc_macros::rpc,
};
use nunchi_clob::{MarketId, Side};
use nunchi_common::{Address, CommitState};
use nunchi_house::HouseDB;
use nunchi_rpc::{decode_hex, encode_hex, invalid_params, module_error, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::{
    BatchIntent, BatchOutcome, BatchParams, BatchResult, CbcDB, CbcError, CbcLedger, ClearingFill,
    IntentId, IntentStatus, MarketClearingState,
};

/// Read-only CBC state required by the CBC RPC server.
#[async_trait]
pub trait CbcQuery: Clone + Send + Sync + 'static {
    async fn nonce(&self, account: Address) -> Result<u64, CbcError>;

    async fn params(&self, market: MarketId) -> Result<Option<BatchParams>, CbcError>;

    async fn markets(&self) -> Result<Vec<MarketId>, CbcError>;

    async fn clearing_state(&self, market: MarketId) -> Result<MarketClearingState, CbcError>;

    async fn intent(&self, intent: IntentId) -> Result<Option<BatchIntent>, CbcError>;

    async fn pending_intents(&self, market: MarketId) -> Result<Vec<BatchIntent>, CbcError>;

    async fn batch_result(
        &self,
        market: MarketId,
        batch_number: u64,
    ) -> Result<Option<BatchResult>, CbcError>;

    async fn state_root(&self) -> Result<Digest, CbcError>;
}

/// Shared committed CBC ledger handle suitable for RPC query servers.
pub struct SharedLedger<D> {
    ledger: Arc<AsyncMutex<CbcLedger<D>>>,
}

impl<D> SharedLedger<D> {
    pub fn new(ledger: CbcLedger<D>) -> Self {
        Self {
            ledger: Arc::new(AsyncMutex::new(ledger)),
        }
    }

    pub async fn lock(&self) -> futures::lock::MutexGuard<'_, CbcLedger<D>> {
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
impl<D> CbcQuery for SharedLedger<D>
where
    D: CbcDB + HouseDB + CommitState + Send + Sync + 'static,
{
    async fn nonce(&self, account: Address) -> Result<u64, CbcError> {
        self.lock().await.nonce(&account).await
    }

    async fn params(&self, market: MarketId) -> Result<Option<BatchParams>, CbcError> {
        self.lock().await.params(&market).await
    }

    async fn markets(&self) -> Result<Vec<MarketId>, CbcError> {
        self.lock().await.markets().await
    }

    async fn clearing_state(&self, market: MarketId) -> Result<MarketClearingState, CbcError> {
        self.lock().await.clearing_state(&market).await
    }

    async fn intent(&self, intent: IntentId) -> Result<Option<BatchIntent>, CbcError> {
        self.lock().await.intent(&intent).await
    }

    async fn pending_intents(&self, market: MarketId) -> Result<Vec<BatchIntent>, CbcError> {
        self.lock().await.pending_intents(&market).await
    }

    async fn batch_result(
        &self,
        market: MarketId,
        batch_number: u64,
    ) -> Result<Option<BatchResult>, CbcError> {
        self.lock().await.batch_result(&market, batch_number).await
    }

    async fn state_root(&self) -> Result<Digest, CbcError> {
        Ok(self.lock().await.db().root())
    }
}

/// Concrete CBC RPC server over a query backend.
#[derive(Clone)]
pub struct CbcRpc<Q> {
    query: Q,
}

impl<Q> CbcRpc<Q> {
    pub fn new(query: Q) -> Self {
        Self { query }
    }
}

#[rpc(server, namespace = "cbc", namespace_separator = ".")]
pub trait Cbc {
    #[method(name = "nonce", param_kind = map)]
    async fn nonce(&self, account: String) -> RpcResult<NonceResponse>;

    #[method(name = "params", param_kind = map)]
    async fn params(&self, market: String) -> RpcResult<Option<ParamsResponse>>;

    #[method(name = "markets")]
    async fn markets(&self) -> RpcResult<MarketsResponse>;

    #[method(name = "state", param_kind = map)]
    async fn state(&self, market: String) -> RpcResult<StateResponse>;

    #[method(name = "intent", param_kind = map)]
    async fn intent(&self, intent: String) -> RpcResult<Option<IntentResponse>>;

    #[method(name = "pending", param_kind = map)]
    async fn pending(&self, market: String) -> RpcResult<IntentsResponse>;

    #[method(name = "result", param_kind = map)]
    async fn result(&self, market: String, batch_number: u64)
        -> RpcResult<Option<ResultResponse>>;

    #[method(name = "state_root")]
    async fn state_root(&self) -> RpcResult<RootResponse>;
}

#[async_trait]
impl<Q> CbcServer for CbcRpc<Q>
where
    Q: CbcQuery,
{
    async fn nonce(&self, account: String) -> RpcResult<NonceResponse> {
        let account = decode_account(&account)?;
        let nonce = self.query.nonce(account.clone()).await.map_err(rpc_error)?;
        Ok(NonceResponse {
            account: account.to_bech32(),
            nonce,
        })
    }

    async fn params(&self, market: String) -> RpcResult<Option<ParamsResponse>> {
        let market = decode_hex(&market, "market")?;
        Ok(self
            .query
            .params(market)
            .await
            .map_err(rpc_error)?
            .map(ParamsResponse::from))
    }

    async fn markets(&self) -> RpcResult<MarketsResponse> {
        let markets = self
            .query
            .markets()
            .await
            .map_err(rpc_error)?
            .iter()
            .map(encode_hex)
            .collect();
        Ok(MarketsResponse { markets })
    }

    async fn state(&self, market: String) -> RpcResult<StateResponse> {
        let market_id = decode_hex(&market, "market")?;
        let state = self
            .query
            .clearing_state(market_id)
            .await
            .map_err(rpc_error)?;
        Ok(StateResponse {
            market,
            mode: mode_name(state.mode).to_string(),
            batch_number: state.batch_number,
            last_clear_height: state.last_clear_height,
            pending_notional: state.pending_notional.to_string(),
        })
    }

    async fn intent(&self, intent: String) -> RpcResult<Option<IntentResponse>> {
        let intent = decode_hex(&intent, "intent")?;
        Ok(self
            .query
            .intent(intent)
            .await
            .map_err(rpc_error)?
            .map(IntentResponse::from))
    }

    async fn pending(&self, market: String) -> RpcResult<IntentsResponse> {
        let market = decode_hex(&market, "market")?;
        let intents = self
            .query
            .pending_intents(market)
            .await
            .map_err(rpc_error)?
            .into_iter()
            .map(IntentResponse::from)
            .collect();
        Ok(IntentsResponse { intents })
    }

    async fn result(
        &self,
        market: String,
        batch_number: u64,
    ) -> RpcResult<Option<ResultResponse>> {
        let market = decode_hex(&market, "market")?;
        Ok(self
            .query
            .batch_result(market, batch_number)
            .await
            .map_err(rpc_error)?
            .map(ResultResponse::from))
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
pub struct ParamsResponse {
    pub admin: String,
    pub keeper: String,
    pub cadence_blocks: u64,
    pub oracle_band_bps: u32,
    pub max_batch_notional: String,
    pub max_submitter_notional: String,
    pub min_clearing_qty: String,
    pub price_tick: String,
    pub size_tick: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarketsResponse {
    pub markets: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateResponse {
    pub market: String,
    pub mode: String,
    pub batch_number: u64,
    pub last_clear_height: u64,
    pub pending_notional: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntentResponse {
    pub id: String,
    pub market: String,
    pub vault: String,
    pub submitter: String,
    pub side: String,
    pub limit_price: String,
    pub original_base: String,
    pub remaining_base: String,
    pub filled_base: String,
    pub reduce_only: bool,
    pub expiry_height: u64,
    pub sequence: u64,
    pub status: String,
    pub submitted_at_height: u64,
    pub submitted_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntentsResponse {
    pub intents: Vec<IntentResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FillResponse {
    pub intent: String,
    pub vault: String,
    pub side: String,
    pub base_quantity: String,
    pub quote_quantity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResultResponse {
    pub market: String,
    pub batch_number: u64,
    pub outcome: String,
    pub oracle_price: String,
    pub clearing_price: String,
    pub total_base: String,
    pub fills: Vec<FillResponse>,
    pub rejected: Vec<String>,
    pub cleared_at_height: u64,
    pub cleared_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootResponse {
    pub root: String,
}

/// Register the CBC module's query RPC methods into a downstream router.
pub fn register<Context, Q>(
    router: &mut RpcRouter<Context>,
    rpc: CbcRpc<Q>,
) -> Result<(), RegisterMethodError>
where
    Q: CbcQuery,
{
    router.merge(rpc.into_rpc())
}

fn decode_account(value: &str) -> RpcResult<Address> {
    Address::from_bech32(value)
        .map_err(|err| invalid_params(format!("invalid account address: {err}")))
}

fn side_name(side: Side) -> &'static str {
    match side {
        Side::Bid => "bid",
        Side::Ask => "ask",
    }
}

fn mode_name(mode: nunchi_house::Mode) -> &'static str {
    match mode {
        nunchi_house::Mode::Live => "live",
        nunchi_house::Mode::Frozen => "frozen",
        nunchi_house::Mode::Halt => "halt",
    }
}

fn status_name(status: IntentStatus) -> &'static str {
    match status {
        IntentStatus::Pending => "pending",
        IntentStatus::PartiallyFilled => "partially_filled",
        IntentStatus::Filled => "filled",
        IntentStatus::Cancelled => "cancelled",
        IntentStatus::Expired => "expired",
        IntentStatus::Rejected => "rejected",
    }
}

fn outcome_name(outcome: BatchOutcome) -> &'static str {
    match outcome {
        BatchOutcome::Cleared => "cleared",
        BatchOutcome::NoCross => "no_cross",
        BatchOutcome::OutsideBand => "outside_band",
    }
}

fn rpc_error(error: CbcError) -> jsonrpsee::types::ErrorObjectOwned {
    module_error(error.to_string())
}

impl From<BatchParams> for ParamsResponse {
    fn from(params: BatchParams) -> Self {
        Self {
            admin: params.admin.to_bech32(),
            keeper: params.keeper.to_bech32(),
            cadence_blocks: params.cadence_blocks,
            oracle_band_bps: params.oracle_band_bps,
            max_batch_notional: params.max_batch_notional.to_string(),
            max_submitter_notional: params.max_submitter_notional.to_string(),
            min_clearing_qty: params.min_clearing_qty.to_string(),
            price_tick: params.price_tick.to_string(),
            size_tick: params.size_tick.to_string(),
        }
    }
}

impl From<BatchIntent> for IntentResponse {
    fn from(intent: BatchIntent) -> Self {
        Self {
            id: encode_hex(&intent.id),
            market: encode_hex(&intent.market),
            vault: encode_hex(&intent.vault),
            submitter: intent.submitter.to_bech32(),
            side: side_name(intent.side).to_string(),
            limit_price: intent.limit_price.to_string(),
            original_base: intent.original_base.to_string(),
            remaining_base: intent.remaining_base.to_string(),
            filled_base: intent.filled_base.to_string(),
            reduce_only: intent.reduce_only,
            expiry_height: intent.expiry_height,
            sequence: intent.sequence,
            status: status_name(intent.status).to_string(),
            submitted_at_height: intent.submitted_at_height,
            submitted_at_ms: intent.submitted_at_ms,
        }
    }
}

impl From<ClearingFill> for FillResponse {
    fn from(fill: ClearingFill) -> Self {
        Self {
            intent: encode_hex(&fill.intent),
            vault: encode_hex(&fill.vault),
            side: side_name(fill.side).to_string(),
            base_quantity: fill.base_quantity.to_string(),
            quote_quantity: fill.quote_quantity.to_string(),
        }
    }
}

impl From<BatchResult> for ResultResponse {
    fn from(result: BatchResult) -> Self {
        Self {
            market: encode_hex(&result.market),
            batch_number: result.batch_number,
            outcome: outcome_name(result.outcome).to_string(),
            oracle_price: result.oracle_price.to_string(),
            clearing_price: result.clearing_price.to_string(),
            total_base: result.total_base.to_string(),
            fills: result.fills.into_iter().map(FillResponse::from).collect(),
            rejected: result.rejected.iter().map(encode_hex).collect(),
            cleared_at_height: result.cleared_at_height,
            cleared_at_ms: result.cleared_at_ms,
        }
    }
}
