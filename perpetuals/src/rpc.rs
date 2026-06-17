//! JSON-RPC surface for the perpetuals module.

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

use crate::{
    Address, LedgerError, Market, MarketId, PerpetualDB, PerpetualLedger, Position, PositionId,
};

#[async_trait]
pub trait PerpetualQuery: Clone + Send + Sync + 'static {
    async fn nonce(&self, account: Address) -> Result<u64, LedgerError>;

    async fn market(&self, market: MarketId) -> Result<Option<Market>, LedgerError>;

    async fn position(&self, position: PositionId) -> Result<Option<Position>, LedgerError>;

    async fn state_root(&self) -> Result<Digest, LedgerError>;
}

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
    D: PerpetualDB + CommitState + Send + Sync + 'static,
{
    async fn nonce(&self, account: Address) -> Result<u64, LedgerError> {
        self.lock().await.nonce(&account).await
    }

    async fn market(&self, market: MarketId) -> Result<Option<Market>, LedgerError> {
        self.lock().await.market(&market).await
    }

    async fn position(&self, position: PositionId) -> Result<Option<Position>, LedgerError> {
        self.lock().await.position(&position).await
    }

    async fn state_root(&self) -> Result<Digest, LedgerError> {
        Ok(self.lock().await.root())
    }
}

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
        let account = decode_account(&account)?;
        let nonce = self.query.nonce(account.clone()).await.map_err(rpc_error)?;
        Ok(NonceResponse {
            account: encode_hex(&account),
            nonce,
        })
    }

    async fn market(&self, market: String) -> RpcResult<Option<MarketResponse>> {
        let market = decode_market(&market)?;
        let market = self.query.market(market).await.map_err(rpc_error)?;
        Ok(market.map(MarketResponse::from))
    }

    async fn position(&self, position: String) -> RpcResult<Option<PositionResponse>> {
        let position = decode_position(&position)?;
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
    pub max_leverage_bps: u32,
    pub maintenance_margin_bps: u32,
    pub mark_price: String,
    pub open_interest: String,
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
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootResponse {
    pub root: String,
}

pub fn register<Context, Q>(
    router: &mut RpcRouter<Context>,
    rpc: PerpetualsRpc<Q>,
) -> Result<(), RegisterMethodError>
where
    Q: PerpetualQuery,
{
    router.merge(rpc.into_rpc())
}

fn decode_account(value: &str) -> RpcResult<Address> {
    decode_hex(value, "account")
}

fn decode_market(value: &str) -> RpcResult<MarketId> {
    decode_hex(value, "market")
}

fn decode_position(value: &str) -> RpcResult<PositionId> {
    decode_hex(value, "position")
}

fn rpc_error(error: LedgerError) -> jsonrpsee::types::ErrorObjectOwned {
    module_error(error.to_string())
}

impl From<Market> for MarketResponse {
    fn from(market: Market) -> Self {
        Self {
            id: encode_hex(&market.id),
            base_asset: encode_hex(&market.base_asset),
            quote_asset: encode_hex(&market.quote_asset),
            collateral_asset: encode_hex(&market.collateral_asset),
            max_leverage_bps: market.max_leverage_bps,
            maintenance_margin_bps: market.maintenance_margin_bps,
            mark_price: market.mark_price.to_string(),
            open_interest: market.open_interest.to_string(),
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
                crate::Side::Long => "long".to_string(),
                crate::Side::Short => "short".to_string(),
            },
            quantity: position.quantity.to_string(),
            entry_price: position.entry_price.to_string(),
            collateral: position.collateral.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use commonware_cryptography::{Hasher, Sha256};
    use commonware_runtime::Runner as _;

    use super::*;
    use crate::{derive_market_id, derive_position_id, CoinId, Side};

    #[derive(Clone)]
    struct MockQuery {
        inner: Arc<MockState>,
    }

    struct MockState {
        account: Address,
        market: Market,
        position: Position,
    }

    impl MockQuery {
        fn new() -> Self {
            let account =
                Address::external(&nunchi_crypto::PrivateKey::ed25519_from_seed(9).public_key());
            let base_asset = CoinId(Sha256::hash(b"BTC"));
            let quote_asset = CoinId(Sha256::hash(b"USD"));
            let collateral_asset = CoinId(Sha256::hash(b"USDC"));
            let market_id = derive_market_id(base_asset, quote_asset, collateral_asset, 0);
            let market = Market {
                id: market_id,
                base_asset,
                quote_asset,
                collateral_asset,
                max_leverage_bps: 25_000,
                maintenance_margin_bps: 500,
                mark_price: 50_000,
                open_interest: 1_000,
            };
            let position = Position {
                id: derive_position_id(&account, &market_id, 0),
                market: market_id,
                owner: account.clone(),
                side: Side::Long,
                quantity: 1_000,
                entry_price: 49_000,
                collateral: 2_500,
            };
            Self {
                inner: Arc::new(MockState {
                    account,
                    market,
                    position,
                }),
            }
        }
    }

    #[async_trait]
    impl PerpetualQuery for MockQuery {
        async fn nonce(&self, account: Address) -> Result<u64, LedgerError> {
            assert_eq!(account, self.inner.account);
            Ok(3)
        }

        async fn market(&self, market: MarketId) -> Result<Option<Market>, LedgerError> {
            assert_eq!(market, self.inner.market.id);
            Ok(Some(self.inner.market.clone()))
        }

        async fn position(&self, position: PositionId) -> Result<Option<Position>, LedgerError> {
            assert_eq!(position, self.inner.position.id);
            Ok(Some(self.inner.position.clone()))
        }

        async fn state_root(&self) -> Result<Digest, LedgerError> {
            Ok(Sha256::hash(b"perpetuals-root"))
        }
    }

    #[test]
    fn perpetual_rpc_queries() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let query = MockQuery::new();
            let mut router = RpcRouter::new(());
            register(&mut router, PerpetualsRpc::new(query.clone()))
                .expect("register perpetuals RPC");
            let module = router.into_module();

            let account = encode_hex(&query.inner.account);
            let market = encode_hex(&query.inner.market.id);
            let position = encode_hex(&query.inner.position.id);

            let mut nonce_params = jsonrpsee::core::params::ObjectParams::new();
            nonce_params
                .insert("account", account)
                .expect("serialize nonce params");
            let nonce: NonceResponse = module
                .call("perpetuals.nonce", nonce_params)
                .await
                .expect("nonce response");
            assert_eq!(nonce.nonce, 3);

            let mut market_params = jsonrpsee::core::params::ObjectParams::new();
            market_params
                .insert("market", market)
                .expect("serialize market params");
            let market: Option<MarketResponse> = module
                .call("perpetuals.market", market_params)
                .await
                .expect("market response");
            assert_eq!(market.unwrap().max_leverage_bps, 25_000);

            let mut position_params = jsonrpsee::core::params::ObjectParams::new();
            position_params
                .insert("position", position)
                .expect("serialize position params");
            let position: Option<PositionResponse> = module
                .call("perpetuals.position", position_params)
                .await
                .expect("position response");
            assert_eq!(position.unwrap().side, "long");

            let root: RootResponse = module
                .call(
                    "perpetuals.state_root",
                    jsonrpsee::core::EmptyServerParams::new(),
                )
                .await
                .expect("root response");
            assert_eq!(root.root, encode_hex(&Sha256::hash(b"perpetuals-root")));
        });
    }
}
