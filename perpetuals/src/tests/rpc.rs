use std::sync::Arc;

use async_trait::async_trait;
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::Runner as _;
use nunchi_oracle::NamespaceId;
use nunchi_rpc::{encode_hex, RpcRouter};

use nunchi_crypto::PrivateKey;

use crate::{
    Address, CoinId, Market, MarketId, PerpetualError, Position, PositionId, Side,
    DEFAULT_LIQUIDATION_REWARD_BPS,
};

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
        let account = Address::external(&PrivateKey::from_seed(1).public_key());
        let market_id = Sha256::hash(b"btc-usd-perp");
        let market = Market {
            id: market_id,
            base_asset: CoinId(Sha256::hash(b"btc")),
            quote_asset: CoinId(Sha256::hash(b"usd")),
            collateral_asset: CoinId(Sha256::hash(b"usdc")),
            oracle_namespace: NamespaceId(Sha256::hash(b"oracle")),
            oracle_writer: account.clone(),
            clob_market: Some(Sha256::hash(b"clob")),
            oracle_interval_ms: 1_000,
            max_oracle_staleness_ms: 60_000,
            price_decimals: 2,
            max_leverage_bps: 50_000,
            maintenance_margin_bps: 1_000,
            funding_interval_ms: 3_600_000,
            max_funding_rate_bps: 100,
            liquidation_reward_bps: DEFAULT_LIQUIDATION_REWARD_BPS,
            mark_price: 100_000,
            index_price: 99_500,
            long_open_interest: 4_000_000_000,
            short_open_interest: 4_000_000_000,
            last_oracle_interval: 1,
            last_oracle_update_ms: 1_000,
            last_funding_ms: 0,
            cumulative_funding_long: 0,
            cumulative_funding_short: 0,
        };
        let position = Position {
            id: Sha256::hash(b"position"),
            market: market_id,
            owner: account.clone(),
            side: Side::Long,
            quantity: 2_000_000_000,
            entry_price: 100_000,
            collateral: 10_000,
            entry_funding_index: 0,
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
impl crate::rpc::PerpetualQuery for MockQuery {
    async fn nonce(&self, account: Address) -> Result<u64, PerpetualError> {
        assert_eq!(account, self.inner.account);
        Ok(9)
    }

    async fn market(&self, market: MarketId) -> Result<Option<Market>, PerpetualError> {
        assert_eq!(market, self.inner.market.id);
        Ok(Some(self.inner.market.clone()))
    }

    async fn position(&self, position: PositionId) -> Result<Option<Position>, PerpetualError> {
        assert_eq!(position, self.inner.position.id);
        Ok(Some(self.inner.position.clone()))
    }

    async fn state_root(&self) -> Result<commonware_cryptography::sha256::Digest, PerpetualError> {
        Ok(Sha256::hash(b"perps-root"))
    }
}

#[test]
fn perpetuals_rpc_queries() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let query = MockQuery::new();
        let mut router = RpcRouter::new(());
        crate::rpc::register(&mut router, crate::rpc::PerpetualsRpc::new(query.clone()))
            .expect("register perpetuals RPC");
        let module = router.into_module();
        let account = encode_hex(&query.inner.account);
        let market = encode_hex(&query.inner.market.id);
        let position = encode_hex(&query.inner.position.id);

        let mut nonce_params = jsonrpsee::core::params::ObjectParams::new();
        nonce_params
            .insert("account", account.clone())
            .expect("serialize nonce params");
        let nonce: crate::rpc::NonceResponse = module
            .call("perpetuals.nonce", nonce_params)
            .await
            .expect("nonce response");
        assert_eq!(nonce.account, account);
        assert_eq!(nonce.nonce, 9);

        let mut market_params = jsonrpsee::core::params::ObjectParams::new();
        market_params
            .insert("market", market.clone())
            .expect("serialize market params");
        let market_resp: Option<crate::rpc::MarketResponse> = module
            .call("perpetuals.market", market_params)
            .await
            .expect("market response");
        let market_resp = market_resp.expect("market exists");
        assert_eq!(market_resp.id, market);
        assert_eq!(market_resp.matched_open_interest, "4000000000");

        let mut position_params = jsonrpsee::core::params::ObjectParams::new();
        position_params
            .insert("position", position.clone())
            .expect("serialize position params");
        let position_resp: Option<crate::rpc::PositionResponse> = module
            .call("perpetuals.position", position_params)
            .await
            .expect("position response");
        let position_resp = position_resp.expect("position exists");
        assert_eq!(position_resp.id, position);
        assert_eq!(position_resp.side, "long");

        let root: crate::rpc::RootResponse = module
            .call(
                "perpetuals.state_root",
                jsonrpsee::core::EmptyServerParams::new(),
            )
            .await
            .expect("root response");
        assert_eq!(root.root, encode_hex(&Sha256::hash(b"perps-root")));
    });
}
