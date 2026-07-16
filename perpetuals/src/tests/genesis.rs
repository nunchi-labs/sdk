use std::collections::BTreeMap;

use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use futures::executor::block_on;
use nunchi_coins::{CoinDB, CoinSpec, TokenDefinition, TokenName, TokenSymbol};
use nunchi_common::{Address, StateError, StateStore};
use nunchi_crypto::PrivateKey;
use nunchi_oracle::NamespaceId;

use crate::{
    CoinId, MarketGenesis, PerpetualLedger, PerpetualsGenesis, BPS_DENOMINATOR,
    DEFAULT_LIQUIDATION_REWARD_BPS,
};

#[derive(Default)]
struct MemoryStore {
    values: BTreeMap<Digest, Option<Vec<u8>>>,
}

impl StateStore for MemoryStore {
    async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.values.get(key).cloned().flatten())
    }

    fn set(&mut self, key: Digest, value: Vec<u8>) {
        self.values.insert(key, Some(value));
    }

    fn remove(&mut self, key: Digest) {
        self.values.insert(key, None);
    }
}

fn digest(seed: &'static [u8]) -> Digest {
    Sha256::hash(seed)
}

fn coin(seed: &'static [u8]) -> CoinId {
    CoinId(digest(seed))
}

#[test]
fn perpetuals_genesis_json_roundtrips() {
    let writer = PrivateKey::from_seed(1);
    let genesis = PerpetualsGenesis {
        markets: vec![MarketGenesis {
            base_asset: coin(b"btc"),
            quote_asset: coin(b"usd"),
            collateral_asset: coin(b"usdc"),
            oracle_namespace: NamespaceId(digest(b"oracle")),
            oracle_writer: Address::external(&writer.public_key()),
            clob_market: Some(digest(b"clob-market")),
            oracle_interval_ms: 1_000,
            max_oracle_staleness_ms: 60_000,
            price_decimals: 2,
            max_leverage_bps: 50_000,
            maintenance_margin_bps: 1_000,
            funding_interval_ms: 3_600_000,
            max_funding_rate_bps: 100,
            liquidation_reward_bps: DEFAULT_LIQUIDATION_REWARD_BPS,
        }],
    };

    let raw = serde_json::to_string(&genesis).expect("serialize genesis");
    let decoded: PerpetualsGenesis = serde_json::from_str(&raw).expect("deserialize genesis");
    assert_eq!(decoded, genesis);
}

#[test]
fn apply_genesis_seeds_markets() {
    let writer = PrivateKey::from_seed(2);
    let issuer = PrivateKey::from_seed(3);
    let mut store = MemoryStore::default();
    store.set_token(&TokenDefinition::from_spec(
        coin(b"usdc"),
        Address::external(&issuer.public_key()),
        CoinSpec::new(
            TokenSymbol::new("USDC").unwrap(),
            TokenName::new("USD Coin").unwrap(),
            6,
            1_000_000,
            None,
        ),
    ));

    let genesis = PerpetualsGenesis {
        markets: vec![MarketGenesis {
            base_asset: coin(b"btc"),
            quote_asset: coin(b"usd"),
            collateral_asset: coin(b"usdc"),
            oracle_namespace: NamespaceId(digest(b"oracle")),
            oracle_writer: Address::external(&writer.public_key()),
            clob_market: None,
            oracle_interval_ms: 1_000,
            max_oracle_staleness_ms: 60_000,
            price_decimals: 0,
            max_leverage_bps: 10 * BPS_DENOMINATOR,
            maintenance_margin_bps: 500,
            funding_interval_ms: 3_600_000,
            max_funding_rate_bps: 100,
            liquidation_reward_bps: DEFAULT_LIQUIDATION_REWARD_BPS,
        }],
    };

    let ids = block_on(PerpetualLedger::new(&mut store).apply_genesis(&genesis)).unwrap();
    assert_eq!(ids.len(), 1);

    let market = block_on(PerpetualLedger::new(&mut store).market(&ids[0]))
        .unwrap()
        .expect("market exists");
    assert_eq!(market.collateral_asset, coin(b"usdc"));
    assert_eq!(market.max_leverage_bps, 10 * BPS_DENOMINATOR);
}
