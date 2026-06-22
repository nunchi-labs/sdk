use std::collections::BTreeMap;

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use futures::executor::block_on;
use nunchi_common::{Address, RuntimeContext, StateError, StateStore};
use nunchi_crypto::PrivateKey;

use crate::{
    DivergenceLevel, FeedId, MarkInputs, MarketId, OracleConfig, OracleConfigGenesis, OracleError,
    OracleGenesis, OracleLedger, OracleMarketGenesis, OracleOperation, OracleStatus,
    OracleUpdaterGenesis, Price, SourceId, Transaction, UpdaterPolicy,
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

fn id(seed: &'static [u8]) -> Digest {
    Sha256::hash(seed)
}

fn market() -> MarketId {
    MarketId(id(b"market"))
}

fn source() -> SourceId {
    SourceId(id(b"source"))
}

fn feed() -> FeedId {
    FeedId(id(b"feed"))
}

fn context(timestamp_ms: u64) -> RuntimeContext {
    RuntimeContext {
        epoch: 0,
        height: 1,
        timestamp_ms,
    }
}

fn config(admin: &Address) -> OracleConfig {
    OracleConfig {
        admin: admin.clone(),
        price_decimals: 6,
        max_staleness_ms: 1_000,
        max_confidence_bps: 500,
        high_volatility_bps: 1_000,
        divergence_warn_bps: 500,
        divergence_halt_bps: 2_000,
        source_priority: vec![source()],
        allow_negative: false,
    }
}

fn genesis(admin: &PrivateKey, updater: &PrivateKey) -> OracleGenesis {
    OracleGenesis {
        markets: vec![OracleMarketGenesis {
            market: market(),
            config: OracleConfigGenesis {
                admin: Address::external(&admin.public_key()),
                price_decimals: 6,
                max_staleness_ms: 1_000,
                max_confidence_bps: 500,
                high_volatility_bps: 1_000,
                divergence_warn_bps: 500,
                divergence_halt_bps: 2_000,
                source_priority: vec![source()],
                allow_negative: false,
            },
            updaters: vec![OracleUpdaterGenesis {
                source: source(),
                updater: Address::external(&updater.public_key()),
                enabled: true,
            }],
        }],
    }
}

fn sign(signer: &PrivateKey, nonce: u64, operation: OracleOperation) -> Transaction {
    Transaction::sign(signer, nonce, operation)
}

fn configure_tx(admin: &PrivateKey, nonce: u64) -> Transaction {
    sign(
        admin,
        nonce,
        OracleOperation::ConfigureMarket {
            market: market(),
            config: config(&Address::external(&admin.public_key())),
        },
    )
}

fn set_updater_tx(admin: &PrivateKey, updater: &PrivateKey, nonce: u64) -> Transaction {
    sign(
        admin,
        nonce,
        OracleOperation::SetUpdater {
            market: market(),
            source: source(),
            updater: Address::external(&updater.public_key()),
            policy: UpdaterPolicy { enabled: true },
        },
    )
}

fn feed_update_tx(
    updater: &PrivateKey,
    nonce: u64,
    raw_value: i128,
    raw_decimals: u8,
    publish_time_ms: u64,
    confidence: u128,
) -> Transaction {
    sign(
        updater,
        nonce,
        OracleOperation::SubmitFeedUpdate {
            market: market(),
            source: source(),
            feed: feed(),
            raw_value,
            raw_decimals,
            publish_time_ms,
            confidence,
        },
    )
}

fn initialized() -> (OracleLedger<MemoryStore>, PrivateKey, PrivateKey) {
    let admin = PrivateKey::from_seed(1);
    let updater = PrivateKey::from_seed(2);
    let mut ledger = OracleLedger::new(MemoryStore::default());
    block_on(ledger.apply_transaction(&configure_tx(&admin, 0), context(100))).unwrap();
    block_on(ledger.apply_transaction(&set_updater_tx(&admin, &updater, 1), context(100))).unwrap();
    (ledger, admin, updater)
}

#[test]
fn feed_update_normalizes_and_sets_oracle_price() {
    let (mut ledger, _, updater) = initialized();

    let tx = feed_update_tx(&updater, 0, 123_456_789, 8, 900, 1_000);
    block_on(ledger.apply_transaction(&tx, context(1_000))).unwrap();

    let oracle = block_on(ledger.oracle(&market())).unwrap().unwrap();
    assert_eq!(oracle.status, OracleStatus::Fresh);
    assert_eq!(oracle.oracle_price, Some(Price::new(1_234_567, 6)));
    assert_eq!(oracle.external_reference_price, oracle.oracle_price);
    assert_eq!(oracle.external_observed_price, oracle.oracle_price);
}

#[test]
fn unauthorized_updater_is_rejected() {
    let (mut ledger, _, _) = initialized();
    let attacker = PrivateKey::from_seed(3);

    let tx = feed_update_tx(&attacker, 0, 100_000_000, 8, 900, 0);
    let err = block_on(ledger.apply_transaction(&tx, context(1_000))).unwrap_err();

    assert_eq!(err, OracleError::Unauthorized);
}

#[test]
fn stale_and_out_of_order_updates_are_rejected() {
    let (mut ledger, _, updater) = initialized();

    let stale = feed_update_tx(&updater, 0, 100_000_000, 8, 1, 0);
    assert_eq!(
        block_on(ledger.apply_transaction(&stale, context(2_500))).unwrap_err(),
        OracleError::StaleUpdate
    );

    let fresh = feed_update_tx(&updater, 0, 100_000_000, 8, 1_900, 0);
    block_on(ledger.apply_transaction(&fresh, context(2_000))).unwrap();
    let old = feed_update_tx(&updater, 1, 101_000_000, 8, 1_800, 0);
    assert_eq!(
        block_on(ledger.apply_transaction(&old, context(2_000))).unwrap_err(),
        OracleError::OutOfOrderUpdate
    );
}

#[test]
fn high_confidence_sets_high_volatility_status() {
    let (mut ledger, _, updater) = initialized();

    let tx = feed_update_tx(&updater, 0, 100_000_000, 8, 900, 6_000_000);
    block_on(ledger.apply_transaction(&tx, context(1_000))).unwrap();

    let oracle = block_on(ledger.oracle(&market())).unwrap().unwrap();
    assert_eq!(oracle.status, OracleStatus::HighVolatility);
}

#[test]
fn mark_inputs_update_divergence_status() {
    let (mut ledger, admin, updater) = initialized();

    let update = feed_update_tx(&updater, 0, 100_000_000, 8, 900, 0);
    block_on(ledger.apply_transaction(&update, context(1_000))).unwrap();
    let inputs = MarkInputs {
        impact_bid: None,
        impact_ask: None,
        best_bid: None,
        best_ask: None,
        mark_price: Price::new(1_100_000, 6),
        mark_time_ms: 1_000,
    };
    let mark = sign(
        &admin,
        2,
        OracleOperation::SubmitMarkInputs {
            market: market(),
            inputs,
        },
    );
    block_on(ledger.apply_transaction(&mark, context(1_000))).unwrap();

    let oracle = block_on(ledger.oracle(&market())).unwrap().unwrap();
    let divergence = block_on(ledger.divergence(&market())).unwrap().unwrap();
    assert_eq!(oracle.status, OracleStatus::Divergent);
    assert_eq!(divergence.level, DivergenceLevel::Warn);
    assert_eq!(divergence.bps, 1_000);
}

#[test]
fn transaction_codec_round_trips() {
    let admin = PrivateKey::from_seed(1);
    let tx = configure_tx(&admin, 0);
    let encoded = tx.encode();

    assert_eq!(Transaction::decode(encoded).unwrap(), tx);
}

#[test]
fn genesis_seeds_config_and_updater_policy() {
    let admin = PrivateKey::from_seed(1);
    let updater = PrivateKey::from_seed(2);
    let mut ledger = OracleLedger::new(MemoryStore::default());

    block_on(ledger.apply_genesis(&genesis(&admin, &updater))).unwrap();
    let tx = feed_update_tx(&updater, 0, 100_000_000, 8, 900, 0);
    block_on(ledger.apply_transaction(&tx, context(1_000))).unwrap();

    let oracle = block_on(ledger.oracle(&market())).unwrap().unwrap();
    assert_eq!(oracle.status, OracleStatus::Fresh);
    assert_eq!(oracle.oracle_price, Some(Price::new(1_000_000, 6)));
}

#[test]
fn genesis_rejects_updater_for_unknown_source() {
    let admin = PrivateKey::from_seed(1);
    let updater = PrivateKey::from_seed(2);
    let mut genesis = genesis(&admin, &updater);
    genesis.markets[0].updaters[0].source = SourceId(id(b"unknown-source"));
    let mut ledger = OracleLedger::new(MemoryStore::default());

    assert_eq!(
        block_on(ledger.apply_genesis(&genesis)).unwrap_err(),
        OracleError::UnknownSource
    );
}
