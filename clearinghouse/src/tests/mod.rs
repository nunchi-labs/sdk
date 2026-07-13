use std::collections::BTreeMap;

use commonware_codec::Encode;
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use futures::executor::block_on;
use nunchi_clob::{
    market_id, AssetId, ClobLedger, ClobOperation, Side as ClobSide, TimeInForce,
    Transaction as ClobTransaction,
};
use nunchi_coins::{CoinDB, CoinSpec, TokenDefinition, TokenName, TokenSymbol};
use nunchi_common::{Address, RuntimeContext, StateError, StateStore};
use nunchi_crypto::PrivateKey;
use nunchi_oracle::{
    IntervalKey, NamespaceId, OracleLedger, OracleOperation, Transaction as OracleTransaction,
};
use nunchi_perpetuals::{
    derive_position_id_for_side, CoinId, OraclePricePayload, PerpetualLedger, Side as PerpsSide,
    BPS_DENOMINATOR, DEFAULT_LIQUIDATION_REWARD_BPS,
};

use crate::{
    ClearinghouseDB, ClearinghouseLedger, ClearinghouseOperation, SettlementDomain,
    Transaction as ClearingTx,
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

fn context(timestamp_ms: u64) -> RuntimeContext {
    RuntimeContext {
        epoch: 0,
        height: timestamp_ms / 100,
        timestamp_ms,
        block_digest: None,
    }
}

fn digest(seed: &'static [u8]) -> Digest {
    Sha256::hash(seed)
}

fn coin(seed: &'static [u8]) -> CoinId {
    CoinId(digest(seed))
}

fn asset(seed: &'static [u8]) -> AssetId {
    AssetId(digest(seed))
}

fn namespace() -> NamespaceId {
    NamespaceId(digest(b"perps-price-feed"))
}

fn address(signer: &PrivateKey) -> Address {
    Address::external(&signer.public_key())
}

const MARKET_TICK: u128 = 5;
const MARKET_LOT: u128 = 2;
const FILL_PRICE: u128 = 100;
const FILL_QTY: u128 = 4;

fn clob_market_id() -> nunchi_clob::MarketId {
    market_id(&asset(b"base"), &asset(b"quote"), MARKET_TICK, MARKET_LOT)
}

fn seed_collateral(store: &mut MemoryStore, owner: &Address, amount: u128) {
    let issuer = address(&PrivateKey::from_seed(999));
    let token = TokenDefinition::from_spec(
        coin(b"usdc"),
        issuer,
        CoinSpec::new(
            TokenSymbol::new("USDC").unwrap(),
            TokenName::new("USD Coin").unwrap(),
            6,
            1_000_000_000,
            None,
        ),
    );
    store.set_token(&token);
    store.set_balance(owner, &coin(b"usdc"), amount);
}

fn append_price(
    store: &mut MemoryStore,
    writer: &PrivateKey,
    nonce: u64,
    market: Digest,
    price: u128,
    timestamp_ms: u64,
) {
    let payload = OraclePricePayload {
        market,
        price,
        price_decimals: 0,
        source_timestamp_ms: timestamp_ms,
    };
    let append = OracleTransaction::sign(
        writer,
        nonce,
        OracleOperation::AppendRecord {
            namespace: namespace(),
            interval: IntervalKey::new(timestamp_ms / 1_000),
            payload: payload.encode().as_ref().to_vec(),
            proof: None,
        },
    );
    let mut oracle = OracleLedger::new(store);
    block_on(oracle.apply_transaction(&append, context(timestamp_ms))).unwrap();
}

fn setup_perps_market(store: &mut MemoryStore, clob_market: nunchi_clob::MarketId) -> Digest {
    let oracle_writer = PrivateKey::from_seed(2);
    let perps_market = block_on(
        PerpetualLedger::new(&mut *store).create_market(
            coin(b"base"),
            coin(b"usd"),
            coin(b"usdc"),
            namespace(),
            address(&oracle_writer),
            Some(clob_market.0),
            1_000,
            10_000,
            0,
            10 * BPS_DENOMINATOR,
            500,
            3_600_000,
            100,
            DEFAULT_LIQUIDATION_REWARD_BPS,
        ),
    )
    .unwrap();
    append_price(store, &oracle_writer, 0, perps_market, FILL_PRICE, 1_000);
    block_on(
        PerpetualLedger::new(&mut *store).refresh_market_from_oracle(perps_market, context(1_000)),
    )
    .unwrap();
    perps_market
}

fn register_perps_market(
    store: &mut MemoryStore,
    clob_market: nunchi_clob::MarketId,
    perps_market: Digest,
) {
    let settler = PrivateKey::from_seed(3);
    block_on(
        ClearinghouseLedger::new(store).apply_transaction(
            &ClearingTx::sign(
                &settler,
                0,
                ClearinghouseOperation::RegisterPerpsMarket {
                    clob_market,
                    perps_market,
                },
            ),
            context(1_000),
        ),
    )
    .unwrap();
}

#[test]
fn settle_fill_opens_counterparty_perps_positions() {
    let maker = PrivateKey::from_seed(1);
    let taker = PrivateKey::from_seed(2);
    let settler = PrivateKey::from_seed(3);
    let mut store = MemoryStore::default();
    let clob_market = clob_market_id();

    block_on(
        ClobLedger::new(&mut store).apply_transaction(
            &ClobTransaction::sign(
                &maker,
                0,
                ClobOperation::CreateMarket {
                    base_asset: asset(b"base"),
                    quote_asset: asset(b"quote"),
                    tick_size: MARKET_TICK,
                    lot_size: MARKET_LOT,
                },
            ),
            context(1_000),
        ),
    )
    .unwrap();

    let perps_market = setup_perps_market(&mut store, clob_market);
    register_perps_market(&mut store, clob_market, perps_market);

    seed_collateral(&mut store, &address(&maker), 100_000);
    seed_collateral(&mut store, &address(&taker), 100_000);

    block_on(
        ClobLedger::new(&mut store).apply_transaction(
            &ClobTransaction::sign(
                &maker,
                1,
                ClobOperation::PlaceOrder {
                    market: clob_market,
                    side: ClobSide::Ask,
                    price: FILL_PRICE,
                    base_quantity: 10,
                    time_in_force: TimeInForce::GoodTilCancelled,
                },
            ),
            context(2_000),
        ),
    )
    .unwrap();

    block_on(
        ClobLedger::new(&mut store).apply_transaction(
            &ClobTransaction::sign(
                &taker,
                0,
                ClobOperation::PlaceOrder {
                    market: clob_market,
                    side: ClobSide::Bid,
                    price: FILL_PRICE,
                    base_quantity: FILL_QTY,
                    time_in_force: TimeInForce::ImmediateOrCancel,
                },
            ),
            context(3_000),
        ),
    )
    .unwrap();

    let fill = block_on(ClobLedger::new(&mut store).market_fills(&clob_market))
        .unwrap()
        .pop()
        .unwrap();

    block_on(
        ClearinghouseLedger::new(&mut store).apply_transaction(
            &ClearingTx::sign(
                &settler,
                1,
                ClearinghouseOperation::SettleFill { fill: fill.id },
            ),
            context(4_000),
        ),
    )
    .unwrap();

    let perps = PerpetualLedger::new(&mut store);
    let market = block_on(perps.market(&perps_market)).unwrap().unwrap();
    assert_eq!(market.long_open_interest, FILL_QTY * nunchi_perpetuals::PRICE_SCALE);
    assert_eq!(market.short_open_interest, FILL_QTY * nunchi_perpetuals::PRICE_SCALE);

    let maker_position = block_on(
        perps.position(&derive_position_id_for_side(
            &address(&maker),
            &perps_market,
            PerpsSide::Short,
        )),
    )
    .unwrap()
    .unwrap();
    assert_eq!(maker_position.quantity, FILL_QTY * nunchi_perpetuals::PRICE_SCALE);

    let taker_position = block_on(
        perps.position(&derive_position_id_for_side(
            &address(&taker),
            &perps_market,
            PerpsSide::Long,
        )),
    )
    .unwrap()
    .unwrap();
    assert_eq!(taker_position.quantity, FILL_QTY * nunchi_perpetuals::PRICE_SCALE);

    let registered = block_on(
        ClearinghouseLedger::new(&mut store)
            .db()
            .settlement_market_for_clob(&clob_market),
    )
    .unwrap()
    .unwrap();
    assert!(matches!(
        registered.domain,
        SettlementDomain::Perps(id) if id == perps_market
    ));
}

#[test]
fn settle_fill_is_idempotent_guarded() {
    let maker = PrivateKey::from_seed(10);
    let taker = PrivateKey::from_seed(11);
    let mut store = MemoryStore::default();
    let clob_market = clob_market_id();

    block_on(
        ClobLedger::new(&mut store).apply_transaction(
            &ClobTransaction::sign(
                &maker,
                0,
                ClobOperation::CreateMarket {
                    base_asset: asset(b"base"),
                    quote_asset: asset(b"quote"),
                    tick_size: MARKET_TICK,
                    lot_size: MARKET_LOT,
                },
            ),
            context(1_000),
        ),
    )
    .unwrap();

    let perps_market = setup_perps_market(&mut store, clob_market);
    block_on(
        ClearinghouseLedger::new(&mut store).register_perps_market(clob_market, perps_market),
    )
    .unwrap();

    seed_collateral(&mut store, &address(&maker), 100_000);
    seed_collateral(&mut store, &address(&taker), 100_000);

    block_on(
        ClobLedger::new(&mut store).apply_transaction(
            &ClobTransaction::sign(
                &maker,
                1,
                ClobOperation::PlaceOrder {
                    market: clob_market,
                    side: ClobSide::Ask,
                    price: FILL_PRICE,
                    base_quantity: 10,
                    time_in_force: TimeInForce::GoodTilCancelled,
                },
            ),
            context(2_000),
        ),
    )
    .unwrap();
    block_on(
        ClobLedger::new(&mut store).apply_transaction(
            &ClobTransaction::sign(
                &taker,
                0,
                ClobOperation::PlaceOrder {
                    market: clob_market,
                    side: ClobSide::Bid,
                    price: FILL_PRICE,
                    base_quantity: FILL_QTY,
                    time_in_force: TimeInForce::ImmediateOrCancel,
                },
            ),
            context(3_000),
        ),
    )
    .unwrap();

    let fill_id = block_on(ClobLedger::new(&mut store).market_fills(&clob_market))
        .unwrap()
        .pop()
        .unwrap()
        .id;

    block_on(
        ClearinghouseLedger::new(&mut store).settle_fill(fill_id, context(4_000)),
    )
    .unwrap();
    let err = block_on(
        ClearinghouseLedger::new(&mut store).settle_fill(fill_id, context(5_000)),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "fill already settled");
}

#[test]
fn commit_and_settle_fill_applies_memclob_style_fill() {
    let maker = PrivateKey::from_seed(20);
    let taker = PrivateKey::from_seed(21);
    let settler = PrivateKey::from_seed(22);
    let mut store = MemoryStore::default();
    let clob_market = clob_market_id();

    block_on(
        ClobLedger::new(&mut store).apply_transaction(
            &ClobTransaction::sign(
                &maker,
                0,
                ClobOperation::CreateMarket {
                    base_asset: asset(b"base"),
                    quote_asset: asset(b"quote"),
                    tick_size: MARKET_TICK,
                    lot_size: MARKET_LOT,
                },
            ),
            context(1_000),
        ),
    )
    .unwrap();

    let perps_market = setup_perps_market(&mut store, clob_market);
    register_perps_market(&mut store, clob_market, perps_market);
    seed_collateral(&mut store, &address(&maker), 100_000);
    seed_collateral(&mut store, &address(&taker), 100_000);

    block_on(
        ClobLedger::new(&mut store).apply_transaction(
            &ClobTransaction::sign(
                &maker,
                1,
                ClobOperation::PlaceOrder {
                    market: clob_market,
                    side: ClobSide::Ask,
                    price: FILL_PRICE,
                    base_quantity: 10,
                    time_in_force: TimeInForce::GoodTilCancelled,
                },
            ),
            context(2_000),
        ),
    )
    .unwrap();
    block_on(
        ClobLedger::new(&mut store).apply_transaction(
            &ClobTransaction::sign(
                &taker,
                0,
                ClobOperation::PlaceOrder {
                    market: clob_market,
                    side: ClobSide::Bid,
                    price: FILL_PRICE,
                    base_quantity: FILL_QTY,
                    time_in_force: TimeInForce::ImmediateOrCancel,
                },
            ),
            context(3_000),
        ),
    )
    .unwrap();

    let fill = block_on(ClobLedger::new(&mut store).market_fills(&clob_market))
        .unwrap()
        .pop()
        .unwrap();

    block_on(
        ClearinghouseLedger::new(&mut store).apply_transaction(
            &ClearingTx::sign(
                &settler,
                0,
                ClearinghouseOperation::CommitAndSettleFill { fill: fill.clone() },
            ),
            context(4_000),
        ),
    )
    .unwrap();

    let perps = PerpetualLedger::new(&mut store);
    let market = block_on(perps.market(&perps_market)).unwrap().unwrap();
    assert_eq!(market.long_open_interest, FILL_QTY * nunchi_perpetuals::PRICE_SCALE);
    assert_eq!(market.short_open_interest, FILL_QTY * nunchi_perpetuals::PRICE_SCALE);
}
