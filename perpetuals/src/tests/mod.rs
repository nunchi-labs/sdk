mod genesis;
mod rpc;
mod transaction;

use std::collections::BTreeMap;

use commonware_codec::Encode;
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use futures::executor::block_on;
use nunchi_coins::{CoinDB, CoinSpec, TokenDefinition, TokenName, TokenSymbol};
use nunchi_common::{Address, RuntimeContext, StateError, StateStore};
use nunchi_crypto::PrivateKey;
use nunchi_oracle::{
    IntervalKey, NamespaceId, OracleLedger, OracleOperation, Transaction as OracleTransaction,
};

use crate::{
    collateral_escrow_account, insurance_fund_account, CoinId, OraclePricePayload, PerpetualDB,
    PerpetualError, PerpetualLedger, PositionId, Side, BPS_DENOMINATOR,
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

fn namespace() -> NamespaceId {
    NamespaceId(digest(b"perps-price-feed"))
}

fn context(timestamp_ms: u64) -> RuntimeContext {
    RuntimeContext {
        epoch: 0,
        height: timestamp_ms / 100,
        timestamp_ms,
        block_digest: None,
    }
}

fn address(signer: &PrivateKey) -> Address {
    Address::external(&signer.public_key())
}

fn append_price(
    ledger: &mut PerpetualLedger<MemoryStore>,
    writer: &PrivateKey,
    nonce: u64,
    market: Digest,
    price: u128,
    price_decimals: u8,
    timestamp_ms: u64,
) {
    let payload = OraclePricePayload {
        market,
        price,
        price_decimals,
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
    let mut oracle = OracleLedger::new(ledger.db_mut());
    block_on(oracle.apply_transaction(&append, context(timestamp_ms))).unwrap();
}

fn oracle_writer() -> PrivateKey {
    PrivateKey::from_seed(2)
}

fn create_market(ledger: &mut PerpetualLedger<MemoryStore>) -> Digest {
    block_on(ledger.create_market(
        coin(b"btc"),
        coin(b"usd"),
        coin(b"usdc"),
        namespace(),
        address(&oracle_writer()),
        None,
        1_000,
        10_000,
        2,
        10 * BPS_DENOMINATOR,
        500,
        3_600_000,
        100,
        DEFAULT_LIQUIDATION_REWARD_BPS,
    ))
    .unwrap()
}

fn seed_collateral(ledger: &mut PerpetualLedger<MemoryStore>, owner: &Address, amount: u128) {
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
    ledger.db_mut().set_token(&token);
    ledger.db_mut().set_balance(owner, &coin(b"usdc"), amount);
}

fn balance(ledger: &PerpetualLedger<MemoryStore>, account: &Address) -> u128 {
    block_on(CoinDB::balance(ledger.db(), account, &coin(b"usdc"))).unwrap()
}

fn escrow_balance(ledger: &PerpetualLedger<MemoryStore>) -> u128 {
    balance(ledger, &collateral_escrow_account())
}

fn set_insurance_balance(ledger: &mut PerpetualLedger<MemoryStore>, amount: u128) {
    ledger
        .db_mut()
        .set_balance(&insurance_fund_account(), &coin(b"usdc"), amount);
}

fn skew_market_prices(
    ledger: &mut PerpetualLedger<MemoryStore>,
    market: Digest,
    mark_price: u128,
    index_price: u128,
) {
    let mut market_state = block_on(ledger.market(&market)).unwrap().unwrap();
    market_state.mark_price = mark_price;
    market_state.index_price = index_price;
    market_state.max_oracle_staleness_ms = 10_000_000;
    ledger.db_mut().set_market(&market_state);
}

fn open_long(
    ledger: &mut PerpetualLedger<MemoryStore>,
    owner: &PrivateKey,
    market: Digest,
    timestamp_ms: u64,
) -> PositionId {
    block_on(ledger.open_position(
        address(owner),
        market,
        Side::Long,
        1_000,
        5 * BPS_DENOMINATOR,
        context(timestamp_ms),
    ))
    .unwrap()
}

fn open_short(
    ledger: &mut PerpetualLedger<MemoryStore>,
    owner: &PrivateKey,
    market: Digest,
    timestamp_ms: u64,
) -> PositionId {
    block_on(ledger.open_position(
        address(owner),
        market,
        Side::Short,
        1_000,
        5 * BPS_DENOMINATOR,
        context(timestamp_ms),
    ))
    .unwrap()
}

#[test]
fn refresh_market_from_oracle_decodes_mock_price_payload() {
    let writer = oracle_writer();
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    let market = create_market(&mut ledger);

    append_price(&mut ledger, &writer, 0, market, 500_000_000, 4, 1_000);
    block_on(ledger.refresh_market_from_oracle(market, context(1_500))).unwrap();

    let market = block_on(ledger.market(&market)).unwrap().unwrap();
    assert_eq!(market.mark_price, 5_000_000);
    assert_eq!(market.index_price, 5_000_000);
    assert_eq!(market.last_oracle_interval, 1);
}

#[test]
fn refresh_market_skips_malformed_and_untrusted_oracle_records() {
    let writer = oracle_writer();
    let untrusted = PrivateKey::from_seed(99);
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    let market = create_market(&mut ledger);

    append_price(&mut ledger, &untrusted, 0, market, 900_000_000, 4, 1_000);
    let append = OracleTransaction::sign(
        &writer,
        0,
        OracleOperation::AppendRecord {
            namespace: namespace(),
            interval: IntervalKey::new(1),
            payload: b"not-a-price-payload".to_vec(),
            proof: None,
        },
    );
    let mut oracle = OracleLedger::new(ledger.db_mut());
    block_on(oracle.apply_transaction(&append, context(1_000))).unwrap();
    append_price(&mut ledger, &writer, 1, market, 500_000_000, 4, 1_500);

    block_on(ledger.refresh_market_from_oracle(market, context(2_000))).unwrap();
    let market = block_on(ledger.market(&market)).unwrap().unwrap();
    assert_eq!(market.index_price, 5_000_000);
}

#[test]
fn long_position_blocks_unsafe_withdrawal_then_liquidates_after_price_drop() {
    let writer = oracle_writer();
    let trader = PrivateKey::from_seed(12);
    let trader_address = address(&trader);
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    let market = create_market(&mut ledger);
    seed_collateral(&mut ledger, &trader_address, 10_000);

    append_price(&mut ledger, &writer, 0, market, 500_000_000, 4, 1_000);
    block_on(ledger.refresh_market_from_oracle(market, context(1_500))).unwrap();
    let position = open_long(&mut ledger, &trader, market, 1_600);
    assert_eq!(balance(&ledger, &trader_address), 9_000);
    assert_eq!(escrow_balance(&ledger), 1_000);

    append_price(&mut ledger, &writer, 1, market, 430_000_000, 4, 2_000);
    block_on(ledger.refresh_market_from_oracle(market, context(2_500))).unwrap();
    let reduction =
        block_on(ledger.reduce_collateral(&address(&trader), position, 100, context(2_600)));
    assert_eq!(
        reduction.unwrap_err(),
        PerpetualError::CollateralReductionWouldCauseLiquidation
    );
    assert_eq!(balance(&ledger, &trader_address), 9_000);
    assert_eq!(escrow_balance(&ledger), 1_000);

    append_price(&mut ledger, &writer, 2, market, 400_000_000, 4, 3_000);
    block_on(ledger.refresh_market_from_oracle(market, context(3_500))).unwrap();
    let liquidator = address(&PrivateKey::from_seed(13));
    let reward = block_on(ledger.liquidate(&liquidator, position, context(3_600))).unwrap();
    assert_eq!(reward, 50);
    assert!(block_on(ledger.position(&position)).unwrap().is_none());
    assert_eq!(balance(&ledger, &trader_address), 9_000);
    assert_eq!(balance(&ledger, &liquidator), reward);
    assert_eq!(escrow_balance(&ledger), 0);
    assert_eq!(balance(&ledger, &insurance_fund_account()), 950);
}

#[cfg(feature = "mock-execution")]
#[test]
fn collateral_moves_through_escrow_on_open_adjust_and_close() {
    let writer = oracle_writer();
    let trader = PrivateKey::from_seed(32);
    let trader_address = address(&trader);
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    let market = create_market(&mut ledger);
    seed_collateral(&mut ledger, &trader_address, 5_000);

    append_price(&mut ledger, &writer, 0, market, 500_000_000, 4, 1_000);
    block_on(ledger.refresh_market_from_oracle(market, context(1_500))).unwrap();
    let position = open_long(&mut ledger, &trader, market, 1_600);
    assert_eq!(balance(&ledger, &trader_address), 4_000);
    assert_eq!(escrow_balance(&ledger), 1_000);

    block_on(ledger.add_collateral(&trader_address, position, 500)).unwrap();
    assert_eq!(balance(&ledger, &trader_address), 3_500);
    assert_eq!(escrow_balance(&ledger), 1_500);

    block_on(ledger.reduce_collateral(&trader_address, position, 250, context(1_700))).unwrap();
    assert_eq!(balance(&ledger, &trader_address), 3_750);
    assert_eq!(escrow_balance(&ledger), 1_250);

    let payout =
        block_on(ledger.close_position(&trader_address, position, context(1_800))).unwrap();
    assert_eq!(payout, 1_250);
    assert_eq!(balance(&ledger, &trader_address), 5_000);
    assert_eq!(escrow_balance(&ledger), 0);
    assert!(block_on(ledger.position(&position)).unwrap().is_none());
}

#[test]
fn funding_accrual_is_capped_and_interval_based() {
    let writer = oracle_writer();
    let long_trader = PrivateKey::from_seed(42);
    let short_trader = PrivateKey::from_seed(43);
    let long_address = address(&long_trader);
    let short_address = address(&short_trader);
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    let market = create_market(&mut ledger);
    seed_collateral(&mut ledger, &long_address, 5_000);
    seed_collateral(&mut ledger, &short_address, 5_000);

    append_price(&mut ledger, &writer, 0, market, 500_000_000, 4, 1_000);
    block_on(ledger.refresh_market_from_oracle(market, context(1_500))).unwrap();
    open_long(&mut ledger, &long_trader, market, 1_600);
    open_short(&mut ledger, &short_trader, market, 1_600);
    skew_market_prices(&mut ledger, market, 5_000_000, 4_000_000);

    block_on(ledger.settle_funding(market, context(7_201_500))).unwrap();
    let market_state = block_on(ledger.market(&market)).unwrap().unwrap();

    assert_eq!(market_state.cumulative_funding_long, 100_000);
    assert_eq!(market_state.cumulative_funding_short, -100_000);
    assert_eq!(market_state.last_funding_ms, 7_201_500);
}

#[cfg(feature = "mock-execution")]
#[test]
fn funding_reduces_long_close_payout_when_mark_exceeds_index() {
    let writer = oracle_writer();
    let long_trader = PrivateKey::from_seed(52);
    let short_trader = PrivateKey::from_seed(53);
    let long_address = address(&long_trader);
    let short_address = address(&short_trader);
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    let market = create_market(&mut ledger);
    seed_collateral(&mut ledger, &long_address, 10_000);
    seed_collateral(&mut ledger, &short_address, 10_000);

    append_price(&mut ledger, &writer, 0, market, 500_000_000, 4, 1_000);
    block_on(ledger.refresh_market_from_oracle(market, context(1_500))).unwrap();
    let position = open_long(&mut ledger, &long_trader, market, 1_600);
    open_short(&mut ledger, &short_trader, market, 1_600);
    skew_market_prices(&mut ledger, market, 5_000_000, 4_000_000);

    let payout =
        block_on(ledger.close_position(&long_address, position, context(3_601_500))).unwrap();

    assert_eq!(payout, 950);
    assert_eq!(balance(&ledger, &long_address), 9_950);
    assert_eq!(balance(&ledger, &short_address), 9_000);
    assert_eq!(escrow_balance(&ledger), 1_050);
}

#[cfg(feature = "mock-execution")]
#[test]
fn funding_increases_short_close_payout_when_mark_exceeds_index() {
    let writer = oracle_writer();
    let long_trader = PrivateKey::from_seed(61);
    let short_trader = PrivateKey::from_seed(62);
    let long_address = address(&long_trader);
    let short_address = address(&short_trader);
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    let market = create_market(&mut ledger);
    seed_collateral(&mut ledger, &long_address, 10_000);
    seed_collateral(&mut ledger, &short_address, 10_000);

    append_price(&mut ledger, &writer, 0, market, 500_000_000, 4, 1_000);
    block_on(ledger.refresh_market_from_oracle(market, context(1_500))).unwrap();
    open_long(&mut ledger, &long_trader, market, 1_600);
    let position = open_short(&mut ledger, &short_trader, market, 1_600);
    skew_market_prices(&mut ledger, market, 5_000_000, 4_000_000);

    let payout =
        block_on(ledger.close_position(&short_address, position, context(3_601_500))).unwrap();

    assert_eq!(payout, 1_050);
    assert_eq!(balance(&ledger, &short_address), 10_050);
    assert_eq!(balance(&ledger, &long_address), 9_000);
    assert_eq!(escrow_balance(&ledger), 950);
}

#[test]
fn update_mark_price_keeps_index_from_oracle() {
    let writer = oracle_writer();
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    let market = create_market(&mut ledger);

    append_price(&mut ledger, &writer, 0, market, 500_000_000, 4, 1_000);
    block_on(ledger.refresh_market_from_oracle(market, context(1_500))).unwrap();
    block_on(ledger.update_mark_price(market, 4_500_000, context(1_600))).unwrap();

    let market = block_on(ledger.market(&market)).unwrap().unwrap();
    assert_eq!(market.index_price, 5_000_000);
    assert_eq!(market.mark_price, 4_500_000);
}

#[cfg(feature = "mock-execution")]
#[test]
fn profitable_close_draws_from_insurance_when_escrow_is_insufficient() {
    let writer = oracle_writer();
    let winner = PrivateKey::from_seed(71);
    let loser = PrivateKey::from_seed(72);
    let winner_address = address(&winner);
    let loser_address = address(&loser);
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    let market = create_market(&mut ledger);
    seed_collateral(&mut ledger, &winner_address, 10_000);
    seed_collateral(&mut ledger, &loser_address, 10_000);
    set_insurance_balance(&mut ledger, 500);

    append_price(&mut ledger, &writer, 0, market, 500_000_000, 4, 1_000);
    block_on(ledger.refresh_market_from_oracle(market, context(1_500))).unwrap();
    open_short(&mut ledger, &loser, market, 1_600);
    let winner_position = open_long(&mut ledger, &winner, market, 1_600);
    skew_market_prices(&mut ledger, market, 6_000_000, 5_000_000);

    let payout =
        block_on(ledger.close_position(&winner_address, winner_position, context(1_700))).unwrap();
    assert!(payout > 1_000);
    assert_eq!(balance(&ledger, &winner_address), 10_000 - 1_000 + payout);
}

#[test]
fn stale_oracle_price_blocks_trading() {
    let writer = oracle_writer();
    let trader = PrivateKey::from_seed(22);
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    let market = create_market(&mut ledger);

    append_price(&mut ledger, &writer, 0, market, 500_000_000, 4, 1_000);
    block_on(ledger.refresh_market_from_oracle(market, context(1_500))).unwrap();
    let err = block_on(ledger.open_position(
        address(&trader),
        market,
        Side::Long,
        1_000,
        5 * BPS_DENOMINATOR,
        context(20_000),
    ))
    .unwrap_err();
    assert_eq!(err, PerpetualError::StaleOraclePrice);
}
