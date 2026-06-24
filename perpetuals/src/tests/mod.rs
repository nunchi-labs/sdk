use std::collections::BTreeMap;

use commonware_codec::Encode;
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use futures::executor::block_on;
use nunchi_coins::{CoinDB, CoinSpec, TokenDefinition, TokenName, TokenSymbol};
use nunchi_common::{Address, RuntimeContext, StateError, StateStore};
use nunchi_crypto::PrivateKey;
use nunchi_oracle::{
    IntervalKey, NamespaceId, NamespacePolicy, OracleLedger, OracleOperation,
    Transaction as OracleTransaction,
};

use crate::{
    collateral_escrow_account, CoinId, OraclePricePayload, PerpetualError, PerpetualLedger,
    PositionId, Side, BPS_DENOMINATOR,
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
    }
}

fn address(signer: &PrivateKey) -> Address {
    Address::external(&signer.public_key())
}

fn configure_oracle(
    ledger: &mut PerpetualLedger<MemoryStore>,
    admin: &PrivateKey,
    writer: &PrivateKey,
) {
    let mut oracle = OracleLedger::new(ledger.db_mut());
    let configure = OracleTransaction::sign(
        admin,
        0,
        OracleOperation::ConfigureNamespace {
            namespace: namespace(),
            policy: NamespacePolicy {
                admin: address(admin),
                max_payload_size: 1024,
            },
        },
    );
    block_on(oracle.apply_transaction(&configure, context(100))).unwrap();
    let set_writer = OracleTransaction::sign(
        admin,
        1,
        OracleOperation::SetWriter {
            namespace: namespace(),
            writer: address(writer),
            enabled: true,
        },
    );
    block_on(oracle.apply_transaction(&set_writer, context(100))).unwrap();
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

fn create_market(ledger: &mut PerpetualLedger<MemoryStore>) -> Digest {
    block_on(ledger.create_market(
        coin(b"btc"),
        coin(b"usd"),
        coin(b"usdc"),
        namespace(),
        1_000,
        10_000,
        2,
        10 * BPS_DENOMINATOR,
        500,
        3_600_000,
        100,
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

#[test]
fn refresh_market_from_oracle_decodes_mock_price_payload() {
    let admin = PrivateKey::from_seed(1);
    let writer = PrivateKey::from_seed(2);
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    configure_oracle(&mut ledger, &admin, &writer);
    let market = create_market(&mut ledger);

    append_price(&mut ledger, &writer, 0, market, 500_000_000, 4, 1_000);
    block_on(ledger.refresh_market_from_oracle(market, context(1_500))).unwrap();

    let market = block_on(ledger.market(&market)).unwrap().unwrap();
    assert_eq!(market.mark_price, 5_000_000);
    assert_eq!(market.index_price, 5_000_000);
    assert_eq!(market.last_oracle_interval, 1);
}

#[test]
fn long_position_blocks_unsafe_withdrawal_then_liquidates_after_price_drop() {
    let admin = PrivateKey::from_seed(10);
    let writer = PrivateKey::from_seed(11);
    let trader = PrivateKey::from_seed(12);
    let trader_address = address(&trader);
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    configure_oracle(&mut ledger, &admin, &writer);
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
    block_on(ledger.liquidate(position, context(3_600))).unwrap();
    assert!(block_on(ledger.position(&position)).unwrap().is_none());
    assert_eq!(balance(&ledger, &trader_address), 9_000);
    assert_eq!(escrow_balance(&ledger), 1_000);
}

#[test]
fn collateral_moves_through_escrow_on_open_adjust_and_close() {
    let admin = PrivateKey::from_seed(30);
    let writer = PrivateKey::from_seed(31);
    let trader = PrivateKey::from_seed(32);
    let trader_address = address(&trader);
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    configure_oracle(&mut ledger, &admin, &writer);
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
fn stale_oracle_price_blocks_trading() {
    let admin = PrivateKey::from_seed(20);
    let writer = PrivateKey::from_seed(21);
    let trader = PrivateKey::from_seed(22);
    let mut ledger = PerpetualLedger::new(MemoryStore::default());
    configure_oracle(&mut ledger, &admin, &writer);
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
