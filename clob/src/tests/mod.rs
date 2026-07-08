use std::{collections::BTreeMap, future::Future};

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_formatting::hex;
use commonware_runtime::{deterministic, Runner as _};
use nunchi_common::{Address, RuntimeContext, StateError, StateStore};
use nunchi_crypto::PrivateKey;

use crate::{
    market_id, AssetId, ClobDB, ClobError, ClobGenesis, ClobLedger, ClobMarketGenesis, ClobOperation,
    MatchBatch, MatchEngine, OrderId, Side, TimeInForce, Transaction,
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

fn run_test<F, Fut>(test: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    deterministic::Runner::default().start(|_| test());
}

fn context(height: u64) -> RuntimeContext {
    RuntimeContext {
        epoch: 0,
        height,
        timestamp_ms: height * 1_000,
        block_digest: None,
    }
}

fn asset(seed: &'static [u8]) -> AssetId {
    AssetId(Sha256::hash(seed))
}

const MARKET_TICK: u128 = 5;
const MARKET_LOT: u128 = 2;

fn market() -> crate::MarketId {
    market_id(&asset(b"base"), &asset(b"quote"), MARKET_TICK, MARKET_LOT)
}

fn create_market_tx(signer: &PrivateKey, nonce: u64) -> Transaction {
    Transaction::sign(
        signer,
        nonce,
        ClobOperation::CreateMarket {
            base_asset: asset(b"base"),
            quote_asset: asset(b"quote"),
            tick_size: MARKET_TICK,
            lot_size: MARKET_LOT,
        },
    )
}

fn place_tx(
    signer: &PrivateKey,
    nonce: u64,
    side: Side,
    price: u128,
    base_quantity: u128,
    time_in_force: TimeInForce,
) -> Transaction {
    Transaction::sign(
        signer,
        nonce,
        ClobOperation::PlaceOrder {
            market: market(),
            side,
            price,
            base_quantity,
            time_in_force,
        },
    )
}

async fn seed_market(ledger: &mut ClobLedger<MemoryStore>, signer: &PrivateKey) {
    ledger
        .apply_transaction(&create_market_tx(signer, 0), context(1))
        .await
        .unwrap();
}

async fn batch_from_orders(
    ledger: &ClobLedger<MemoryStore>,
    orders: Vec<Transaction>,
    context: RuntimeContext,
) -> MatchBatch {
    let market_info = ledger.market(&market()).await.unwrap().unwrap();
    let mut markets = BTreeMap::new();
    markets.insert(market_info.id, market_info);
    let mut sequences = BTreeMap::new();
    sequences.insert(market(), ledger.db.market_sequence(&market()).await.unwrap());
    let replay = MatchEngine::replay(&orders, &markets, sequences, context).unwrap();
    MatchBatch {
        orders,
        fills: replay.fills,
    }
}

#[test]
fn transaction_codec_round_trips() {
    let signer = PrivateKey::from_seed(1);
    let tx = Transaction::sign(
        &signer,
        0,
        ClobOperation::ApplyMatchBatch {
            batch: MatchBatch::default(),
        },
    );
    let encoded = tx.encode();

    assert_eq!(Transaction::decode(encoded).unwrap(), tx);
}

#[test]
fn genesis_seeds_markets() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let mut ledger = ClobLedger::new(MemoryStore::default());

        ledger
            .apply_genesis(&ClobGenesis {
                markets: vec![ClobMarketGenesis {
                    base_asset: hex(asset(b"base").encode().as_ref()),
                    quote_asset: hex(asset(b"quote").encode().as_ref()),
                    tick_size: 5,
                    lot_size: 2,
                    created_by: Address::external(&creator.public_key()).to_bech32(),
                }],
            })
            .await
            .unwrap();

        let markets = ledger.markets().await.unwrap();
        assert_eq!(markets.len(), 1);
        assert_eq!(markets[0].id, market());
        assert_eq!(markets[0].tick_size, 5);
        assert_eq!(markets[0].lot_size, 2);
    });
}

#[test]
fn place_order_is_offchain_only_for_ledger_transactions() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let trader = PrivateKey::from_seed(2);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;

        let err = ledger
            .apply_transaction(
                &place_tx(
                    &trader,
                    0,
                    Side::Bid,
                    100,
                    4,
                    TimeInForce::GoodTilCancelled,
                ),
                context(2),
            )
            .await
            .unwrap_err();
        assert_eq!(err, ClobError::OffchainOnly);
        assert!(ledger.book(&market(), Side::Bid).await.unwrap().is_empty());
    });
}

#[test]
fn apply_match_batch_records_replayed_fills_without_resting_onchain_orders() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;

        let ask = place_tx(
            &maker,
            0,
            Side::Ask,
            100,
            10,
            TimeInForce::GoodTilCancelled,
        );
        let bid = place_tx(
            &taker,
            0,
            Side::Bid,
            110,
            4,
            TimeInForce::ImmediateOrCancel,
        );
        let batch = batch_from_orders(&ledger, vec![ask.clone(), bid.clone()], context(2)).await;
        ledger.apply_match_batch(&batch, context(2)).await.unwrap();

        let fills = ledger.market_fills(&market()).await.unwrap();
        assert_eq!(fills.len(), 1);
        assert_eq!(fills[0].maker_order, OrderId(ask.digest()));
        assert_eq!(fills[0].taker_order, OrderId(bid.digest()));
        assert_eq!(fills[0].price, 100);
        assert_eq!(fills[0].base_quantity, 4);
        assert_eq!(fills[0].quote_quantity, 400);
        assert!(ledger.book(&market(), Side::Ask).await.unwrap().is_empty());
    });
}

#[test]
fn best_price_wins_during_validator_replay() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let high_asker = PrivateKey::from_seed(2);
        let low_asker = PrivateKey::from_seed(3);
        let bidder = PrivateKey::from_seed(4);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;

        let high_ask = place_tx(
            &high_asker,
            0,
            Side::Ask,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        );
        let low_ask = place_tx(
            &low_asker,
            0,
            Side::Ask,
            90,
            2,
            TimeInForce::GoodTilCancelled,
        );
        let bid = place_tx(
            &bidder,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        let low_ask_id = OrderId(low_ask.digest());
        let batch = batch_from_orders(&ledger, vec![high_ask, low_ask, bid], context(2)).await;

        ledger.apply_match_batch(&batch, context(2)).await.unwrap();

        let fills = ledger.market_fills(&market()).await.unwrap();
        assert_eq!(fills.len(), 1);
        assert_eq!(fills[0].maker_order, low_ask_id);
        assert_eq!(fills[0].price, 90);
    });
}

#[test]
fn tampered_match_batch_is_rejected() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;

        let ask = place_tx(
            &maker,
            0,
            Side::Ask,
            100,
            4,
            TimeInForce::GoodTilCancelled,
        );
        let bid = place_tx(
            &taker,
            0,
            Side::Bid,
            100,
            4,
            TimeInForce::ImmediateOrCancel,
        );
        let mut batch = batch_from_orders(&ledger, vec![ask, bid], context(2)).await;
        batch.fills[0].price = 95;

        let err = ledger.apply_match_batch(&batch, context(2)).await.unwrap_err();
        assert_eq!(err, ClobError::MatchBatchMismatch);
    });
}

#[test]
fn duplicate_fill_commit_is_rejected() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;

        let ask = place_tx(
            &maker,
            0,
            Side::Ask,
            100,
            4,
            TimeInForce::GoodTilCancelled,
        );
        let bid = place_tx(
            &taker,
            0,
            Side::Bid,
            100,
            4,
            TimeInForce::ImmediateOrCancel,
        );
        let batch = batch_from_orders(&ledger, vec![ask, bid], context(2)).await;
        ledger.apply_match_batch(&batch, context(2)).await.unwrap();

        let err = ledger.apply_match_batch(&batch, context(3)).await.unwrap_err();
        assert_eq!(err, ClobError::NonceMismatch {
            account: Box::new(Address::external(&maker.public_key())),
            expected: 1,
            actual: 0,
        });
    });
}
