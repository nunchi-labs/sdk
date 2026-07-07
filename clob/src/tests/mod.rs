use std::{collections::BTreeMap, future::Future};

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_formatting::hex;
use commonware_runtime::{deterministic, Runner as _};
use nunchi_common::{Address, RuntimeContext, StateError, StateStore};
use nunchi_crypto::PrivateKey;

use crate::{
    market_id, AssetId, ClobError, ClobGenesis, ClobLedger, ClobMarketGenesis, ClobOperation,
    OrderId, OrderStatus, Side, TimeInForce, Transaction,
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

fn cancel_tx(signer: &PrivateKey, nonce: u64, order: OrderId) -> Transaction {
    Transaction::sign(signer, nonce, ClobOperation::CancelOrder { order })
}

#[test]
fn transaction_codec_round_trips() {
    let signer = PrivateKey::from_seed(1);
    let tx = create_market_tx(&signer, 0);
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
fn matching_uses_maker_price_and_leaves_partial_resting_order() {
    run_test(|| async {
        let maker = PrivateKey::from_seed(1);
        let taker = PrivateKey::from_seed(2);
        let market = market();
        let mut ledger = ClobLedger::new(MemoryStore::default());

        ledger
            .apply_transaction(&create_market_tx(&maker, 0), context(1))
            .await
            .unwrap();
        let ask = place_tx(
            &maker,
            1,
            Side::Ask,
            100,
            10,
            TimeInForce::GoodTilCancelled,
        );
        let ask_id = OrderId(ask.digest());
        ledger.apply_transaction(&ask, context(2)).await.unwrap();

        let bid = place_tx(
            &taker,
            0,
            Side::Bid,
            110,
            4,
            TimeInForce::ImmediateOrCancel,
        );
        let bid_id = OrderId(bid.digest());
        ledger.apply_transaction(&bid, context(3)).await.unwrap();

        let maker_order = ledger.order(&ask_id).await.unwrap().unwrap();
        assert_eq!(maker_order.status, OrderStatus::PartiallyFilled);
        assert_eq!(maker_order.remaining_base, 6);
        assert_eq!(maker_order.filled_base, 4);

        let taker_order = ledger.order(&bid_id).await.unwrap().unwrap();
        assert_eq!(taker_order.status, OrderStatus::Filled);
        assert_eq!(taker_order.remaining_base, 0);

        let fills = ledger.market_fills(&market).await.unwrap();
        assert_eq!(fills.len(), 1);
        assert_eq!(fills[0].price, 100);
        assert_eq!(fills[0].base_quantity, 4);
        assert_eq!(fills[0].quote_quantity, 400);

        let asks = ledger.book(&market, Side::Ask).await.unwrap();
        assert_eq!(asks.len(), 1);
        assert_eq!(asks[0].id, ask_id);
    });
}

#[test]
fn best_price_wins_before_time_priority() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let first_asker = PrivateKey::from_seed(2);
        let second_asker = PrivateKey::from_seed(3);
        let bidder = PrivateKey::from_seed(4);
        let market = market();
        let mut ledger = ClobLedger::new(MemoryStore::default());

        ledger
            .apply_transaction(&create_market_tx(&creator, 0), context(1))
            .await
            .unwrap();
        let high_ask = place_tx(
            &first_asker,
            0,
            Side::Ask,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        );
        ledger.apply_transaction(&high_ask, context(2)).await.unwrap();
        let low_ask = place_tx(
            &second_asker,
            0,
            Side::Ask,
            90,
            2,
            TimeInForce::GoodTilCancelled,
        );
        let low_ask_id = OrderId(low_ask.digest());
        ledger.apply_transaction(&low_ask, context(3)).await.unwrap();

        ledger
            .apply_transaction(
                &place_tx(
                    &bidder,
                    0,
                    Side::Bid,
                    100,
                    2,
                    TimeInForce::ImmediateOrCancel,
                ),
                context(4),
            )
            .await
            .unwrap();

        let fills = ledger.market_fills(&market).await.unwrap();
        assert_eq!(fills.len(), 1);
        assert_eq!(fills[0].maker_order, low_ask_id);
        assert_eq!(fills[0].price, 90);
    });
}

#[test]
fn owner_can_cancel_open_order() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let bidder = PrivateKey::from_seed(2);
        let market = market();
        let mut ledger = ClobLedger::new(MemoryStore::default());

        ledger
            .apply_transaction(&create_market_tx(&creator, 0), context(1))
            .await
            .unwrap();
        let bid = place_tx(
            &bidder,
            0,
            Side::Bid,
            100,
            4,
            TimeInForce::GoodTilCancelled,
        );
        let bid_id = OrderId(bid.digest());
        ledger.apply_transaction(&bid, context(2)).await.unwrap();
        ledger
            .apply_transaction(&cancel_tx(&bidder, 1, bid_id), context(3))
            .await
            .unwrap();

        let order = ledger.order(&bid_id).await.unwrap().unwrap();
        assert_eq!(order.status, OrderStatus::Cancelled);
        assert!(ledger.book(&market, Side::Bid).await.unwrap().is_empty());
    });
}

#[test]
fn non_owner_cannot_cancel_order() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let bidder = PrivateKey::from_seed(2);
        let attacker = PrivateKey::from_seed(3);
        let mut ledger = ClobLedger::new(MemoryStore::default());

        ledger
            .apply_transaction(&create_market_tx(&creator, 0), context(1))
            .await
            .unwrap();
        let bid = place_tx(
            &bidder,
            0,
            Side::Bid,
            100,
            4,
            TimeInForce::GoodTilCancelled,
        );
        let bid_id = OrderId(bid.digest());
        ledger.apply_transaction(&bid, context(2)).await.unwrap();

        let err = ledger
            .apply_transaction(&cancel_tx(&attacker, 0, bid_id), context(3))
            .await
            .unwrap_err();
        assert_eq!(err, ClobError::UnauthorizedCancel);
    });
}

#[test]
fn market_id_is_independent_of_asset_order_and_includes_market_params() {
    let base = asset(b"base");
    let quote = asset(b"quote");
    assert_eq!(
        market_id(&base, &quote, 5, 2),
        market_id(&quote, &base, 5, 2)
    );
    assert_ne!(market_id(&base, &quote, 5, 2), market_id(&base, &quote, 10, 2));
}

#[test]
fn reverse_asset_pair_cannot_create_duplicate_market() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let mut ledger = ClobLedger::new(MemoryStore::default());

        ledger
            .apply_transaction(&create_market_tx(&creator, 0), context(1))
            .await
            .unwrap();

        let reverse_market = Transaction::sign(
            &creator,
            1,
            ClobOperation::CreateMarket {
                base_asset: asset(b"quote"),
                quote_asset: asset(b"base"),
                tick_size: MARKET_TICK,
                lot_size: MARKET_LOT,
            },
        );
        let err = ledger
            .apply_transaction(&reverse_market, context(2))
            .await
            .unwrap_err();
        assert_eq!(err, ClobError::MarketAlreadyExists);
    });
}

#[test]
fn terminal_orders_are_pruned_from_account_index() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let trader = PrivateKey::from_seed(2);
        let mut ledger = ClobLedger::new(MemoryStore::default());

        ledger
            .apply_transaction(&create_market_tx(&creator, 0), context(1))
            .await
            .unwrap();

        let ask = place_tx(
            &trader,
            0,
            Side::Ask,
            100,
            4,
            TimeInForce::GoodTilCancelled,
        );
        let ask_id = OrderId(ask.digest());
        ledger.apply_transaction(&ask, context(2)).await.unwrap();

        let trader_addr = Address::external(&trader.public_key());
        assert_eq!(ledger.account_orders(&trader_addr).await.unwrap().len(), 1);

        ledger
            .apply_transaction(&cancel_tx(&trader, 1, ask_id), context(3))
            .await
            .unwrap();
        assert!(ledger.account_orders(&trader_addr).await.unwrap().is_empty());

        let bid = place_tx(
            &trader,
            2,
            Side::Bid,
            100,
            4,
            TimeInForce::ImmediateOrCancel,
        );
        let bid_id = OrderId(bid.digest());
        ledger.apply_transaction(&bid, context(4)).await.unwrap();
        assert!(ledger.account_orders(&trader_addr).await.unwrap().is_empty());
        assert_eq!(
            ledger.order(&bid_id).await.unwrap().unwrap().status,
            OrderStatus::Expired
        );
    });
}
