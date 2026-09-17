use std::{collections::BTreeMap, future::Future, time::Duration};

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{ed25519, sha256::Digest, Hasher, Sha256, Signer as _};
use commonware_formatting::hex;
use commonware_p2p::simulated::{self, Link, Network};
use commonware_runtime::{deterministic, Clock, Runner as _, Supervisor};
use commonware_utils::{NZUsize, NZU32};
use governor::Quota;
use nunchi_common::{Address, CommitState, RuntimeContext, StateError, StateStore};
use nunchi_crypto::PrivateKey;

use crate::{
    market_id, AssetId, ClobActor, ClobConfig, ClobDB, ClobError, ClobGenesis, ClobLedger,
    ClobMailbox, ClobMarketGenesis, ClobOperation, FillId, Market, MatchBatch, MatchEngine,
    OrderId, Side, TimeInForce, Transaction, MAX_FILLS_PER_MARKET,
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

impl CommitState for MemoryStore {
    async fn commit(&mut self) -> Result<Digest, StateError> {
        Ok(self.root())
    }

    fn root(&self) -> Digest {
        Sha256::hash(b"clob-test-root")
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

fn fake_fill_id(seed: u64) -> FillId {
    FillId(Sha256::hash(seed.encode().as_ref()))
}

fn encoded_id<T: Encode>(id: &T) -> String {
    hex(id.encode().as_ref())
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

async fn sync_actor_from_ledger(
    mailbox: &ClobMailbox,
    ledger: &ClobLedger<MemoryStore>,
    market: Market,
    accepted_orders: Vec<OrderId>,
) {
    let mut order_updates = Vec::new();
    for order_id in &accepted_orders {
        order_updates.push((*order_id, ledger.order(order_id).await.unwrap()));
    }
    let sequence = ledger.market_sequence(&market.id).await.unwrap();
    mailbox
        .sync_accepted(market, sequence, accepted_orders, order_updates, Vec::new())
        .await
        .unwrap();
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
fn apply_match_batch_is_offchain_only_for_ledger_transactions() {
    run_test(|| async {
        let signer = PrivateKey::from_seed(1);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        let tx = Transaction::sign(
            &signer,
            0,
            ClobOperation::ApplyMatchBatch {
                batch: MatchBatch::default(),
            },
        );

        let err = ledger.apply_transaction(&tx, context(1)).await.unwrap_err();

        assert_eq!(err, ClobError::OffchainOnly);
        assert_eq!(
            ledger
                .nonce(&Address::external(&signer.public_key()))
                .await
                .unwrap(),
            0
        );
    });
}

#[test]
fn apply_match_batch_records_replayed_fills_and_residual_orders() {
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
        let resting_asks = ledger.book(&market(), Side::Ask).await.unwrap();
        assert_eq!(resting_asks.len(), 1);
        assert_eq!(resting_asks[0].id, OrderId(ask.digest()));
        assert_eq!(resting_asks[0].remaining_base, 6);

        let maker_orders = ledger
            .account_orders(&Address::external(&maker.public_key()))
            .await
            .unwrap();
        assert_eq!(maker_orders.len(), 1);
        assert_eq!(maker_orders[0].id, OrderId(ask.digest()));
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
fn matcher_returns_no_fills_for_non_crossing_orders() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;

        let batch = batch_from_orders(
            &ledger,
            vec![
                place_tx(
                    &maker,
                    0,
                    Side::Ask,
                    100,
                    2,
                    TimeInForce::GoodTilCancelled,
                ),
                place_tx(
                    &taker,
                    0,
                    Side::Bid,
                    90,
                    2,
                    TimeInForce::ImmediateOrCancel,
                ),
            ],
            context(2),
        )
        .await;

        assert!(batch.fills.is_empty());
    });
}

#[test]
fn matcher_rejects_invalid_price_and_sequence_overflow() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let trader = PrivateKey::from_seed(2);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;
        let market_info = ledger.market(&market()).await.unwrap().unwrap();
        let mut markets = BTreeMap::new();
        markets.insert(market_info.id, market_info);

        let err = MatchEngine::replay(
            &[place_tx(
                &trader,
                0,
                Side::Bid,
                101,
                2,
                TimeInForce::ImmediateOrCancel,
            )],
            &markets,
            BTreeMap::new(),
            context(2),
        )
        .unwrap_err();
        assert_eq!(err, ClobError::InvalidOrder("price is not on the market tick"));

        let mut sequences = BTreeMap::new();
        sequences.insert(market(), u64::MAX);
        let err = MatchEngine::replay(
            &[place_tx(
                &trader,
                0,
                Side::Bid,
                100,
                2,
                TimeInForce::ImmediateOrCancel,
            )],
            &markets,
            sequences,
            context(2),
        )
        .unwrap_err();
        assert_eq!(err, ClobError::SequenceOverflow);
    });
}

#[test]
fn matcher_rejects_orders_whose_quote_would_overflow() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;
        let market_info = ledger.market(&market()).await.unwrap().unwrap();
        let mut markets = BTreeMap::new();
        markets.insert(market_info.id, market_info);

        let overflow_price = u128::MAX - (u128::MAX % MARKET_TICK);
        assert!(overflow_price.is_multiple_of(MARKET_TICK));
        assert!(overflow_price.checked_mul(MARKET_LOT).is_none());

        let resting_bid = place_tx(
            &maker,
            0,
            Side::Bid,
            overflow_price,
            MARKET_LOT,
            TimeInForce::GoodTilCancelled,
        );
        let crossing_ask = place_tx(
            &taker,
            0,
            Side::Ask,
            overflow_price,
            MARKET_LOT,
            TimeInForce::ImmediateOrCancel,
        );

        let overflow = ClobError::InvalidOrder("price times quantity overflows u128");
        assert_eq!(
            MatchEngine::replay(
                std::slice::from_ref(&resting_bid),
                &markets,
                BTreeMap::new(),
                context(2),
            )
            .unwrap_err(),
            overflow
        );
        assert_eq!(
            MatchEngine::replay(
                &[resting_bid, crossing_ask],
                &markets,
                BTreeMap::new(),
                context(2),
            )
            .unwrap_err(),
            overflow
        );
    });
}

#[test]
fn partially_filled_taker_rests_for_later_match() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let first_asker = PrivateKey::from_seed(2);
        let bidder = PrivateKey::from_seed(3);
        let second_asker = PrivateKey::from_seed(4);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;

        let batch = batch_from_orders(
            &ledger,
            vec![
                place_tx(
                    &first_asker,
                    0,
                    Side::Ask,
                    100,
                    2,
                    TimeInForce::GoodTilCancelled,
                ),
                place_tx(
                    &bidder,
                    0,
                    Side::Bid,
                    100,
                    4,
                    TimeInForce::GoodTilCancelled,
                ),
                place_tx(
                    &second_asker,
                    0,
                    Side::Ask,
                    100,
                    2,
                    TimeInForce::ImmediateOrCancel,
                ),
            ],
            context(2),
        )
        .await;

        assert_eq!(batch.fills.len(), 2);
        assert_eq!(batch.fills[0].base_quantity, 2);
        assert_eq!(batch.fills[1].base_quantity, 2);
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
fn empty_match_batch_is_noop() {
    run_test(|| async {
        let mut ledger = ClobLedger::new(MemoryStore::default());

        ledger
            .apply_match_batch(&MatchBatch::default(), context(1))
            .await
            .unwrap();

        assert!(ledger.markets().await.unwrap().is_empty());
    });
}

#[test]
fn match_batch_rejects_non_place_order_inputs() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;

        let batch = MatchBatch {
            orders: vec![create_market_tx(&creator, 1)],
            fills: Vec::new(),
        };

        let err = ledger.apply_match_batch(&batch, context(2)).await.unwrap_err();
        assert_eq!(
            err,
            ClobError::InvalidOrder("match batches may only carry signed place-order intents")
        );
    });
}

#[test]
fn match_batch_rejects_unknown_market() {
    run_test(|| async {
        let trader = PrivateKey::from_seed(1);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        let batch = MatchBatch {
            orders: vec![place_tx(
                &trader,
                0,
                Side::Bid,
                100,
                2,
                TimeInForce::ImmediateOrCancel,
            )],
            fills: Vec::new(),
        };

        let err = ledger.apply_match_batch(&batch, context(1)).await.unwrap_err();
        assert_eq!(err, ClobError::MarketNotFound);
    });
}

#[test]
fn match_batch_rejects_missing_proposed_fill() {
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
        let batch = MatchBatch {
            orders: vec![ask, bid],
            fills: Vec::new(),
        };

        let err = ledger.apply_match_batch(&batch, context(2)).await.unwrap_err();
        assert_eq!(err, ClobError::MatchBatchMismatch);
    });
}

#[test]
fn match_batch_rejects_no_fill_order_only_payload() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;

        let ask = place_tx(
            &maker,
            0,
            Side::Ask,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        );
        let batch = batch_from_orders(&ledger, vec![ask], context(2)).await;
        assert!(batch.fills.is_empty());

        let err = ledger
            .apply_match_batch(&batch, context(2))
            .await
            .unwrap_err();
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

#[test]
fn full_market_fill_index_retains_recent_fills_without_blocking() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let market = market();
        let mut ledger = ClobLedger::new(MemoryStore::default());

        seed_market(&mut ledger, &creator).await;

        let stale_fill_ids = (0..MAX_FILLS_PER_MARKET as u64)
            .map(fake_fill_id)
            .collect::<Vec<_>>();
        ledger.db.set_market_fills(&market, &stale_fill_ids);

        let ask = place_tx(
            &maker,
            0,
            Side::Ask,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        );
        let bid = place_tx(
            &taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        let batch = batch_from_orders(&ledger, vec![ask, bid], context(2)).await;
        ledger
            .apply_match_batch(&batch, context(2))
            .await
            .expect("a full market fill index should not block matching");

        let retained = ledger.db.market_fills(&market).await.unwrap();
        assert_eq!(retained.len(), MAX_FILLS_PER_MARKET);
        assert_eq!(retained[0], stale_fill_ids[1]);

        let recent_fill = ledger.fill(retained.last().unwrap()).await.unwrap().unwrap();
        assert_eq!(recent_fill.market, market);
        assert_eq!(recent_fill.price, 100);
        assert_eq!(recent_fill.base_quantity, 2);

        let queryable_fills = ledger.market_fills(&market).await.unwrap();
        assert_eq!(queryable_fills, vec![recent_fill]);
    });
}

#[test]
fn actor_keeps_non_crossing_gtc_until_later_crossing_order() {
    deterministic::Runner::default().start(|runtime| async move {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;
        let market_info = ledger.market(&market()).await.unwrap().unwrap();

        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor_handle = actor.start(runtime);
        mailbox.upsert_market_state(market_info, ledger.market_sequence(&market()).await.unwrap());

        let ask = place_tx(
            &maker,
            0,
            Side::Ask,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        );
        mailbox.submit_order(ask.clone()).await.unwrap();
        assert!(mailbox.propose().await.is_empty());
        assert_eq!(ledger.nonce(&Address::external(&maker.public_key())).await.unwrap(), 0);

        let bid = place_tx(
            &taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(bid.clone()).await.unwrap();
        let batch = mailbox.propose().await;
        assert_eq!(batch.orders, vec![ask.clone(), bid.clone()]);
        assert_eq!(batch.fills.len(), 1);

        ledger.apply_match_batch(&batch, context(2)).await.unwrap();
        let fills = ledger.market_fills(&market()).await.unwrap();
        assert_eq!(fills.len(), 1);
        assert_eq!(fills[0].maker_order, OrderId(ask.digest()));
        assert_eq!(fills[0].taker_order, OrderId(bid.digest()));
    });
}

#[test]
fn actor_p2p_gossips_submitted_orders_to_peer_books() {
    deterministic::Runner::default().start(|runtime| async move {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;
        let market_info = ledger.market(&market()).await.unwrap().unwrap();
        let sequence = ledger.market_sequence(&market()).await.unwrap();

        let p2p_key_a = ed25519::PrivateKey::from_seed(11);
        let p2p_key_b = ed25519::PrivateKey::from_seed(12);
        let peer_a = p2p_key_a.public_key();
        let peer_b = p2p_key_b.public_key();
        let (network, oracle) = Network::<_, ed25519::PublicKey>::new_with_peers(
            runtime.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            [peer_a.clone(), peer_b.clone()],
        )
        .await;
        network.start();
        let quota = Quota::per_second(NZU32!(u32::MAX));
        let p2p_a = oracle
            .control(peer_a.clone())
            .register(17, quota)
            .await
            .unwrap();
        let p2p_b = oracle
            .control(peer_b.clone())
            .register(17, quota)
            .await
            .unwrap();
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::ZERO,
            success_rate: 1.0,
        };
        oracle
            .add_link(peer_a.clone(), peer_b.clone(), link.clone())
            .await
            .unwrap();
        oracle.add_link(peer_b, peer_a, link).await.unwrap();

        let (actor_a, mailbox_a) = ClobActor::new(ClobConfig::default());
        let (actor_b, mailbox_b) = ClobActor::new(ClobConfig::default());
        let _handle_a = actor_a.start_p2p(runtime.child("clob_a"), p2p_a);
        let _handle_b = actor_b.start_p2p(runtime.child("clob_b"), p2p_b);
        mailbox_a.upsert_market_state(market_info.clone(), sequence);
        mailbox_b.upsert_market_state(market_info, sequence);
        runtime.sleep(Duration::from_millis(1)).await;

        let ask = place_tx(
            &maker,
            0,
            Side::Ask,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        );
        let bid = place_tx(
            &taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        );
        mailbox_a.submit_order(ask.clone()).await.unwrap();
        mailbox_b.submit_order(bid.clone()).await.unwrap();

        for _ in 0..100 {
            let batch = mailbox_b.propose().await;
            if batch.fills.len() == 1 {
                assert!(batch.orders.contains(&ask));
                assert!(batch.orders.contains(&bid));
                return;
            }
            runtime.sleep(Duration::from_millis(5)).await;
        }
        panic!("gossiped clob order did not reach peer proposer");
    });
}

#[test]
fn actor_uses_committed_resting_order_and_current_sequence_for_later_batch() {
    deterministic::Runner::default().start(|runtime| async move {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let first_taker = PrivateKey::from_seed(3);
        let second_taker = PrivateKey::from_seed(4);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;
        let market_info = ledger.market(&market()).await.unwrap().unwrap();

        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor_handle = actor.start(runtime);
        mailbox.upsert_market_state(market_info.clone(), ledger.market_sequence(&market()).await.unwrap());

        let ask = place_tx(
            &maker,
            0,
            Side::Ask,
            100,
            4,
            TimeInForce::GoodTilCancelled,
        );
        let first_bid = place_tx(
            &first_taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(ask.clone()).await.unwrap();
        mailbox.submit_order(first_bid.clone()).await.unwrap();
        let first_batch = mailbox.propose().await;
        assert_eq!(
            mailbox.propose().await,
            first_batch,
            "proposal generation should not mutate actor state before acceptance"
        );
        assert_eq!(first_batch.fills.len(), 1);
        ledger
            .apply_match_batch(&first_batch, context(2))
            .await
            .unwrap();
        sync_actor_from_ledger(
            &mailbox,
            &ledger,
            market_info.clone(),
            vec![OrderId(ask.digest()), OrderId(first_bid.digest())],
        )
        .await;

        let second_bid = place_tx(
            &second_taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(second_bid.clone()).await.unwrap();
        let second_batch = mailbox.propose().await;
        assert_eq!(second_batch.orders, vec![second_bid.clone()]);
        assert_eq!(second_batch.fills.len(), 1);

        ledger
            .apply_match_batch(&second_batch, context(3))
            .await
            .expect("actor-proposed second batch should use committed market sequence");
        let fills = ledger.market_fills(&market()).await.unwrap();
        assert_eq!(fills.len(), 2);
        assert_eq!(fills[1].maker_order, OrderId(ask.digest()));
        assert_eq!(fills[1].taker_order, OrderId(second_bid.digest()));
    });
}

#[test]
fn actor_drops_unmatchable_ioc_without_dropping_pending_gtc() {
    deterministic::Runner::default().start(|runtime| async move {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let stale_taker = PrivateKey::from_seed(3);
        let live_taker = PrivateKey::from_seed(4);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;
        let market_info = ledger.market(&market()).await.unwrap().unwrap();

        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor_handle = actor.start(runtime);
        mailbox.upsert_market_state(market_info, ledger.market_sequence(&market()).await.unwrap());

        let ask = place_tx(
            &maker,
            0,
            Side::Ask,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        );
        let stale_bid = place_tx(
            &stale_taker,
            0,
            Side::Bid,
            95,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(ask.clone()).await.unwrap();
        mailbox.submit_order(stale_bid.clone()).await.unwrap();
        assert!(
            mailbox.propose().await.is_empty(),
            "non-crossing IOC should not produce an accepted batch"
        );

        let live_bid = place_tx(
            &live_taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(live_bid.clone()).await.unwrap();
        let batch = mailbox.propose().await;
        assert_eq!(batch.orders, vec![ask.clone(), live_bid.clone()]);
        assert_eq!(batch.fills.len(), 1);
        assert_eq!(batch.fills[0].maker_order, OrderId(ask.digest()));
        assert_eq!(batch.fills[0].taker_order, OrderId(live_bid.digest()));
    });
}

#[test]
fn actor_drops_stale_intents_after_nonce_sync() {
    deterministic::Runner::default().start(|runtime| async move {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let stale_taker = PrivateKey::from_seed(3);
        let live_taker = PrivateKey::from_seed(4);
        let stale_addr = Address::external(&stale_taker.public_key());
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;
        let market_info = ledger.market(&market()).await.unwrap().unwrap();

        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor_handle = actor.start(runtime);
        mailbox.upsert_market_state(market_info, ledger.market_sequence(&market()).await.unwrap());
        mailbox.sync_nonce(stale_addr.clone(), 1).await.unwrap();

        let ask = place_tx(
            &maker,
            0,
            Side::Ask,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        );
        let stale_bid = place_tx(
            &stale_taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(ask.clone()).await.unwrap();
        assert_eq!(
            mailbox.submit_order(stale_bid).await.unwrap_err(),
            ClobError::NonceMismatch {
                account: Box::new(stale_addr),
                expected: 1,
                actual: 0,
            }
        );

        let live_bid = place_tx(
            &live_taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(live_bid.clone()).await.unwrap();
        let batch = mailbox.propose().await;
        assert_eq!(batch.orders, vec![ask, live_bid.clone()]);
        assert_eq!(batch.fills.len(), 1);
        assert_eq!(batch.fills[0].taker_order, OrderId(live_bid.digest()));
    });
}

#[cfg(feature = "rpc")]
#[test]
fn rpc_queries_ledger_state() {
    use crate::rpc::{register, ClobRpc, ClobServer, SharedLedger};
    use nunchi_rpc::RpcRouter;

    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let maker_addr = Address::external(&maker.public_key());
        let market = market();
        let mut ledger = ClobLedger::new(MemoryStore::default());

        seed_market(&mut ledger, &creator).await;
        let ask = place_tx(
            &maker,
            0,
            Side::Ask,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        );
        let ask_id = OrderId(ask.digest());

        let bid = place_tx(
            &taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        let bid_id = OrderId(bid.digest());
        let batch = batch_from_orders(&ledger, vec![ask, bid], context(2)).await;
        ledger.apply_match_batch(&batch, context(2)).await.unwrap();
        let fill = ledger.market_fills(&market).await.unwrap().remove(0);

        let rpc = ClobRpc::new(SharedLedger::new(ledger));
        let market_hex = encoded_id(&market);

        let nonce = rpc.nonce(maker_addr.to_bech32()).await.unwrap();
        assert_eq!(nonce.account, maker_addr.to_bech32());
        assert_eq!(nonce.nonce, 1);

        let markets = rpc.markets().await.unwrap();
        assert_eq!(markets.markets.len(), 1);
        assert_eq!(markets.markets[0].id, market_hex);
        assert_eq!(markets.markets[0].tick_size, MARKET_TICK.to_string());
        assert_eq!(markets.markets[0].lot_size, MARKET_LOT.to_string());

        let market_response = rpc.market(market_hex.clone()).await.unwrap().unwrap();
        let (canonical_base, _) = crate::canonical_asset_pair(asset(b"base"), asset(b"quote"));
        assert_eq!(market_response.base_asset, encoded_id(&canonical_base));

        assert!(rpc.order(encoded_id(&ask_id)).await.unwrap().is_none());
        assert!(rpc.order(encoded_id(&bid_id)).await.unwrap().is_none());

        let asks = rpc.book(market_hex.clone(), "ask".to_string()).await.unwrap();
        assert_eq!(asks.market, market_hex);
        assert_eq!(asks.side, "ask");
        assert!(asks.orders.is_empty());

        let open_orders = rpc.account_orders(maker_addr.to_bech32()).await.unwrap();
        assert!(open_orders.orders.is_empty());

        let fills = rpc.fills(market_hex.clone()).await.unwrap();
        assert_eq!(fills.market, market_hex);
        assert_eq!(fills.fills.len(), 1);
        assert_eq!(fills.fills[0].id, encoded_id(&fill.id));
        assert_eq!(fills.fills[0].taker_side, "bid");
        assert_eq!(fills.fills[0].quote_quantity, "200");

        let fill_response = rpc.fill(encoded_id(&fill.id)).await.unwrap().unwrap();
        assert_eq!(fill_response.maker_order, encoded_id(&ask_id));
        assert_eq!(fill_response.taker_order, encoded_id(&bid_id));

        let root = rpc.state_root().await.unwrap();
        assert_eq!(root.root, encoded_id(&Sha256::hash(b"clob-test-root")));

        assert!(rpc
            .book(encoded_id(&market), "crossed".to_string())
            .await
            .is_err());
        assert!(rpc.market("not-hex".to_string()).await.is_err());

        let mut router = RpcRouter::new(());
        register(&mut router, rpc).unwrap();
        let methods = router.method_names();
        assert!(methods.contains(&"clob.nonce"));
        assert!(methods.contains(&"clob.fills"));
    });
}

#[test]
fn clob_actor_proposes_empty_batch_without_orders() {
    deterministic::Runner::default().start(|context| async move {
        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor_handle = actor.start(context);

        let batch = mailbox.propose().await;

        assert!(batch.is_empty());
    });
}

#[test]
fn clob_actor_holds_order_when_market_metadata_is_missing() {
    deterministic::Runner::default().start(|context| async move {
        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor_handle = actor.start(context);
        let trader = PrivateKey::from_seed(9);

        mailbox
            .submit_order(place_tx(
                &trader,
                0,
                Side::Bid,
                100,
                2,
                TimeInForce::ImmediateOrCancel,
            ))
            .await
            .unwrap();

        let batch = mailbox.propose().await;
        assert!(batch.is_empty());
    });
}

#[test]
fn clob_actor_rejects_gap_nonce_for_unknown_account() {
    deterministic::Runner::default().start(|context| async move {
        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor_handle = actor.start(context);
        let trader = PrivateKey::from_seed(9);

        let err = mailbox
            .submit_order(place_tx(
                &trader,
                999,
                Side::Bid,
                100,
                2,
                TimeInForce::ImmediateOrCancel,
            ))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            ClobError::NonceMismatch {
                account: Box::new(Address::external(&trader.public_key())),
                expected: 0,
                actual: 999,
            }
        );
        assert!(mailbox.propose().await.is_empty());
    });
}

#[test]
fn clob_mailbox_reports_stopped_actor() {
    deterministic::Runner::default().start(|_| async move {
        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        drop(actor);
        let trader = PrivateKey::from_seed(9);

        let err = mailbox
            .submit_order(place_tx(
                &trader,
                0,
                Side::Bid,
                100,
                2,
                TimeInForce::ImmediateOrCancel,
            ))
            .await
            .unwrap_err();
        assert_eq!(err, ClobError::ActorStopped);
        assert!(mailbox.propose().await.is_empty());

        mailbox.upsert_market(crate::Market {
            id: market(),
            base_asset: asset(b"base"),
            quote_asset: asset(b"quote"),
            tick_size: MARKET_TICK,
            lot_size: MARKET_LOT,
            created_by: Address::external(&trader.public_key()),
            created_at_height: 0,
            created_at_ms: 0,
        });
    });
}
