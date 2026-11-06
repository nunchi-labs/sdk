use std::{collections::BTreeMap, future::Future, time::Duration};

use commonware_codec::{DecodeExt, Encode, EncodeSize, MaxEncodeSize};
use commonware_cryptography::{
    ed25519, sha256::Digest, Digest as DigestTrait, Hasher, Sha256, Signer as _,
};
use commonware_formatting::hex;
use commonware_p2p::simulated::{self, Link, Network};
use commonware_runtime::{deterministic, Clock, Runner as _, Supervisor};
use commonware_utils::{probability, NZUsize, NZU32};
use governor::Quota;
use nunchi_chain::ConsensusExtension;
use nunchi_common::{
    Address, CommitState, MultisigPolicy, RuntimeContext, StateError, StateStore,
    MAX_MULTISIG_SIGNERS, MAX_STATE_VALUE_SIZE,
};
use nunchi_crypto::PrivateKey;

use crate::{
    market_id, transaction::MAX_SIGNED_ORDER_ENCODE_SIZE, AssetId, ClobActor, ClobConfig, ClobDB,
    ClobError, ClobExtension, ClobGenesis, ClobLedger, ClobMailbox, ClobMarketGenesis, ClobOperation,
    Fill, FillId, Market, MatchBatch, MatchEngine, Order, OrderId, OrderStatus, Side, TimeInForce,
    Transaction, MAX_BOOK_ORDERS, MAX_FILLS_PER_MARKET, MAX_MATCH_BATCH_FILLS, MAX_MATCH_BATCH_ORDERS,
};

#[derive(Clone, Default)]
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
        Sha256::hash(&[b"clob-test-root"])
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
    AssetId(Sha256::hash(&[seed]))
}

const MARKET_TICK: u128 = 5;
const MARKET_LOT: u128 = 2;

fn market() -> crate::MarketId {
    market_id(&asset(b"base"), &asset(b"quote"), MARKET_TICK, MARKET_LOT)
}

fn test_markets() -> BTreeMap<crate::MarketId, Market> {
    let creator = PrivateKey::from_seed(1);
    let mut markets = BTreeMap::new();
    markets.insert(
        market(),
        Market {
            id: market(),
            base_asset: asset(b"base"),
            quote_asset: asset(b"quote"),
            tick_size: MARKET_TICK,
            lot_size: MARKET_LOT,
            created_by: Address::external(&creator.public_key()),
            created_at_height: 0,
            created_at_ms: 0,
        },
    );
    markets
}

fn fake_fill_id(seed: u64) -> FillId {
    FillId(Sha256::hash(&[seed.encode().as_ref()]))
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
    place_tx_on(
        signer,
        nonce,
        market(),
        side,
        price,
        base_quantity,
        time_in_force,
    )
}

fn place_tx_on(
    signer: &PrivateKey,
    nonce: u64,
    market: crate::MarketId,
    side: Side,
    price: u128,
    base_quantity: u128,
    time_in_force: TimeInForce,
) -> Transaction {
    Transaction::sign(
        signer,
        nonce,
        ClobOperation::PlaceOrder {
            market,
            side,
            price,
            base_quantity,
            time_in_force,
        },
    )
}

fn create_market_tx_sized(
    signer: &PrivateKey,
    nonce: u64,
    tick_size: u128,
    lot_size: u128,
) -> Transaction {
    Transaction::sign(
        signer,
        nonce,
        ClobOperation::CreateMarket {
            base_asset: asset(b"base"),
            quote_asset: asset(b"quote"),
            tick_size,
            lot_size,
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
fn forged_multisig_cannot_create_market_for_another_account() {
    run_test(|| async {
        let victim = PrivateKey::from_seed(1);
        let attacker = PrivateKey::from_seed(2);
        let victim_account = Address::external(&victim.public_key());
        let forged = MultisigPolicy::new(1, vec![attacker.public_key()]).unwrap();
        let tx = Transaction::sign_multisig(
            victim_account,
            forged,
            &[&attacker],
            0,
            ClobOperation::CreateMarket {
                base_asset: asset(b"base"),
                quote_asset: asset(b"quote"),
                tick_size: MARKET_TICK,
                lot_size: MARKET_LOT,
            },
        );

        let mut ledger = ClobLedger::new(MemoryStore::default());
        let err = ledger
            .apply_transaction(&tx, context(1))
            .await
            .expect_err("forged authorization");

        assert!(matches!(err, ClobError::BadSignature(_)));
        assert!(ledger.market(&market()).await.unwrap().is_none());
    });
}

#[test]
fn policy_derived_multisig_can_create_market() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let policy = MultisigPolicy::new(1, vec![creator.public_key()]).unwrap();
        let account = Address::multisig(&policy);
        let tx = Transaction::sign_multisig(
            account.clone(),
            policy,
            &[&creator],
            0,
            ClobOperation::CreateMarket {
                base_asset: asset(b"base"),
                quote_asset: asset(b"quote"),
                tick_size: MARKET_TICK,
                lot_size: MARKET_LOT,
            },
        );

        let mut ledger = ClobLedger::new(MemoryStore::default());
        ledger
            .apply_transaction(&tx, context(1))
            .await
            .expect("policy-derived multisig");

        let created = ledger.market(&market()).await.unwrap().expect("market");
        assert_eq!(created.created_by, account);
    });
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

fn forged_multisig_order(victim: Address, nonce: u64) -> Transaction {
    let attacker = PrivateKey::from_seed(50);
    let policy = MultisigPolicy::new(1, vec![attacker.public_key()]).unwrap();
    Transaction::sign_multisig(
        victim,
        policy,
        &[&attacker],
        nonce,
        ClobOperation::PlaceOrder {
            market: market(),
            side: Side::Bid,
            price: 100,
            base_quantity: 4,
            time_in_force: TimeInForce::GoodTilCancelled,
        },
    )
}

#[test]
fn multisig_authorization_cannot_create_a_market_for_another_account() {
    run_test(|| async {
        let attacker = PrivateKey::from_seed(1);
        let victim = Address::external(&PrivateKey::from_seed(2).public_key());
        let policy = MultisigPolicy::new(1, vec![attacker.public_key()]).unwrap();
        let tx = Transaction::sign_multisig(
            victim.clone(),
            policy,
            &[&attacker],
            0,
            ClobOperation::CreateMarket {
                base_asset: asset(b"base"),
                quote_asset: asset(b"quote"),
                tick_size: MARKET_TICK,
                lot_size: MARKET_LOT,
            },
        );
        assert!(tx.verify().is_err());

        let mut ledger = ClobLedger::new(MemoryStore::default());
        assert!(matches!(
            ledger.apply_transaction(&tx, context(1)).await.unwrap_err(),
            ClobError::BadSignature(_)
        ));
        assert!(ledger.markets().await.unwrap().is_empty());
        assert_eq!(ledger.nonce(&victim).await.unwrap(), 0);
    });
}

#[test]
fn multisig_match_batch_cannot_trade_as_another_account() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let victim = Address::external(&PrivateKey::from_seed(2).public_key());
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;

        let forged = forged_multisig_order(victim.clone(), 0);
        assert!(forged.verify().is_err());
        let err = MatchEngine::replay(
            std::slice::from_ref(&forged),
            &BTreeMap::from([(market(), ledger.market(&market()).await.unwrap().unwrap())]),
            BTreeMap::from([(market(), 0)]),
            context(2),
        )
        .unwrap_err();
        assert!(matches!(err, ClobError::BadSignature(_)));

        let batch = MatchBatch {
            orders: vec![forged],
            fills: Vec::new(),
        };
        assert!(matches!(
            ledger.apply_match_batch(&batch, context(2)).await.unwrap_err(),
            ClobError::BadSignature(_)
        ));
        assert!(ledger.market_fills(&market()).await.unwrap().is_empty());
        assert_eq!(ledger.nonce(&victim).await.unwrap(), 0);
        assert!(ledger.book(&market(), Side::Bid).await.unwrap().is_empty());
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
                max_peers_per_set: NZUsize!(2),
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
            success_rate: probability!(1.0),
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
        assert_eq!(root.root, encoded_id(&Sha256::hash(&[b"clob-test-root"])));

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
fn clob_actor_rejects_multisig_order_for_another_account() {
    deterministic::Runner::default().start(|context| async move {
        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor_handle = actor.start(context);
        let victim = Address::external(&PrivateKey::from_seed(9).public_key());

        let err = mailbox
            .submit_order(forged_multisig_order(victim, 0))
            .await
            .unwrap_err();
        assert!(matches!(err, ClobError::BadSignature(_)));
        assert!(mailbox.propose().await.is_empty());
    });
}

#[test]
fn extension_verify_payload_rejects_multisig_and_bad_signatures() {
    deterministic::Runner::default().start(|context| async move {
        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor_handle = actor.start(context);
        let mut extension = ClobExtension::new(mailbox);

        assert!(extension.verify_payload(&MatchBatch::default()).await);

        let honest = place_tx(
            &PrivateKey::from_seed(1),
            0,
            Side::Bid,
            100,
            4,
            TimeInForce::GoodTilCancelled,
        );
        assert!(
            extension
                .verify_payload(&MatchBatch {
                    orders: vec![honest],
                    fills: Vec::new(),
                })
                .await
        );

        let victim = Address::external(&PrivateKey::from_seed(9).public_key());
        let forged = forged_multisig_order(victim, 0);
        assert!(forged.verify().is_err());
        assert!(
            !extension
                .verify_payload(&MatchBatch {
                    orders: vec![forged],
                    fills: Vec::new(),
                })
                .await
        );

        let signer = PrivateKey::from_seed(4);
        let policy = MultisigPolicy::new(1, vec![signer.public_key()]).unwrap();
        let bound = Transaction::sign_multisig(
            Address::multisig(&policy),
            policy,
            &[&signer],
            0,
            ClobOperation::PlaceOrder {
                market: market(),
                side: Side::Bid,
                price: 100,
                base_quantity: 4,
                time_in_force: TimeInForce::GoodTilCancelled,
            },
        );
        assert!(bound.verify().is_ok());
        assert!(
            extension
                .verify_payload(&MatchBatch {
                    orders: vec![bound],
                    fills: Vec::new(),
                })
                .await
        );

        let mut tampered = place_tx(
            &PrivateKey::from_seed(1),
            0,
            Side::Bid,
            100,
            4,
            TimeInForce::GoodTilCancelled,
        );
        let ClobOperation::PlaceOrder { price, .. } = &mut tampered.payload.operation else {
            panic!("expected place order");
        };
        *price += MARKET_TICK;
        assert!(tampered.verify().is_err());
        assert!(
            !extension
                .verify_payload(&MatchBatch {
                    orders: vec![tampered],
                    fills: Vec::new(),
                })
                .await
        );
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
fn commit_payload_tolerates_a_stopped_actor_while_syncing_nonces() {
    deterministic::Runner::default().start(|_| async move {
        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        drop(actor);
        let mut extension = ClobExtension::new(mailbox);
        let mut state = MemoryStore::default();
        extension
            .commit_payload(&mut state, context(1), &MatchBatch::default())
            .await;
        let err = extension
            .mailbox()
            .sync_nonce_index(Vec::new())
            .await
            .unwrap_err();
        assert_eq!(err, ClobError::ActorStopped);
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

#[test]
fn max_fill_index_fits_in_state_value_limit() {
    let fills = (0..MAX_FILLS_PER_MARKET as u64)
        .map(fake_fill_id)
        .collect::<Vec<_>>();
    let size = fills.encode_size();
    assert!(
        size <= MAX_STATE_VALUE_SIZE,
        "fill index encodes to {size}, cap is {MAX_STATE_VALUE_SIZE}"
    );
}

#[test]
fn create_market_rejects_multisig_for_another_account() {
    run_test(|| async {
        let victim_key = PrivateKey::from_seed(1);
        let attacker = PrivateKey::from_seed(2);
        let victim = Address::external(&victim_key.public_key());
        let policy = MultisigPolicy::new(1, vec![attacker.public_key()]).unwrap();
        let tx = Transaction::sign_multisig(
            victim,
            policy,
            &[&attacker],
            0,
            ClobOperation::CreateMarket {
                base_asset: asset(b"base"),
                quote_asset: asset(b"quote"),
                tick_size: MARKET_TICK,
                lot_size: MARKET_LOT,
            },
        );
        assert!(tx.verify().is_err());
        let mut ledger = ClobLedger::new(MemoryStore::default());
        let err = ledger
            .apply_transaction(&tx, context(1))
            .await
            .unwrap_err();
        assert!(matches!(err, ClobError::BadSignature(_)));
        assert!(ledger.db.market_index().await.unwrap().is_empty());
    });
}

#[test]
fn fill_budget_rejects_a_sweep_that_still_crosses() {
    let maker_a = PrivateKey::from_seed(2);
    let maker_b = PrivateKey::from_seed(3);
    let taker = PrivateKey::from_seed(4);
    let markets = test_markets();
    let mut sequences = BTreeMap::new();
    sequences.insert(market(), 0);
    let first = place_tx(
        &maker_a,
        0,
        Side::Ask,
        100,
        2,
        TimeInForce::GoodTilCancelled,
    );
    let second = place_tx(
        &maker_b,
        0,
        Side::Ask,
        100,
        2,
        TimeInForce::GoodTilCancelled,
    );
    let resting = MatchEngine::replay(
        &[first, second],
        &markets,
        sequences.clone(),
        context(2),
    )
    .unwrap();
    let resting_orders = resting.orders.values().cloned().collect::<Vec<_>>();
    sequences.insert(market(), resting.sequences[&market()]);

    for time_in_force in [TimeInForce::GoodTilCancelled, TimeInForce::ImmediateOrCancel] {
        let bid = place_tx(&taker, 0, Side::Bid, 100, 4, time_in_force);
        let err = MatchEngine::replay_limited(
            &resting_orders,
            &[bid],
            &markets,
            sequences.clone(),
            context(3),
            1,
        )
        .unwrap_err();
        assert_eq!(err, ClobError::FillBudgetExceeded);
    }

    let bid = place_tx(
        &taker,
        0,
        Side::Bid,
        100,
        4,
        TimeInForce::GoodTilCancelled,
    );
    let complete = MatchEngine::replay_limited(
        &resting_orders,
        &[bid],
        &markets,
        sequences,
        context(3),
        2,
    )
    .unwrap();
    assert_eq!(complete.fills.len(), 2);
    let taker_order = complete
        .orders
        .values()
        .find(|order| order.side == Side::Bid)
        .unwrap();
    assert_eq!(taker_order.status, OrderStatus::Filled);
}

#[test]
fn fill_budget_rests_only_after_crossing_liquidity_is_gone() {
    let maker_a = PrivateKey::from_seed(2);
    let maker_b = PrivateKey::from_seed(3);
    let taker = PrivateKey::from_seed(4);
    let markets = test_markets();
    let mut sequences = BTreeMap::new();
    sequences.insert(market(), 0);
    let crossing = place_tx(
        &maker_a,
        0,
        Side::Ask,
        100,
        2,
        TimeInForce::GoodTilCancelled,
    );
    let behind = place_tx(
        &maker_b,
        0,
        Side::Ask,
        110,
        2,
        TimeInForce::GoodTilCancelled,
    );
    let resting = MatchEngine::replay(
        &[crossing, behind],
        &markets,
        sequences.clone(),
        context(2),
    )
    .unwrap();
    let resting_orders = resting.orders.values().cloned().collect::<Vec<_>>();
    sequences.insert(market(), resting.sequences[&market()]);

    let gtc = place_tx(
        &taker,
        0,
        Side::Bid,
        100,
        4,
        TimeInForce::GoodTilCancelled,
    );
    let limited = MatchEngine::replay_limited(
        &resting_orders,
        std::slice::from_ref(&gtc),
        &markets,
        sequences.clone(),
        context(3),
        1,
    )
    .unwrap();
    assert_eq!(limited.fills.len(), 1);
    let taker_order = &limited.orders[&OrderId(gtc.digest())];
    assert_eq!(taker_order.status, OrderStatus::PartiallyFilled);
    assert_eq!(taker_order.remaining_base, 2);
    assert!(limited.orders.values().all(|order| {
        order.side != Side::Ask || !order.status.is_open() || order.price > taker_order.price
    }));

    let ioc = place_tx(
        &taker,
        0,
        Side::Bid,
        100,
        4,
        TimeInForce::ImmediateOrCancel,
    );
    let limited = MatchEngine::replay_limited(
        &resting_orders,
        std::slice::from_ref(&ioc),
        &markets,
        sequences,
        context(3),
        1,
    )
    .unwrap();
    assert_eq!(limited.fills.len(), 1);
    assert_eq!(
        limited.orders[&OrderId(ioc.digest())].status,
        OrderStatus::Expired
    );
}

#[test]
fn bounded_selection_skips_a_sweep_that_would_leave_a_crossed_book() {
    let maker_a = PrivateKey::from_seed(2);
    let maker_b = PrivateKey::from_seed(3);
    let large = PrivateKey::from_seed(4);
    let small = PrivateKey::from_seed(5);
    let markets = test_markets();
    let mut sequences = BTreeMap::new();
    sequences.insert(market(), 0);
    let asks = [
        place_tx(
            &maker_a,
            0,
            Side::Ask,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        ),
        place_tx(
            &maker_b,
            0,
            Side::Ask,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        ),
    ];
    let resting = MatchEngine::replay(&asks, &markets, sequences.clone(), context(2)).unwrap();
    let resting_orders = resting.orders.values().cloned().collect::<Vec<_>>();
    let sequences = resting.sequences.clone();
    let oversized = place_tx(
        &large,
        0,
        Side::Bid,
        100,
        4,
        TimeInForce::GoodTilCancelled,
    );
    let fits = place_tx(&small, 0, Side::Bid, 100, 2, TimeInForce::GoodTilCancelled);
    let selected = crate::actor::select_bounded_orders(
        &[oversized, fits.clone()],
        |batch| {
            MatchEngine::replay_limited(
                &resting_orders,
                batch,
                &markets,
                sequences.clone(),
                context(3),
                1,
            )
            .map(|result| result.fills.len())
        },
        8,
        1,
    );
    assert_eq!(selected, vec![fits]);
}

#[test]
fn bounded_proposal_keeps_a_slot_for_a_later_crossing_order() {
    let maker = PrivateKey::from_seed(2);
    let taker = PrivateKey::from_seed(3);
    let mut orders = (0..MAX_MATCH_BATCH_ORDERS)
        .map(|nonce| {
            place_tx(
                &maker,
                nonce as u64,
                Side::Ask,
                100,
                2,
                TimeInForce::GoodTilCancelled,
            )
        })
        .collect::<Vec<_>>();
    let bid = place_tx(
        &taker,
        0,
        Side::Bid,
        100,
        2,
        TimeInForce::ImmediateOrCancel,
    );
    orders.push(bid.clone());
    let selected = crate::actor::select_bounded_orders(
        &orders,
        |batch| {
            let fills = batch
                .iter()
                .filter(|tx| {
                    matches!(
                        tx.payload.operation,
                        ClobOperation::PlaceOrder {
                            side: Side::Bid,
                            ..
                        }
                    )
                })
                .count();
            Ok(fills)
        },
        MAX_MATCH_BATCH_ORDERS,
        MAX_MATCH_BATCH_ORDERS,
    );
    assert!(selected.len() <= MAX_MATCH_BATCH_ORDERS);
    assert!(selected.iter().any(|tx| tx.digest() == bid.digest()));
    assert!(selected.len() < orders.len());
}

#[test]
fn incremental_fill_counts_match_a_full_replay() {
    let maker = PrivateKey::from_seed(2);
    let filler = PrivateKey::from_seed(3);
    let taker = PrivateKey::from_seed(4);
    let markets = test_markets();
    let mut sequences = BTreeMap::new();
    sequences.insert(market(), 0);
    let ask = place_tx(
        &maker,
        0,
        Side::Ask,
        100,
        2,
        TimeInForce::GoodTilCancelled,
    );
    let resting = MatchEngine::replay(std::slice::from_ref(&ask), &markets, sequences, context(2))
        .unwrap();
    let resting_orders = resting.orders.values().cloned().collect::<Vec<_>>();
    let mut orders = (0..8)
        .map(|nonce| {
            place_tx(
                &filler,
                nonce,
                Side::Bid,
                50,
                2,
                TimeInForce::GoodTilCancelled,
            )
        })
        .collect::<Vec<_>>();
    orders.push(place_tx(
        &taker,
        0,
        Side::Bid,
        100,
        2,
        TimeInForce::ImmediateOrCancel,
    ));
    let mut counter = crate::actor::ProposalFillCount::new(
        &resting_orders,
        &markets,
        resting.sequences.clone(),
        context(3),
    )
    .unwrap();
    let selected = crate::actor::select_bounded_orders(
        &orders,
        |batch| {
            let incremental = counter.fill_count(batch)?;
            let full = MatchEngine::replay_with_resting(
                &resting_orders,
                batch,
                &markets,
                resting.sequences.clone(),
                context(3),
            )?
            .fills
            .len();
            assert_eq!(incremental, full);
            Ok(incremental)
        },
        8,
        8,
    );
    let replay = MatchEngine::replay_with_resting(
        &resting_orders,
        &selected,
        &markets,
        resting.sequences,
        context(3),
    )
    .unwrap();
    assert_eq!(replay.fills.len(), 1);
    assert!(selected.iter().any(|tx| tx.digest() == orders.last().unwrap().digest()));
}

#[test]
fn full_book_applies_removals_before_inserts() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let seller = PrivateKey::from_seed(3);
        let buyer = PrivateKey::from_seed(4);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;

        let fresh_bid = place_tx(
            &buyer,
            0,
            Side::Bid,
            MARKET_TICK,
            MARKET_LOT,
            TimeInForce::GoodTilCancelled,
        );
        let fresh_id = OrderId(fresh_bid.digest());
        let victim_id = order_id_above(&fresh_id);
        let owner = Address::external(&PrivateKey::from_seed(8).public_key());
        let mut ids = Vec::with_capacity(MAX_BOOK_ORDERS);
        for index in 0..MAX_BOOK_ORDERS - 1 {
            let id = OrderId(Sha256::hash(&[b"resting", (index as u64).encode().as_ref()]));
            if id == victim_id || id == fresh_id {
                continue;
            }
            ids.push(id);
        }
        ids.push(victim_id);
        assert_eq!(ids.len(), MAX_BOOK_ORDERS);

        for (index, id) in ids.iter().enumerate() {
            let price = if *id == victim_id { 100 } else { MARKET_TICK };
            ledger.db.set_order(&resting_order(*id, price, index as u64, owner.clone()));
        }
        ledger.db.set_side_book(&market(), Side::Bid, &ids);

        let ask = place_tx(
            &seller,
            0,
            Side::Ask,
            MARKET_TICK,
            MARKET_LOT,
            TimeInForce::ImmediateOrCancel,
        );
        let market_info = ledger.market(&market()).await.unwrap().unwrap();
        let mut markets = BTreeMap::new();
        markets.insert(market(), market_info);
        let mut sequences = BTreeMap::new();
        sequences.insert(market(), 0);
        let resting = ids
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let price = if *id == victim_id { 100 } else { MARKET_TICK };
                resting_order(*id, price, index as u64, owner.clone())
            })
            .collect::<Vec<_>>();
        let replay = MatchEngine::replay_with_resting(
            &resting,
            &[fresh_bid.clone(), ask.clone()],
            &markets,
            sequences,
            context(2),
        )
        .unwrap();
        let batch = MatchBatch {
            orders: vec![fresh_bid, ask],
            fills: replay.fills,
        };
        ledger
            .apply_match_batch(&batch, context(2))
            .await
            .expect("a full book can replace one order in the same batch");
        let book = ledger.db.side_book(&market(), Side::Bid).await.unwrap();
        assert_eq!(book.len(), MAX_BOOK_ORDERS);
        assert!(book.contains(&fresh_id));
        assert!(!book.contains(&victim_id));
    });
}

#[test]
fn restored_actor_proposes_against_committed_resting_liquidity() {
    deterministic::Runner::default().start(|runtime| async move {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let first_taker = PrivateKey::from_seed(3);
        let second_taker = PrivateKey::from_seed(4);
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
            &first_taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        let batch = batch_from_orders(&ledger, vec![ask, bid], context(2)).await;
        ledger.apply_match_batch(&batch, context(2)).await.unwrap();
        let snapshot = ledger.actor_snapshot().await.unwrap();
        assert_eq!(snapshot.orders.len(), 1);
        assert!(!snapshot.nonces.is_empty());

        let (mut actor, mailbox) = ClobActor::new(ClobConfig::default());
        actor.restore_snapshot(snapshot);
        let _actor_handle = actor.start(runtime);

        let next = place_tx(
            &second_taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(next.clone()).await.unwrap();
        let proposed = mailbox.propose().await;
        assert_eq!(proposed.orders, vec![next]);
        assert_eq!(proposed.fills.len(), 1);
        ledger
            .apply_match_batch(&proposed, context(3))
            .await
            .expect("restored proposer matches validator replay");
    });
}

#[test]
fn match_engine_default_uses_the_fill_cap() {
    assert_eq!(MatchEngine::default(), MatchEngine::new());
}

#[test]
fn extension_rejects_unbound_multisig_and_bad_signatures() {
    deterministic::Runner::default().start(|runtime| async move {
        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor_handle = actor.start(runtime);
        let mut extension = ClobExtension::new(mailbox);

        let honest = place_tx(
            &PrivateKey::from_seed(2),
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::GoodTilCancelled,
        );
        assert!(extension
            .verify_payload(&MatchBatch {
                orders: vec![honest.clone()],
                fills: Vec::new(),
            })
            .await);

        let mut tampered = honest;
        tampered.payload.nonce = 9;
        assert!(!extension
            .verify_payload(&MatchBatch {
                orders: vec![tampered],
                fills: Vec::new(),
            })
            .await);

        let attacker = PrivateKey::from_seed(3);
        let policy = MultisigPolicy::new(1, vec![attacker.public_key()]).unwrap();
        let forged = Transaction::sign_multisig(
            Address::external(&PrivateKey::from_seed(2).public_key()),
            policy,
            &[&attacker],
            0,
            ClobOperation::PlaceOrder {
                market: market(),
                side: Side::Bid,
                price: 100,
                base_quantity: 2,
                time_in_force: TimeInForce::GoodTilCancelled,
            },
        );
        assert!(forged.verify().is_err());
        assert!(!extension
            .verify_payload(&MatchBatch {
                orders: vec![forged.clone()],
                fills: Vec::new(),
            })
            .await);

        let err = extension
            .mailbox()
            .submit_order(forged)
            .await
            .unwrap_err();
        assert!(matches!(err, ClobError::BadSignature(_)));
    });
}

#[test]
fn full_nonce_index_rejects_accounts_it_cannot_recover() {
    deterministic::Runner::default().start(|runtime| async move {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let fresh = PrivateKey::from_seed(4);
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
        let opener = place_tx(
            &taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        let batch = batch_from_orders(&ledger, vec![ask, opener], context(2)).await;
        ledger.apply_match_batch(&batch, context(2)).await.unwrap();
        fill_nonce_account_index(&mut ledger).await;

        let fresh_addr = Address::external(&fresh.public_key());
        let taker_addr = Address::external(&taker.public_key());
        let fresh_bid = place_tx(
            &fresh,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        let market_info = ledger.market(&market()).await.unwrap().unwrap();
        let mut markets = BTreeMap::new();
        markets.insert(market(), market_info);
        let mut sequences = BTreeMap::new();
        sequences.insert(market(), ledger.market_sequence(&market()).await.unwrap());
        let resting = ledger.book(&market(), Side::Ask).await.unwrap();
        let replay = MatchEngine::replay_with_resting(
            &resting,
            std::slice::from_ref(&fresh_bid),
            &markets,
            sequences,
            context(3),
        )
        .unwrap();
        assert!(!replay.fills.is_empty());
        let overflow = MatchBatch {
            orders: vec![fresh_bid.clone()],
            fills: replay.fills,
        };
        let err = ledger
            .apply_match_batch(&overflow, context(3))
            .await
            .unwrap_err();
        assert_eq!(err, ClobError::NonceIndexFull);
        assert_eq!(ledger.nonce(&fresh_addr).await.unwrap(), 0);
        assert!(!ledger
            .db
            .nonce_accounts()
            .await
            .unwrap()
            .contains(&fresh_addr));
        assert_eq!(ledger.book(&market(), Side::Ask).await.unwrap(), resting);

        let other = market_id(
            &asset(b"other-base"),
            &asset(b"other-quote"),
            MARKET_TICK,
            MARKET_LOT,
        );
        let create = Transaction::sign(
            &fresh,
            0,
            ClobOperation::CreateMarket {
                base_asset: asset(b"other-base"),
                quote_asset: asset(b"other-quote"),
                tick_size: MARKET_TICK,
                lot_size: MARKET_LOT,
            },
        );
        let err = ledger
            .apply_transaction(&create, context(3))
            .await
            .unwrap_err();
        assert_eq!(err, ClobError::NonceIndexFull);
        assert!(ledger.market(&other).await.unwrap().is_none());

        let snapshot = ledger.actor_snapshot().await.unwrap();
        assert!(snapshot
            .nonces
            .iter()
            .all(|(account, _)| account != &fresh_addr));
        assert!(snapshot
            .nonces
            .iter()
            .any(|(account, nonce)| account == &taker_addr && *nonce == 1));

        let (mut actor, mailbox) = ClobActor::new(ClobConfig::default());
        actor.restore_snapshot(snapshot);
        let _actor_handle = actor.start(runtime);

        let err = mailbox.submit_order(fresh_bid).await.unwrap_err();
        assert_eq!(err, ClobError::NonceIndexFull);

        let next = place_tx(
            &taker,
            1,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(next.clone()).await.unwrap();
        let proposed = mailbox.propose().await;
        assert_eq!(proposed.orders, vec![next]);
        ledger
            .apply_match_batch(&proposed, context(3))
            .await
            .expect("indexed account still matches after the nonce index is full");
        assert_eq!(ledger.nonce(&taker_addr).await.unwrap(), 2);
        assert!(!ledger
            .db
            .nonce_accounts()
            .await
            .unwrap()
            .contains(&fresh_addr));
    });
}

#[test]
fn create_market_accounts_count_toward_proposer_nonce_capacity() {
    deterministic::Runner::default().start(|runtime| async move {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let other = PrivateKey::from_seed(4);
        let fresh = PrivateKey::from_seed(5);
        let later = PrivateKey::from_seed(6);
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
        let opener = place_tx(
            &taker,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        let batch = batch_from_orders(&ledger, vec![ask, opener], context(2)).await;
        ledger.apply_match_batch(&batch, context(2)).await.unwrap();

        let mut accounts = ledger.db.nonce_accounts().await.unwrap();
        let mut label = 0u64;
        while accounts.len() + 1 < crate::db::MAX_NONCE_ACCOUNTS {
            accounts.push(Address::reserved(&label.to_le_bytes()));
            label += 1;
        }
        ledger.db.set_nonce_accounts(&accounts);

        let snapshot = ledger.actor_snapshot().await.unwrap();
        assert_eq!(snapshot.nonces.len(), crate::db::MAX_NONCE_ACCOUNTS - 1);
        let (mut actor, mailbox) = ClobActor::new(ClobConfig::default());
        actor.restore_snapshot(snapshot);
        let _actor_handle = actor.start(runtime);
        let market_info = ledger.market(&market()).await.unwrap().unwrap();
        mailbox.upsert_market_state(
            market_info,
            ledger.market_sequence(&market()).await.unwrap(),
        );

        let create = Transaction::sign(
            &other,
            0,
            ClobOperation::CreateMarket {
                base_asset: asset(b"other-base"),
                quote_asset: asset(b"other-quote"),
                tick_size: MARKET_TICK,
                lot_size: MARKET_LOT,
            },
        );
        ledger.apply_transaction(&create, context(3)).await.unwrap();
        assert_eq!(
            ledger.db.nonce_accounts().await.unwrap().len(),
            crate::db::MAX_NONCE_ACCOUNTS
        );

        let fresh_bid = place_tx(
            &fresh,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        // The actor has not observed the create-market account yet.
        mailbox.submit_order(fresh_bid.clone()).await.unwrap();

        let mut extension = ClobExtension::new(mailbox.clone());
        extension.preview(&mut ledger.db).await;
        let hidden = extension.propose(context(4)).await;
        assert!(
            hidden
                .orders
                .iter()
                .all(|tx| tx.account_id != fresh_bid.account_id),
            "a full nonce index must not be proposed"
        );

        extension
            .commit_payload(&mut ledger.db, context(3), &MatchBatch::default())
            .await;

        let later_bid = place_tx(
            &later,
            0,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        assert_eq!(
            mailbox.submit_order(later_bid).await.unwrap_err(),
            ClobError::NonceIndexFull
        );

        let next = place_tx(
            &taker,
            1,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(next.clone()).await.unwrap();
        extension.preview(&mut ledger.db).await;
        let proposed = extension.propose(context(4)).await;
        assert_eq!(proposed.orders, vec![next]);
        ledger
            .apply_match_batch(&proposed, context(4))
            .await
            .expect("indexed account still matches when the nonce index is full");
    });
}

#[test]
fn corrupt_nonce_account_index_is_a_storage_error() {
    run_test(|| async {
        let creator = PrivateKey::from_seed(1);
        let mut ledger = ClobLedger::new(MemoryStore::default());
        seed_market(&mut ledger, &creator).await;
        assert!(ledger.db.nonce_accounts().await.unwrap().len() == 1);

        for value in ledger.db.values.values_mut() {
            if value.is_some() {
                *value = Some(b"not-an-index".to_vec());
            }
        }
        let err = ledger.db.nonce_accounts().await.unwrap_err();
        assert!(matches!(err, ClobError::Storage(_)));
    });
}

async fn fill_nonce_account_index(ledger: &mut ClobLedger<MemoryStore>) {
    let mut accounts = ledger.db.nonce_accounts().await.unwrap();
    let mut label = 0u64;
    while accounts.len() < crate::db::MAX_NONCE_ACCOUNTS {
        accounts.push(Address::reserved(&label.to_le_bytes()));
        label += 1;
    }
    ledger.db.set_nonce_accounts(&accounts);
}

fn order_id_above(floor: &OrderId) -> OrderId {
    let mut index = 0u64;
    loop {
        let candidate = OrderId(Sha256::hash(&[b"above", index.encode().as_ref()]));
        if candidate > *floor {
            return candidate;
        }
        index += 1;
    }
}

fn resting_order(id: OrderId, price: u128, sequence: u64, owner: Address) -> Order {
    Order {
        id,
        owner,
        market: market(),
        side: Side::Bid,
        price,
        original_base: MARKET_LOT,
        remaining_base: MARKET_LOT,
        filled_base: 0,
        status: OrderStatus::Open,
        sequence,
        created_at_height: 1,
        created_at_ms: 1,
    }
}

#[test]
fn prepare_hydrates_a_restarted_matcher_from_the_ledger() {
    deterministic::Runner::default().start(|runtime| async move {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let next_taker = PrivateKey::from_seed(4);
        let mut state = {
            let mut ledger = ClobLedger::new(MemoryStore::default());
            seed_market(&mut ledger, &creator).await;
            let ask = place_tx(
                &maker,
                0,
                Side::Ask,
                100,
                6,
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
            let batch = batch_from_orders(&ledger, vec![ask.clone(), bid], context(2)).await;
            ledger.apply_match_batch(&batch, context(2)).await.unwrap();
            ledger.into_inner()
        };
        let ask = place_tx(
            &maker,
            0,
            Side::Ask,
            100,
            6,
            TimeInForce::GoodTilCancelled,
        );

        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor = actor.start(runtime.child("clob"));
        let mut extension = ClobExtension::new(mailbox.clone());
        extension.prepare(&mut state).await;
        let bid = place_tx(
            &next_taker,
            0,
            Side::Bid,
            100,
            4,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(bid.clone()).await.unwrap();
        let proposal_context = context(3);
        let payload = extension.propose(proposal_context).await;
        assert_eq!(payload.fills.len(), 1);
        assert_eq!(payload.fills[0].written_at_height, proposal_context.height);
        assert_eq!(payload.fills[0].written_at_ms, proposal_context.timestamp_ms);
        assert!(extension
            .apply_payload(&mut state, proposal_context, &payload)
            .await);
        let ledger = ClobLedger::new(&mut state);
        let fills = ledger.market_fills(&market()).await.unwrap();
        assert_eq!(fills.len(), 2);
        assert_eq!(fills[1].maker_order, OrderId(ask.digest()));
        assert_eq!(fills[1].taker_order, OrderId(bid.digest()));
    });
}

#[test]
fn prepare_hydrates_nonce_after_the_account_leaves_the_book() {
    deterministic::Runner::default().start(|runtime| async move {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let maker_addr = Address::external(&maker.public_key());
        let mut state = {
            let mut ledger = ClobLedger::new(MemoryStore::default());
            seed_market(&mut ledger, &creator).await;
            let ask = place_tx(&maker, 0, Side::Ask, 100, 2, TimeInForce::GoodTilCancelled);
            let bid = place_tx(&taker, 0, Side::Bid, 100, 2, TimeInForce::ImmediateOrCancel);
            let batch = batch_from_orders(&ledger, vec![ask, bid], context(2)).await;
            ledger.apply_match_batch(&batch, context(2)).await.unwrap();
            assert!(ledger.book(&market(), Side::Ask).await.unwrap().is_empty());
            assert!(ledger.book(&market(), Side::Bid).await.unwrap().is_empty());
            assert_eq!(ledger.nonce(&maker_addr).await.unwrap(), 1);
            ledger.db.set_nonce_accounts(&[]);
            ledger.into_inner()
        };

        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor = actor.start(runtime.child("clob"));
        let mut extension = ClobExtension::new(mailbox.clone());
        extension.prepare(&mut state).await;

        let stale = place_tx(&maker, 0, Side::Bid, 100, 2, TimeInForce::ImmediateOrCancel);
        assert_eq!(
            mailbox.submit_order(stale).await.unwrap_err(),
            ClobError::NonceMismatch {
                account: Box::new(maker_addr.clone()),
                expected: 1,
                actual: 0,
            }
        );
        let ask = place_tx(&maker, 1, Side::Ask, 100, 2, TimeInForce::GoodTilCancelled);
        let bid = place_tx(&taker, 1, Side::Bid, 100, 2, TimeInForce::ImmediateOrCancel);
        mailbox.submit_order(ask).await.unwrap();
        mailbox.submit_order(bid).await.unwrap();
        let proposal_context = context(4);
        let payload = extension.propose(proposal_context).await;
        assert_eq!(payload.fills.len(), 1);
        assert!(extension
            .apply_payload(&mut state, proposal_context, &payload)
            .await);
        assert_eq!(
            ClobLedger::new(&mut state).nonce(&maker_addr).await.unwrap(),
            2
        );
    });
}

#[test]
fn prepare_keeps_nonce_when_fills_and_the_account_index_are_gone() {
    deterministic::Runner::default().start(|runtime| async move {
        let creator = PrivateKey::from_seed(1);
        let maker = PrivateKey::from_seed(2);
        let taker = PrivateKey::from_seed(3);
        let maker_addr = Address::external(&maker.public_key());
        let mut state = {
            let mut ledger = ClobLedger::new(MemoryStore::default());
            seed_market(&mut ledger, &creator).await;
            let ask = place_tx(&maker, 0, Side::Ask, 100, 2, TimeInForce::GoodTilCancelled);
            let bid = place_tx(&taker, 0, Side::Bid, 100, 2, TimeInForce::ImmediateOrCancel);
            let batch = batch_from_orders(&ledger, vec![ask, bid], context(2)).await;
            ledger.apply_match_batch(&batch, context(2)).await.unwrap();
            ledger.into_inner()
        };

        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor = actor.start(runtime.child("clob"));
        let mut extension = ClobExtension::new(mailbox.clone());
        extension.prepare(&mut state).await;

        {
            let ledger = ClobLedger::new(&mut state);
            let fills = ledger.market_fills(&market()).await.unwrap();
            for fill in &fills {
                ledger.db.remove_fill(&fill.id);
            }
            ledger.db.set_market_fills(&market(), &[]);
            ledger.db.set_nonce_accounts(&[]);
        }

        extension.prepare(&mut state).await;
        let stale = place_tx(&maker, 0, Side::Bid, 100, 2, TimeInForce::ImmediateOrCancel);
        assert_eq!(
            mailbox.submit_order(stale.clone()).await.unwrap_err(),
            ClobError::NonceMismatch {
                account: Box::new(maker_addr.clone()),
                expected: 1,
                actual: 0,
            }
        );

        let (restarted, restarted_mailbox) = ClobActor::new(ClobConfig::default());
        let _restarted = restarted.start(runtime.child("restarted"));
        restarted_mailbox.submit_order(stale).await.unwrap();
        let mut restarted_extension = ClobExtension::new(restarted_mailbox.clone());
        restarted_extension.prepare(&mut state).await;
        let payload = restarted_extension.propose(context(5)).await;
        assert!(payload.is_empty());
        restarted_mailbox
            .submit_order(place_tx(
                &maker,
                1,
                Side::Ask,
                100,
                2,
                TimeInForce::GoodTilCancelled,
            ))
            .await
            .unwrap();
    });
}

#[test]
fn preview_matches_same_block_markets_without_mutating_ingress() {
    deterministic::Runner::default().start(|runtime| async move {
        let creator = PrivateKey::from_seed(1);
        let alt_maker = PrivateKey::from_seed(4);
        let alt_taker = PrivateKey::from_seed(5);
        let probe = PrivateKey::from_seed(6);
        let mut state = {
            let mut ledger = ClobLedger::new(MemoryStore::default());
            seed_market(&mut ledger, &creator).await;
            ledger.into_inner()
        };
        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor = actor.start(runtime.child("clob"));
        let mut extension = ClobExtension::new(mailbox.clone());
        extension.prepare(&mut state).await;

        let creator_order = place_tx(
            &creator,
            1,
            Side::Bid,
            100,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(creator_order.clone()).await.unwrap();

        let mut preview_state = state.clone();
        ClobLedger::new(&mut preview_state)
            .apply_transaction(&create_market_tx_sized(&creator, 1, 7, MARKET_LOT), context(2))
            .await
            .unwrap();
        let alt_market = market_id(&asset(b"base"), &asset(b"quote"), 7, MARKET_LOT);
        extension.preview(&mut preview_state).await;

        assert!(matches!(
            mailbox.submit_order(creator_order.clone()).await.unwrap_err(),
            ClobError::NonceMismatch {
                expected: 2,
                actual: 1,
                ..
            }
        ));

        let ask = place_tx_on(
            &alt_maker,
            0,
            alt_market,
            Side::Ask,
            7,
            2,
            TimeInForce::GoodTilCancelled,
        );
        let bid = place_tx_on(
            &alt_taker,
            0,
            alt_market,
            Side::Bid,
            7,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(ask).await.unwrap();
        mailbox.submit_order(bid).await.unwrap();

        let proposal_context = context(3);
        let payload = extension.propose(proposal_context).await;
        assert_eq!(payload.fills.len(), 1);
        assert_eq!(payload.fills[0].market, alt_market);
        assert!(payload
            .orders
            .iter()
            .all(|tx| tx.digest() != creator_order.digest()));
        assert!(extension
            .apply_payload(&mut preview_state, proposal_context, &payload)
            .await);

        assert!(matches!(
            mailbox.submit_order(creator_order).await.unwrap_err(),
            ClobError::NonceMismatch {
                expected: 2,
                actual: 1,
                ..
            }
        ));
        let off_tick = place_tx_on(
            &probe,
            0,
            alt_market,
            Side::Bid,
            1,
            2,
            TimeInForce::ImmediateOrCancel,
        );
        mailbox.submit_order(off_tick).await.unwrap();
    });
}

#[test]
fn match_batch_bound_covers_full_multisig_orders() {
    let signers: Vec<PrivateKey> = (0..MAX_MULTISIG_SIGNERS)
        .map(|seed| PrivateKey::secp256r1_from_seed(seed as u64))
        .collect();
    let signer_refs: Vec<&PrivateKey> = signers.iter().collect();
    let policy = MultisigPolicy::new(
        1,
        signers.iter().map(PrivateKey::public_key).collect(),
    )
    .expect("multisig policy");
    let account = Address::multisig(&policy);
    let order = Transaction::sign_multisig(
        account,
        policy,
        &signer_refs,
        u64::MAX,
        ClobOperation::PlaceOrder {
            market: market(),
            side: Side::Bid,
            price: u128::MAX,
            base_quantity: u128::MAX,
            time_in_force: TimeInForce::GoodTilCancelled,
        },
    );
    assert!(order.encode_size() <= MAX_SIGNED_ORDER_ENCODE_SIZE);

    let fill = Fill {
        id: FillId(<Digest as DigestTrait>::EMPTY),
        market: market(),
        maker_order: OrderId(<Digest as DigestTrait>::EMPTY),
        taker_order: OrderId(<Digest as DigestTrait>::EMPTY),
        maker: order.account_id.clone(),
        taker: order.account_id.clone(),
        taker_side: Side::Ask,
        price: u128::MAX,
        base_quantity: u128::MAX,
        quote_quantity: u128::MAX,
        sequence: u64::MAX,
        written_at_height: u64::MAX,
        written_at_ms: u64::MAX,
    };
    assert!(fill.encode_size() <= Fill::MAX_ENCODE_SIZE);

    let batch = MatchBatch {
        orders: vec![order],
        fills: vec![fill],
    };
    assert!(batch.encode_size() <= MatchBatch::MAX_ENCODE_SIZE);
    const {
        assert!(MatchBatch::MAX_ENCODE_SIZE > 8 * 1024);
        assert!(MAX_MATCH_BATCH_ORDERS == 4_096);
        assert!(MAX_MATCH_BATCH_FILLS == 4_096);
    }

    let nested = Transaction::sign(
        &PrivateKey::from_seed(1),
        0,
        ClobOperation::ApplyMatchBatch {
            batch: MatchBatch::default(),
        },
    );
    let nested_batch = MatchBatch {
        orders: vec![nested],
        fills: Vec::new(),
    };
    assert!(MatchBatch::decode(nested_batch.encode()).is_err());
}
