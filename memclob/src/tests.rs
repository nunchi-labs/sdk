use commonware_cryptography::{ed25519, Hasher, Sha256, Signer as _};
use commonware_p2p::simulated::{self, Link, Network};
use commonware_runtime::{deterministic, Clock, Runner as _, Supervisor};
use commonware_utils::{NZUsize, NZU32};
use governor::Quota;
use nunchi_clob::{
    market_id, AssetId, ClobOperation, MatchBatch, OrderStatus, Side, TimeInForce, Transaction,
};
use nunchi_common::RuntimeContext;
use nunchi_crypto::PrivateKey;
use std::time::Duration;

use crate::{MemClob, MemClobConfig};

fn block_context(height: u64) -> RuntimeContext {
    RuntimeContext {
        epoch: 0,
        height,
        timestamp_ms: height * 1_000,
        block_digest: None,
    }
}

fn asset(seed: u8) -> AssetId {
    AssetId(Sha256::hash(&[seed]))
}

fn market() -> nunchi_clob::MarketId {
    market_id(&asset(1), &asset(2), 1, 1)
}

#[test]
fn memclob_matches_orders_deterministically() {
    let mut engine = crate::MemBookEngine::default();
    let creator = PrivateKey::from_seed(1);
    let maker = PrivateKey::from_seed(2);
    let taker = PrivateKey::from_seed(3);

    let create = Transaction::sign(
        &creator,
        0,
        ClobOperation::CreateMarket {
            base_asset: asset(1),
            quote_asset: asset(2),
            tick_size: 1,
            lot_size: 1,
        },
    );
    engine.apply_transaction(&create, block_context(1)).unwrap();

    let ask = Transaction::sign(
        &maker,
        0,
        ClobOperation::PlaceOrder {
            market: market(),
            side: Side::Ask,
            price: 100,
            base_quantity: 10,
            time_in_force: TimeInForce::GoodTilCancelled,
        },
    );
    engine.apply_transaction(&ask, block_context(2)).unwrap();

    let bid = Transaction::sign(
        &taker,
        0,
        ClobOperation::PlaceOrder {
            market: market(),
            side: Side::Bid,
            price: 100,
            base_quantity: 4,
            time_in_force: TimeInForce::GoodTilCancelled,
        },
    );
    engine.apply_transaction(&bid, block_context(3)).unwrap();

    assert_eq!(engine.pending_fills().len(), 1);
    let fill = &engine.pending_fills()[0];
    assert_eq!(fill.base_quantity, 4);
    assert_eq!(fill.price, 100);

    let asks = engine.book(&market(), Side::Ask);
    assert_eq!(asks.len(), 1);
    assert_eq!(asks[0].remaining_base, 6);
    assert_eq!(asks[0].status, OrderStatus::PartiallyFilled);
}

#[test]
fn memclob_gossips_orders_between_validators() {
    deterministic::Runner::default().start(|context| async move {
        let key_a = ed25519::PrivateKey::from_seed(1);
        let key_b = ed25519::PrivateKey::from_seed(2);
        let peer_a = key_a.public_key();
        let peer_b = key_b.public_key();
        let (network, oracle) = Network::<_, ed25519::PublicKey>::new_with_peers(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            [peer_a.clone(), peer_b.clone()],
        )
        .await;
        network.start();

        let channel = 7;
        let quota = Quota::per_second(NZU32!(u32::MAX));
        let p2p_a = oracle
            .control(peer_a.clone())
            .register(channel, quota)
            .await
            .unwrap();
        let p2p_b = oracle
            .control(peer_b.clone())
            .register(channel, quota)
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

        let cfg = MemClobConfig::default();
        let (memclob_a, handle_a) = MemClob::new(cfg.clone());
        let (memclob_b, handle_b) = MemClob::new(cfg);
        memclob_a.start_p2p(context.child("memclob_a"), p2p_a);
        memclob_b.start_p2p(context.child("memclob_b"), p2p_b);
        context.sleep(Duration::from_millis(1)).await;

        let creator = PrivateKey::from_seed(10);
        let maker = PrivateKey::from_seed(11);
        let taker = PrivateKey::from_seed(12);

        handle_a
            .submit(
                Transaction::sign(
                    &creator,
                    0,
                    ClobOperation::CreateMarket {
                        base_asset: asset(1),
                        quote_asset: asset(2),
                        tick_size: 1,
                        lot_size: 1,
                    },
                ),
                block_context(1),
            )
            .await
            .unwrap();

        handle_a
            .submit(
                Transaction::sign(
                    &maker,
                    0,
                    ClobOperation::PlaceOrder {
                        market: market(),
                        side: Side::Ask,
                        price: 50,
                        base_quantity: 5,
                        time_in_force: TimeInForce::GoodTilCancelled,
                    },
                ),
                block_context(2),
            )
            .await
            .unwrap();

        for _ in 0..100 {
            if !handle_b.book(market(), Side::Ask).await.is_empty() {
                break;
            }
            context.sleep(Duration::from_millis(5)).await;
        }

        handle_b
            .submit(
                Transaction::sign(
                    &taker,
                    0,
                    ClobOperation::PlaceOrder {
                        market: market(),
                        side: Side::Bid,
                        price: 50,
                        base_quantity: 5,
                        time_in_force: TimeInForce::GoodTilCancelled,
                    },
                ),
                block_context(3),
            )
            .await
            .unwrap();

        for _ in 0..100 {
            let fills_a = handle_a.pending_fills(10).await;
            let fills_b = handle_b.pending_fills(10).await;
            if fills_a.len() == 1 && fills_b.len() == 1 {
                assert_eq!(fills_a[0].id, fills_b[0].id);
                return;
            }
            context.sleep(Duration::from_millis(5)).await;
        }
        panic!("gossiped memclob orders did not converge");
    });
}

#[test]
fn memclob_rejects_on_chain_only_operations() {
    let mut engine = crate::MemBookEngine::default();
    let maker = PrivateKey::from_seed(4);
    let market = market();

    engine
        .apply_transaction(
            &Transaction::sign(
                &PrivateKey::from_seed(1),
                0,
                ClobOperation::CreateMarket {
                    base_asset: asset(1),
                    quote_asset: asset(2),
                    tick_size: 1,
                    lot_size: 1,
                },
            ),
            block_context(1),
        )
        .unwrap();

    let ask = Transaction::sign(
        &maker,
        0,
        ClobOperation::PlaceOrder {
            market,
            side: Side::Ask,
            price: 100,
            base_quantity: 5,
            time_in_force: TimeInForce::GoodTilCancelled,
        },
    );
    engine.apply_transaction(&ask, block_context(2)).unwrap();

    let err = engine
        .apply_transaction(
            &Transaction::sign(
                &maker,
                1,
                ClobOperation::ApplyMatchBatch {
                    batch: MatchBatch::default(),
                },
            ),
            block_context(3),
        )
        .unwrap_err();
    assert_eq!(err.to_string(), "signed order intents are off-chain only");
}
