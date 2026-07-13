use crate::testing::{tx, TestTx};
use crate::{AdmissionError, Mempool, PoolConfig, TxStatus};
use commonware_cryptography::{ed25519, Signer};
use commonware_p2p::simulated::{self, Link, Network};
use commonware_runtime::{deterministic, Clock, Runner as _, Supervisor};
use commonware_utils::{NZUsize, NZU32};
use governor::Quota;
use std::time::Duration;

#[test]
fn submit_pending_finalize_status_roundtrip() {
    deterministic::Runner::default().start(|context| async move {
        let (mempool, handle) = Mempool::new(PoolConfig::default());
        mempool.start(context);

        let digest = handle.submit(tx(1, 0, 10)).await.unwrap();
        assert_eq!(digest, 10);
        assert_eq!(handle.status(10).await, Some(TxStatus::Pending));

        let pending = handle.pending(10).await;
        assert_eq!(pending.len(), 1);

        handle.finalized(vec![10], vec![(1, 1)], 5);
        assert_eq!(
            handle.status(10).await,
            Some(TxStatus::Finalized { height: 5 })
        );
        assert!(handle.pending(10).await.is_empty());
    });
}

#[test]
fn submit_reports_rejections() {
    deterministic::Runner::default().start(|context| async move {
        let (mempool, handle) = Mempool::new(PoolConfig::default());
        mempool.start(context);

        handle.submit(tx(1, 0, 10)).await.unwrap();
        assert_eq!(
            handle.submit(tx(1, 0, 10)).await,
            Err(AdmissionError::Duplicate)
        );
    });
}

#[test]
fn status_unknown_digest_is_none() {
    deterministic::Runner::default().start(|context| async move {
        let (mempool, handle) = Mempool::<crate::testing::TestTx>::new(PoolConfig::default());
        mempool.start(context);
        assert_eq!(handle.status(404).await, None);
    });
}

#[test]
fn p2p_gossips_submitted_transactions() {
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
        let (mempool_a, handle_a) = Mempool::new(PoolConfig::default());
        let (mempool_b, handle_b) = Mempool::<TestTx>::new(PoolConfig::default());
        mempool_a.start_p2p(context.child("mempool_a"), p2p_a);
        mempool_b.start_p2p(context.child("mempool_b"), p2p_b);
        context.sleep(Duration::from_millis(1)).await;

        let digest = handle_a.submit(tx(1, 0, 10)).await.unwrap();
        assert_eq!(digest, 10);

        for _ in 0..100 {
            if handle_b.status(10).await == Some(TxStatus::Pending) {
                return;
            }
            context.sleep(Duration::from_millis(5)).await;
        }
        panic!("gossiped transaction did not reach peer");
    });
}
