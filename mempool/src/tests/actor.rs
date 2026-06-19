use crate::testing::tx;
use crate::{AdmissionError, Mempool, PoolConfig, TxStatus};
use commonware_runtime::{deterministic, Runner as _};

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
