use crate::error::{AdmissionError, DropReason};
use crate::pool::Pool;
use crate::status::TxStatus;
use crate::testing::{tx, TestTx};
use crate::PoolConfig;

fn pool(config: PoolConfig) -> Pool<TestTx> {
    Pool::new(config)
}

fn small_config() -> PoolConfig {
    PoolConfig {
        max_total_txs: 4,
        max_per_account_txs: 3,
        max_tx_bytes: 1_000,
        ttl_blocks: 10,
        status_cache_capacity: 100,
        mailbox_size: 8,
    }
}

#[test]
fn pending_orders_by_account_then_nonce() {
    let mut pool = pool(PoolConfig::default());
    pool.admit(tx(2, 0, 20)).unwrap();
    pool.admit(tx(1, 1, 11)).unwrap();
    pool.admit(tx(1, 0, 10)).unwrap();
    let ids: Vec<u64> = pool.pending(10).iter().map(|t| t.id).collect();
    assert_eq!(ids, vec![10, 11, 20]);
    assert_eq!(pool.pending(2).len(), 2);
    assert!(pool.pending(0).is_empty());
}

#[test]
fn rejects_invalid_signature() {
    let mut pool = pool(PoolConfig::default());
    let mut bad = tx(1, 0, 10);
    bad.valid = false;
    assert!(matches!(
        pool.admit(bad),
        Err(AdmissionError::InvalidSignature(_))
    ));
    assert_eq!(pool.status_of(&10), None);
}

#[test]
fn rejects_oversized_transaction() {
    let mut pool = pool(small_config());
    let mut big = tx(1, 0, 10);
    big.size = 1_001;
    assert!(matches!(
        pool.admit(big),
        Err(AdmissionError::TxTooLarge { size: 1_001, .. })
    ));
}

#[test]
fn rejects_duplicate_digest() {
    let mut pool = pool(PoolConfig::default());
    pool.admit(tx(1, 0, 10)).unwrap();
    assert_eq!(pool.admit(tx(1, 0, 10)), Err(AdmissionError::Duplicate));
}

#[test]
fn rejects_stale_nonce_after_finalization() {
    let mut pool = pool(PoolConfig::default());
    pool.finalize(vec![], vec![(1, 3)], 5);
    assert_eq!(
        pool.admit(tx(1, 2, 10)),
        Err(AdmissionError::StaleNonce {
            nonce: 2,
            committed: 3
        })
    );
    pool.admit(tx(1, 3, 11)).unwrap();
}

#[test]
fn same_nonce_resubmission_replaces() {
    let mut pool = pool(PoolConfig::default());
    pool.admit(tx(1, 0, 10)).unwrap();
    pool.admit(tx(1, 0, 99)).unwrap();
    let ids: Vec<u64> = pool.pending(10).iter().map(|t| t.id).collect();
    assert_eq!(ids, vec![99]);
    assert_eq!(
        pool.status_of(&10),
        Some(TxStatus::Dropped {
            reason: DropReason::Replaced
        })
    );
    assert_eq!(pool.status_of(&99), Some(TxStatus::Pending));
}

#[test]
fn nonce_gaps_are_admitted_but_not_proposed() {
    let mut pool = pool(PoolConfig::default());
    pool.admit(tx(1, 0, 10)).unwrap();
    pool.admit(tx(1, 1, 11)).unwrap();
    pool.admit(tx(1, 3, 13)).unwrap();
    let ids: Vec<u64> = pool.pending(10).iter().map(|t| t.id).collect();
    assert_eq!(ids, vec![10, 11]);
    pool.admit(tx(1, 2, 12)).unwrap();
    let ids: Vec<u64> = pool.pending(10).iter().map(|t| t.id).collect();
    assert_eq!(ids, vec![10, 11, 12, 13]);
}

#[test]
fn enforces_per_account_cap() {
    let mut pool = pool(small_config());
    for nonce in 0..3 {
        pool.admit(tx(1, nonce, nonce)).unwrap();
    }
    assert_eq!(
        pool.admit(tx(1, 3, 3)),
        Err(AdmissionError::AccountQueueFull)
    );
    pool.admit(tx(1, 2, 99)).unwrap();
}

#[test]
fn evicts_highest_nonce_of_largest_queue_when_full() {
    let mut pool = pool(small_config());
    pool.admit(tx(1, 0, 10)).unwrap();
    pool.admit(tx(1, 1, 11)).unwrap();
    pool.admit(tx(1, 2, 12)).unwrap();
    pool.admit(tx(2, 0, 20)).unwrap();
    pool.admit(tx(3, 0, 30)).unwrap();
    assert_eq!(
        pool.status_of(&12),
        Some(TxStatus::Dropped {
            reason: DropReason::Evicted
        })
    );
    let ids: Vec<u64> = pool.pending(10).iter().map(|t| t.id).collect();
    assert_eq!(ids, vec![10, 11, 20, 30]);
}

#[test]
fn refuses_admission_that_would_be_next_victim() {
    let mut pool = pool(small_config());
    pool.admit(tx(1, 0, 10)).unwrap();
    pool.admit(tx(1, 1, 11)).unwrap();
    pool.admit(tx(2, 0, 20)).unwrap();
    pool.admit(tx(2, 1, 21)).unwrap();
    assert_eq!(pool.admit(tx(1, 2, 12)), Err(AdmissionError::PoolFull));
    pool.admit(tx(3, 0, 30)).unwrap();
    assert_eq!(
        pool.status_of(&11),
        Some(TxStatus::Dropped {
            reason: DropReason::Evicted
        })
    );
}

#[test]
fn finalize_marks_included_and_prunes_stale() {
    let mut pool = pool(PoolConfig::default());
    pool.admit(tx(1, 0, 10)).unwrap();
    pool.admit(tx(1, 1, 11)).unwrap();
    pool.admit(tx(1, 2, 12)).unwrap();
    pool.finalize(vec![10], vec![(1, 2)], 7);
    assert_eq!(pool.status_of(&10), Some(TxStatus::Finalized { height: 7 }));
    assert_eq!(
        pool.status_of(&11),
        Some(TxStatus::Dropped {
            reason: DropReason::StaleNonce
        })
    );
    assert_eq!(pool.status_of(&12), Some(TxStatus::Pending));
    let ids: Vec<u64> = pool.pending(10).iter().map(|t| t.id).collect();
    assert_eq!(ids, vec![12]);
}

#[test]
fn finalize_records_unpooled_digests() {
    let mut pool = pool(PoolConfig::default());
    pool.finalize(vec![42], vec![], 3);
    assert_eq!(pool.status_of(&42), Some(TxStatus::Finalized { height: 3 }));
}

#[test]
fn ttl_expires_unincluded_transactions() {
    let mut pool = pool(small_config());
    pool.admit(tx(1, 5, 15)).unwrap();
    pool.finalize(vec![], vec![], 10);
    assert_eq!(pool.status_of(&15), Some(TxStatus::Pending));
    pool.finalize(vec![], vec![], 11);
    assert_eq!(
        pool.status_of(&15),
        Some(TxStatus::Dropped {
            reason: DropReason::Expired
        })
    );
    assert!(pool.pending(10).is_empty());
}

#[test]
fn ttl_is_measured_from_admission_height() {
    let mut pool = pool(small_config());
    pool.finalize(vec![], vec![], 100);
    pool.admit(tx(1, 5, 15)).unwrap();
    pool.finalize(vec![], vec![], 110);
    assert_eq!(pool.status_of(&15), Some(TxStatus::Pending));
    pool.finalize(vec![], vec![], 111);
    assert_eq!(
        pool.status_of(&15),
        Some(TxStatus::Dropped {
            reason: DropReason::Expired
        })
    );
}
