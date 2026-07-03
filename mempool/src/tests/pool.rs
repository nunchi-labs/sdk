use crate::error::{AdmissionError, DropReason};
use crate::pool::Pool;
use crate::status::TxStatus;
use crate::testing::{digest, tx, TestTx};
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
fn pending_round_robins_ready_lanes() {
    let mut pool = pool(PoolConfig::default());
    pool.admit(tx(2, 0, 20)).unwrap();
    pool.admit(tx(1, 1, 11)).unwrap();
    pool.admit(tx(1, 0, 10)).unwrap();
    let ids: Vec<u64> = pool.pending(10).iter().map(|t| t.id).collect();
    assert_eq!(ids, vec![20, 10, 11]);
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
    assert_eq!(pool.status_of(&digest(10)), None);
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
        pool.status_of(&digest(10)),
        Some(TxStatus::Dropped {
            reason: DropReason::Replaced
        })
    );
    assert_eq!(pool.status_of(&digest(99)), Some(TxStatus::Pending));
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
        pool.status_of(&digest(12)),
        Some(TxStatus::Dropped {
            reason: DropReason::Evicted
        })
    );
    // Selection takes contiguous per-lane chunks when the limit is not
    // scarce, so lane 1's run comes out together.
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
        pool.status_of(&digest(11)),
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
    pool.finalize(vec![digest(10)], vec![(1, 2)], 7);
    assert_eq!(
        pool.status_of(&digest(10)),
        Some(TxStatus::Finalized { height: 7 })
    );
    assert_eq!(
        pool.status_of(&digest(11)),
        Some(TxStatus::Dropped {
            reason: DropReason::StaleNonce
        })
    );
    assert_eq!(pool.status_of(&digest(12)), Some(TxStatus::Pending));
    let ids: Vec<u64> = pool.pending(10).iter().map(|t| t.id).collect();
    assert_eq!(ids, vec![12]);
}

#[test]
fn finalize_keeps_lane_ready_after_committed_nonce_advances() {
    let mut pool = pool(PoolConfig::default());
    for nonce in 0..128 {
        pool.admit(tx(1, nonce, nonce)).unwrap();
    }
    let finalized = (0..64).map(digest).collect();
    pool.finalize(finalized, vec![(1, 64)], 7);
    let ids: Vec<u64> = pool.pending(64).iter().map(|t| t.id).collect();
    assert_eq!(ids, (64..128).collect::<Vec<_>>());
}

#[test]
fn finalize_records_unpooled_digests() {
    let mut pool = pool(PoolConfig::default());
    pool.finalize(vec![digest(42)], vec![], 3);
    assert_eq!(
        pool.status_of(&digest(42)),
        Some(TxStatus::Finalized { height: 3 })
    );
}

#[test]
fn ttl_expires_unincluded_transactions() {
    let mut pool = pool(small_config());
    pool.admit(tx(1, 5, 15)).unwrap();
    pool.finalize(vec![], vec![], 10);
    assert_eq!(pool.status_of(&digest(15)), Some(TxStatus::Pending));
    pool.finalize(vec![], vec![], 11);
    assert_eq!(
        pool.status_of(&digest(15)),
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
    assert_eq!(pool.status_of(&digest(15)), Some(TxStatus::Pending));
    pool.finalize(vec![], vec![], 111);
    assert_eq!(
        pool.status_of(&digest(15)),
        Some(TxStatus::Dropped {
            reason: DropReason::Expired
        })
    );
}

/// Drive the pool through the full production flow — bursty out-of-order
/// admission, block building from `pending`, finalization with lane nonces,
/// TTL expiry, and evictions at the cap — and check on every round that
/// selection agrees with the ready accounting.
#[test]
fn stress_ready_tracking_stays_consistent() {
    let mut pool = pool(PoolConfig {
        max_total_txs: 2_000,
        max_per_account_txs: 64,
        max_tx_bytes: 1_000,
        ttl_blocks: 50,
        status_cache_capacity: 100_000,
        mailbox_size: 8,
    });

    // xorshift PRNG for deterministic pseudo-random flow
    let mut state = 0x1234_5678_9abc_def0u64;
    let mut rand = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    const LANES: u64 = 40;
    let mut chain_nonce = vec![0u64; LANES as usize]; // committed on-chain nonce
    let mut frontier = vec![0u64; LANES as usize]; // next nonce each lane will sign
    let mut id_by_key = std::collections::HashMap::<(u8, u64), u64>::new();
    let mut next_id = 1u64;
    let mut height = 0u64;

    for round in 0..3_000 {
        // Bursty submission: mostly the next nonce, sometimes replay of a
        // pending nonce, sometimes a nonce skipped ahead (gap).
        for _ in 0..(rand() % 32) {
            let lane = (rand() % LANES) as usize;
            let account = lane as u8 + 1;
            let nonce = match rand() % 10 {
                0 => frontier[lane] + 1 + rand() % 4, // gap
                1 => chain_nonce[lane].saturating_sub(rand() % 3), // stale
                _ => frontier[lane],
            };
            let id = next_id;
            next_id += 1;
            if pool.admit(tx(account, nonce, id)).is_ok() {
                id_by_key.insert((account, nonce), id);
            }
            if nonce == frontier[lane] {
                frontier[lane] += 1;
            }
        }

        // Selection must agree with the ready accounting on every round.
        let all_ready = pool.pending(usize::MAX);
        assert_eq!(
            all_ready.len(),
            pool.ready_transaction_count(),
            "round {round}: pending(MAX) disagrees with ready count"
        );

        // Build and finalize a block from the selection, mimicking the
        // application: include candidates whose nonce matches chain state.
        let candidates = pool.pending(64);
        let mut digests = Vec::new();
        let mut lane_nonces = std::collections::HashMap::<u8, u64>::new();
        for candidate in candidates {
            let lane = (candidate.account - 1) as usize;
            if candidate.nonce == chain_nonce[lane] {
                chain_nonce[lane] += 1;
                let id = id_by_key[&(candidate.account, candidate.nonce)];
                digests.push(digest(id));
                lane_nonces.insert(candidate.account, chain_nonce[lane]);
            }
        }
        height += 1;
        pool.finalize(digests, lane_nonces.into_iter().collect(), height);

        let all_ready = pool.pending(usize::MAX);
        assert_eq!(
            all_ready.len(),
            pool.ready_transaction_count(),
            "round {round}: post-finalize pending(MAX) disagrees with ready count"
        );
    }
}

/// Model the production pipeline: `pending` is called every view but the
/// resulting block's finalization report only lands a few views later, and
/// whole 64-nonce submission batches can fail (RPC 429), leaving mid-lane
/// holes. The pool must keep making progress and its ready accounting must
/// stay consistent with what selection returns.
#[test]
fn stress_pipelined_finalization_makes_progress() {
    let mut pool = pool(PoolConfig {
        max_total_txs: 50_000,
        max_per_account_txs: 256,
        max_tx_bytes: 1_000,
        ttl_blocks: 1_000,
        status_cache_capacity: 1_000_000,
        mailbox_size: 8,
    });

    let mut state = 0xdead_beef_cafe_f00du64;
    let mut rand = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    const LANES: u64 = 200;
    const BATCH: u64 = 64;
    let mut chain_nonce = vec![0u64; LANES as usize];
    let mut submitted = vec![0u64; LANES as usize];
    let mut id_by_key = std::collections::HashMap::<(u8, u64), u64>::new();
    let mut next_id = 1u64;
    let mut height = 0u64;
    // Blocks in flight: (digests, lane_nonces), finalized 3 views later.
    let mut in_flight = std::collections::VecDeque::<(Vec<_>, Vec<(u8, u64)>)>::new();
    let mut total_finalized = 0usize;

    for round in 0..2_000 {
        // Submit a few whole batches per lane frontier; ~20% of batches fail
        // entirely (RPC overload), leaving 64-nonce holes.
        for _ in 0..8 {
            let lane = (rand() % LANES) as usize;
            let account = (lane % 250) as u8 + 1;
            let dropped = rand() % 5 == 0;
            for _ in 0..BATCH {
                let nonce = submitted[lane];
                submitted[lane] += 1;
                if dropped {
                    continue;
                }
                let id = next_id;
                next_id += 1;
                if pool.admit(tx(account, nonce, id)).is_ok() {
                    id_by_key.insert((account, nonce), id);
                }
            }
        }

        // Every view proposes from the pool; only 1 in 4 views is "our"
        // leader slot with a full pool (others are empty-pool leaders).
        let candidates = if round % 4 == 0 {
            pool.pending(4096)
        } else {
            Vec::new()
        };
        let mut digests = Vec::new();
        let mut lane_nonces = std::collections::HashMap::<u8, u64>::new();
        for candidate in candidates {
            let lane = (candidate.account as u64 - 1) as usize;
            if candidate.nonce == chain_nonce[lane] {
                chain_nonce[lane] += 1;
                digests.push(digest(id_by_key[&(candidate.account, candidate.nonce)]));
                lane_nonces.insert(candidate.account, chain_nonce[lane]);
            }
        }
        in_flight.push_back((digests, lane_nonces.into_iter().collect()));

        // Finalization lands three views later.
        if in_flight.len() > 3 {
            let (digests, lane_nonces) = in_flight.pop_front().unwrap();
            height += 1;
            total_finalized += digests.len();
            pool.finalize(digests, lane_nonces, height);
        }

        let all_ready = pool.pending(usize::MAX);
        assert_eq!(
            all_ready.len(),
            pool.ready_transaction_count(),
            "round {round}: pending(MAX) disagrees with ready count"
        );
    }
    // Liveness: the chain must have made real progress.
    assert!(
        total_finalized > 50_000,
        "pipeline wedged: only {total_finalized} finalized"
    );
}
