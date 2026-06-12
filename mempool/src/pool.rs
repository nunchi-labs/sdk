use crate::config::PoolConfig;
use crate::error::{AdmissionError, DropReason};
use crate::status::{StatusCache, TxStatus};
use crate::tx::PoolTransaction;
use std::collections::{BTreeMap, HashMap};

struct Entry<T> {
    tx: T,
    /// The pool's `last_height` at admission, for TTL expiry.
    admitted_at: u64,
}

/// Nonce-aware pool state. All mutation happens on the actor task.
pub(crate) struct Pool<T: PoolTransaction> {
    /// Per-account pending transactions, ordered by nonce.
    queues: BTreeMap<T::AccountId, BTreeMap<u64, Entry<T>>>,
    /// Digest -> queue position, for O(1) dedup and removal.
    index: HashMap<T::Digest, (T::AccountId, u64)>,
    /// Snapshot of committed account nonces, fed exclusively by finalization.
    committed_nonces: HashMap<T::AccountId, u64>,
    /// Highest finalized height reported so far.
    last_height: u64,
    total_count: usize,
    status: StatusCache<T::Digest>,
    config: PoolConfig,
}

impl<T: PoolTransaction> Pool<T> {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            queues: BTreeMap::new(),
            index: HashMap::new(),
            committed_nonces: HashMap::new(),
            last_height: 0,
            total_count: 0,
            status: StatusCache::new(config.status_cache_capacity),
            config,
        }
    }

    /// Admit a transaction, returning its digest or the reason it was refused.
    pub fn admit(&mut self, tx: T) -> Result<T::Digest, AdmissionError> {
        if let Err(err) = tx.verify() {
            return Err(AdmissionError::InvalidSignature(err.to_string()));
        }
        let size = tx.encoded_size();
        if size > self.config.max_tx_bytes {
            return Err(AdmissionError::TxTooLarge {
                size,
                max: self.config.max_tx_bytes,
            });
        }
        let digest = tx.digest();
        if self.index.contains_key(&digest) {
            return Err(AdmissionError::Duplicate);
        }
        let account = tx.account_id().clone();
        let nonce = tx.nonce();
        let committed = self.committed_nonce(&account);
        if nonce < committed {
            return Err(AdmissionError::StaleNonce { nonce, committed });
        }

        // A same-nonce resubmission replaces the earlier transaction
        // (last-write-wins): only the account's own signers can produce one,
        // and replacement lets owners unstick an unexecutable transaction.
        // Replacements bypass the capacity checks since pool size is unchanged.
        let replacing = self
            .queues
            .get(&account)
            .is_some_and(|queue| queue.contains_key(&nonce));
        if !replacing {
            if self.queues.get(&account).map_or(0, BTreeMap::len) >= self.config.max_per_account_txs
            {
                return Err(AdmissionError::AccountQueueFull);
            }
            if self.total_count >= self.config.max_total_txs {
                self.evict_for(&account, nonce)?;
            }
        }

        let entry = Entry {
            tx,
            admitted_at: self.last_height,
        };
        let previous = self
            .queues
            .entry(account.clone())
            .or_default()
            .insert(nonce, entry);
        match previous {
            Some(replaced) => {
                let old_digest = replaced.tx.digest();
                self.index.remove(&old_digest);
                self.status.insert(
                    old_digest,
                    TxStatus::Dropped {
                        reason: DropReason::Replaced,
                    },
                );
            }
            None => self.total_count += 1,
        }
        self.index.insert(digest, (account, nonce));
        self.status.insert(digest, TxStatus::Pending);
        // TODO(@distractedm1nd): gossip broadcast, frward to a commonware_broadcast handler from here.
        Ok(digest)
    }

    /// Up to `limit` executable transactions: for each account (in id order),
    /// the contiguous nonce run starting at its committed nonce. Never
    /// includes a nonce gap, so every returned transaction can apply in order.
    pub fn pending(&self, limit: usize) -> Vec<T> {
        let mut out = Vec::new();
        'accounts: for (account, queue) in &self.queues {
            let mut next = self.committed_nonce(account);
            for (&nonce, entry) in queue {
                if nonce != next {
                    break;
                }
                if out.len() >= limit {
                    break 'accounts;
                }
                out.push(entry.tx.clone());
                next += 1;
            }
        }
        out
    }

    /// Apply a finalized block's effects: mark included digests, advance
    /// committed nonces, and expire transactions older than the TTL.
    pub fn finalize(
        &mut self,
        digests: Vec<T::Digest>,
        account_nonces: Vec<(T::AccountId, u64)>,
        height: u64,
    ) {
        for digest in digests {
            if let Some((account, nonce)) = self.index.remove(&digest) {
                if let Some(queue) = self.queues.get_mut(&account) {
                    if queue.remove(&nonce).is_some() {
                        self.total_count -= 1;
                    }
                    if queue.is_empty() {
                        self.queues.remove(&account);
                    }
                }
            }
            // even transactions we do not pool get recorded for status queries
            self.status.insert(digest, TxStatus::Finalized { height });
        }

        for (account, new_nonce) in account_nonces {
            let committed = self.committed_nonces.entry(account.clone()).or_insert(0);
            if new_nonce <= *committed {
                continue;
            }
            *committed = new_nonce;
            loop {
                let Some(queue) = self.queues.get(&account) else {
                    break;
                };
                match queue.first_key_value() {
                    Some((&nonce, _)) if nonce < new_nonce => {
                        self.remove_entry(&account, nonce, DropReason::StaleNonce);
                    }
                    _ => break,
                }
            }
        }

        if height > self.last_height {
            self.last_height = height;
        }
        let ttl = self.config.ttl_blocks;
        let expired: Vec<(T::AccountId, u64)> = self
            .queues
            .iter()
            .flat_map(|(account, queue)| {
                queue
                    .iter()
                    .filter(move |(_, entry)| entry.admitted_at.saturating_add(ttl) < height)
                    .map(move |(&nonce, _)| (account.clone(), nonce))
            })
            .collect();
        for (account, nonce) in expired {
            self.remove_entry(&account, nonce, DropReason::Expired);
        }
    }

    pub fn status_of(&self, digest: &T::Digest) -> Option<TxStatus> {
        self.status.get(digest)
    }

    fn committed_nonce(&self, account: &T::AccountId) -> u64 {
        self.committed_nonces.get(account).copied().unwrap_or(0)
    }

    /// Make room for an incoming transaction by evicting the highest-nonce
    /// entry from the largest account queue
    fn evict_for(
        &mut self,
        incoming_account: &T::AccountId,
        incoming_nonce: u64,
    ) -> Result<(), AdmissionError> {
        let victim = self
            .queues
            .iter()
            // On equal lengths, prefer the smaller account id
            .max_by(|(a_id, a), (b_id, b)| a.len().cmp(&b.len()).then_with(|| b_id.cmp(a_id)))
            .map(|(id, queue)| {
                let (&nonce, _) = queue.last_key_value().expect("queues are never empty");
                (id.clone(), nonce)
            });
        let Some((victim_account, victim_nonce)) = victim else {
            return Err(AdmissionError::PoolFull);
        };
        // Refuse rather than churn: if the incoming transaction would itself
        // be the next eviction victim, admitting it gains nothing.
        if victim_account == *incoming_account && incoming_nonce >= victim_nonce {
            return Err(AdmissionError::PoolFull);
        }
        self.remove_entry(&victim_account, victim_nonce, DropReason::Evicted);
        Ok(())
    }

    fn remove_entry(&mut self, account: &T::AccountId, nonce: u64, reason: DropReason) {
        let Some(queue) = self.queues.get_mut(account) else {
            return;
        };
        let Some(entry) = queue.remove(&nonce) else {
            return;
        };
        if queue.is_empty() {
            self.queues.remove(account);
        }
        let digest = entry.tx.digest();
        self.index.remove(&digest);
        self.total_count -= 1;
        self.status.insert(digest, TxStatus::Dropped { reason });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{tx, TestTx};

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
        // Closing the gap makes the tail proposable.
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
        // Replacement is still allowed at the cap.
        pool.admit(tx(1, 2, 99)).unwrap();
    }

    #[test]
    fn evicts_highest_nonce_of_largest_queue_when_full() {
        let mut pool = pool(small_config());
        pool.admit(tx(1, 0, 10)).unwrap();
        pool.admit(tx(1, 1, 11)).unwrap();
        pool.admit(tx(1, 2, 12)).unwrap();
        pool.admit(tx(2, 0, 20)).unwrap();
        // Pool is at max_total_txs = 4; account 1 has the largest queue, so
        // its highest nonce (id 12) is evicted.
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
        // Queues tie at two entries each, so account 1 (smaller id) owns the
        // eviction victim slot (nonce 1); admitting its own higher nonce
        // would just churn.
        assert_eq!(pool.admit(tx(1, 2, 12)), Err(AdmissionError::PoolFull));
        // A lower nonce from the same account is more valuable and displaces
        // the victim.
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
        // The block included id 10 (nonce 0) and some unpooled competing tx at
        // nonce 1, so the committed nonce advances to 2: id 11 is now stale.
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
        pool.admit(tx(1, 5, 15)).unwrap(); // gapped: never proposable
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
}
