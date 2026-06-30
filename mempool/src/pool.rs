use crate::config::PoolConfig;
use crate::error::{AdmissionError, DropReason};
use crate::status::{StatusCache, TxStatus};
use crate::tx::PoolTransaction;
use commonware_cryptography::sha256::Digest;
use std::collections::{BTreeMap, HashMap};

struct Entry<T> {
    tx: T,
    /// The pool's `last_height` at admission, for TTL expiry.
    admitted_at: u64,
}

/// Nonce-aware pool state. All mutation happens on the actor task.
pub(crate) struct Pool<T: PoolTransaction> {
    /// Per-lane pending transactions, ordered by nonce.
    queues: BTreeMap<T::NonceKey, BTreeMap<u64, Entry<T>>>,
    /// Digest -> queue position, for O(1) dedup and removal.
    index: HashMap<Digest, (T::NonceKey, u64)>,
    /// Snapshot of committed lane nonces, fed exclusively by finalization.
    committed_nonces: HashMap<T::NonceKey, u64>,
    /// Highest finalized height reported so far.
    last_height: u64,
    total_count: usize,
    status: StatusCache<Digest>,
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
    pub fn admit(&mut self, tx: T) -> Result<Digest, AdmissionError> {
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
        let lane = tx.nonce_key();
        let nonce = tx.nonce();
        let committed = self.committed_nonce(&lane);
        if nonce < committed {
            return Err(AdmissionError::StaleNonce { nonce, committed });
        }

        // A same-nonce resubmission replaces the earlier transaction
        // (last-write-wins): only the account's own signers can produce one,
        // and replacement lets owners unstick an unexecutable transaction.
        // Replacements bypass the capacity checks since pool size is unchanged.
        let replacing = self
            .queues
            .get(&lane)
            .is_some_and(|queue| queue.contains_key(&nonce));
        if !replacing {
            if self.queues.get(&lane).map_or(0, BTreeMap::len) >= self.config.max_per_account_txs {
                return Err(AdmissionError::AccountQueueFull);
            }
            if self.total_count >= self.config.max_total_txs {
                self.evict_for(&lane, nonce)?;
            }
        }

        let entry = Entry {
            tx,
            admitted_at: self.last_height,
        };
        let previous = self
            .queues
            .entry(lane.clone())
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
        self.index.insert(digest, (lane, nonce));
        self.status.insert(digest, TxStatus::Pending);
        // TODO(@distractedm1nd): gossip broadcast, forward to a commonware_broadcast handler from here.
        Ok(digest)
    }

    /// Up to `limit` executable transactions: for each nonce lane (in id order),
    /// the contiguous nonce run starting at its committed nonce. Never
    /// includes a nonce gap, so every returned transaction can apply in order.
    pub fn pending(&self, limit: usize) -> Vec<T> {
        let mut out = Vec::new();
        'accounts: for (account, queue) in &self.queues {
            for (expected_nonce, (&nonce, entry)) in
                (self.committed_nonce(account)..).zip(queue.iter())
            {
                if nonce != expected_nonce {
                    break;
                }
                if out.len() >= limit {
                    break 'accounts;
                }
                out.push(entry.tx.clone());
            }
        }
        out
    }

    /// Apply a finalized block's effects: mark included digests, advance
    /// committed nonces, and expire transactions older than the TTL.
    pub fn finalize(
        &mut self,
        digests: Vec<Digest>,
        lane_nonces: Vec<(T::NonceKey, u64)>,
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

        for (account, new_nonce) in lane_nonces {
            let committed = self.committed_nonces.entry(account.clone()).or_insert(0);
            if new_nonce <= *committed {
                continue;
            }
            *committed = new_nonce;
            while let Some(queue) = self.queues.get(&account) {
                let Some((&nonce, _)) = queue.first_key_value() else {
                    break;
                };
                if nonce >= new_nonce {
                    break;
                }
                self.remove_entry(&account, nonce, DropReason::StaleNonce);
            }
        }

        if height > self.last_height {
            self.last_height = height;
        }
        let ttl = self.config.ttl_blocks;
        let expired: Vec<(T::NonceKey, u64)> = self
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

    pub fn status_of(&self, digest: &Digest) -> Option<TxStatus> {
        self.status.get(digest)
    }

    fn committed_nonce(&self, account: &T::NonceKey) -> u64 {
        self.committed_nonces.get(account).copied().unwrap_or(0)
    }

    /// Make room for an incoming transaction by evicting the highest-nonce
    /// entry from the largest lane queue
    fn evict_for(
        &mut self,
        incoming_account: &T::NonceKey,
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

    fn remove_entry(&mut self, account: &T::NonceKey, nonce: u64, reason: DropReason) {
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
