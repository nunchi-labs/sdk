use crate::config::PoolConfig;
use crate::error::{AdmissionError, DropReason};
use crate::metrics::MempoolMetrics;
use crate::status::{StatusCache, TxStatus};
use crate::tx::PoolTransaction;
use commonware_cryptography::sha256::Digest;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, OnceLock},
};

struct Entry<T> {
    tx: T,
    /// Content digest, computed once at admission.
    digest: Digest,
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
    /// Lanes that currently have their committed nonce available.
    ready_lanes: Vec<T::NonceKey>,
    /// Lane -> index in `ready_lanes`, for O(1) removal.
    ready_positions: HashMap<T::NonceKey, usize>,
    ready_counts: HashMap<T::NonceKey, usize>,
    total_ready_count: usize,
    ready_cursor: usize,
    /// Highest finalized height reported so far.
    last_height: u64,
    /// Height of the last TTL expiry sweep.
    last_ttl_scan: u64,
    total_count: usize,
    status: StatusCache<Digest>,
    config: PoolConfig,
    metrics: Arc<OnceLock<MempoolMetrics>>,
}

impl<T: PoolTransaction> Pool<T> {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            queues: BTreeMap::new(),
            index: HashMap::new(),
            committed_nonces: HashMap::new(),
            ready_lanes: Vec::new(),
            ready_positions: HashMap::new(),
            ready_counts: HashMap::new(),
            total_ready_count: 0,
            ready_cursor: 0,
            last_height: 0,
            last_ttl_scan: 0,
            total_count: 0,
            status: StatusCache::new(config.status_cache_capacity),
            config,
            metrics: Arc::new(OnceLock::new()),
        }
    }

    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    pub fn set_metrics(&mut self, metrics: Arc<OnceLock<MempoolMetrics>>) {
        self.metrics = metrics;
        self.record_stats();
    }

    /// Admit a transaction, returning its digest or the reason it was refused.
    #[cfg(test)]
    pub fn admit(&mut self, tx: T) -> Result<Digest, AdmissionError> {
        Self::check_stateless(&tx, &self.config)?;
        self.admit_verified(tx)
    }

    pub fn check_stateless(tx: &T, config: &PoolConfig) -> Result<(), AdmissionError> {
        if let Err(err) = tx.verify() {
            return Err(AdmissionError::InvalidSignature(err.to_string()));
        }
        let size = tx.encoded_size();
        if size > config.max_tx_bytes {
            return Err(AdmissionError::TxTooLarge {
                size,
                max: config.max_tx_bytes,
            });
        }
        Ok(())
    }

    /// Admit an already stateless-verified transaction.
    pub fn admit_verified(&mut self, tx: T) -> Result<Digest, AdmissionError> {
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
            digest,
            admitted_at: self.last_height,
        };
        let previous = self
            .queues
            .entry(lane.clone())
            .or_default()
            .insert(nonce, entry);
        match previous {
            Some(replaced) => {
                let old_digest = replaced.digest;
                self.index.remove(&old_digest);
                self.status.insert(
                    old_digest,
                    TxStatus::Dropped {
                        reason: DropReason::Replaced,
                    },
                );
                self.record_drop(DropReason::Replaced);
            }
            None => self.total_count += 1,
        }
        self.index.insert(digest, (lane.clone(), nonce));
        self.status.insert(digest, TxStatus::Pending);
        self.refresh_ready(&lane);
        self.record_stats();
        // TODO(@distractedm1nd): gossip broadcast, forward to a commonware_broadcast handler from here.
        Ok(digest)
    }

    /// Up to `limit` executable transactions, round-robin across ready nonce
    /// lanes. Never includes a nonce gap, so every returned transaction can
    /// apply in order.
    pub fn pending(&mut self, limit: usize) -> Vec<T> {
        let mut out = Vec::with_capacity(limit.min(self.total_ready_count));
        if limit == 0 || self.ready_lanes.is_empty() {
            return out;
        }

        let lanes = self.ready_lanes.len();
        let start = self.ready_cursor % lanes;
        // Transactions already taken from each lane this call, indexed like
        // `ready_lanes`. Lane readiness is contiguous from the committed
        // nonce, so `ready_counts` bounds how far each lane can be drained.
        let mut taken = vec![0usize; lanes];
        'fill: loop {
            let mut progressed = false;
            for offset in 0..lanes {
                if out.len() == limit {
                    break 'fill;
                }
                let index = (start + offset) % lanes;
                let lane = &self.ready_lanes[index];
                let ready = self.ready_counts.get(lane).copied().unwrap_or(0);
                let available = ready.saturating_sub(taken[index]);
                if available == 0 {
                    continue;
                }
                // Take a contiguous chunk per lane visit: an equal share of
                // the remaining budget, at least one.
                let chunk = available
                    .min(((limit - out.len()) / lanes).max(1))
                    .min(limit - out.len());
                let from = self.committed_nonce(lane) + taken[index] as u64;
                let queue = self.queues.get(lane).expect("ready lane has queue");
                out.extend(
                    queue
                        .range(from..)
                        .take(chunk)
                        .map(|(_, entry)| entry.tx.clone()),
                );
                taken[index] += chunk;
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
        self.ready_cursor = (start + 1) % lanes;
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
        let mut finalized = 0u64;
        let mut touched = HashSet::new();
        for digest in digests {
            if let Some((account, nonce)) = self.index.remove(&digest) {
                if let Some(queue) = self.queues.get_mut(&account) {
                    if queue.remove(&nonce).is_some() {
                        self.total_count -= 1;
                        finalized += 1;
                    }
                    if queue.is_empty() {
                        self.queues.remove(&account);
                    }
                }
                touched.insert(account);
            }
            // even transactions we do not pool get recorded for status queries
            self.status.insert(digest, TxStatus::Finalized { height });
        }
        self.record_finalized(finalized);

        for (account, new_nonce) in lane_nonces {
            touched.insert(account.clone());
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
        for account in touched {
            self.refresh_ready(&account);
        }

        if height > self.last_height {
            self.last_height = height;
        }
        // Expiry only needs coarse timing, so amortize the full-pool walk
        // across blocks instead of paying it on every finalization.
        let ttl = self.config.ttl_blocks;
        let scan_interval = (ttl / 8).max(1);
        if height >= self.last_ttl_scan.saturating_add(scan_interval) {
            self.last_ttl_scan = height;
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
        self.record_stats();
    }

    pub fn status_of(&self, digest: &Digest) -> Option<TxStatus> {
        self.status.get(digest)
    }

    pub fn total_count(&self) -> usize {
        self.total_count
    }

    pub fn lane_count(&self) -> usize {
        self.queues.len()
    }

    pub fn ready_lane_count(&self) -> usize {
        self.ready_positions.len()
    }

    pub fn ready_transaction_count(&self) -> usize {
        self.total_ready_count
    }

    fn committed_nonce(&self, account: &T::NonceKey) -> u64 {
        self.committed_nonces.get(account).copied().unwrap_or(0)
    }

    fn ready_count(&self, account: &T::NonceKey) -> usize {
        let Some(queue) = self.queues.get(account) else {
            return 0;
        };
        let mut count = 0usize;
        let mut expected_nonce = self.committed_nonce(account);
        for &nonce in queue.keys() {
            if nonce != expected_nonce {
                break;
            }
            count += 1;
            let Some(next_nonce) = expected_nonce.checked_add(1) else {
                break;
            };
            expected_nonce = next_nonce;
        }
        count
    }

    fn refresh_ready(&mut self, account: &T::NonceKey) {
        let old_count = self.ready_counts.remove(account).unwrap_or(0);
        self.total_ready_count = self.total_ready_count.saturating_sub(old_count);
        let new_count = self.ready_count(account);

        if new_count > 0 {
            self.ready_counts.insert(account.clone(), new_count);
            self.total_ready_count += new_count;
            if !self.ready_positions.contains_key(account) {
                self.ready_positions
                    .insert(account.clone(), self.ready_lanes.len());
                self.ready_lanes.push(account.clone());
            }
            return;
        }

        if let Some(position) = self.ready_positions.remove(account) {
            self.ready_lanes.swap_remove(position);
            if let Some(moved) = self.ready_lanes.get(position) {
                self.ready_positions.insert(moved.clone(), position);
            }
            if self.ready_lanes.is_empty() {
                self.ready_cursor = 0;
            } else {
                self.ready_cursor %= self.ready_lanes.len();
            }
        }
    }

    fn record_stats(&self) {
        if let Some(metrics) = self.metrics.get() {
            metrics.set_pool_stats(
                self.total_count(),
                self.lane_count(),
                self.ready_lane_count(),
                self.ready_transaction_count(),
            );
        }
    }

    fn record_drop(&self, reason: DropReason) {
        if let Some(metrics) = self.metrics.get() {
            metrics.dropped(reason);
        }
    }

    fn record_finalized(&self, count: u64) {
        if count == 0 {
            return;
        }
        if let Some(metrics) = self.metrics.get() {
            metrics.finalized(count);
        }
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

    /// Remove one pooled transaction. Callers are responsible for calling
    /// [`Pool::record_stats`] once their batch of removals is complete.
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
        self.index.remove(&entry.digest);
        self.total_count -= 1;
        self.status
            .insert(entry.digest, TxStatus::Dropped { reason });
        self.refresh_ready(account);
        self.record_drop(reason);
    }
}
