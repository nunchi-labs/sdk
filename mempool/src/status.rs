use crate::error::DropReason;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

/// Lifecycle of a transaction the pool admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxStatus {
    /// Admitted and awaiting inclusion.
    Pending,
    /// Included in a finalized block.
    Finalized { height: u64 },
    /// Left the pool without finalizing.
    Dropped { reason: DropReason },
}

/// Bounded per-digest status map with insertion-order (FIFO) eviction.
pub(crate) struct StatusCache<D> {
    ring: VecDeque<D>,
    map: HashMap<D, TxStatus>,
    capacity: usize,
}

impl<D: Copy + Eq + Hash> StatusCache<D> {
    pub fn new(capacity: usize) -> Self {
        Self {
            ring: VecDeque::new(),
            map: HashMap::new(),
            capacity,
        }
    }

    /// Record or update a digest's status. New digests evict the oldest entry
    /// once the cache is at capacity; updates keep their original ring slot.
    pub fn insert(&mut self, digest: D, status: TxStatus) {
        if self.capacity == 0 {
            return;
        }
        if let Some(existing) = self.map.get_mut(&digest) {
            *existing = status;
            return;
        }
        if self.ring.len() >= self.capacity {
            if let Some(evicted) = self.ring.pop_front() {
                self.map.remove(&evicted);
            }
        }
        self.ring.push_back(digest);
        self.map.insert(digest, status);
    }

    pub fn get(&self, digest: &D) -> Option<TxStatus> {
        self.map.get(digest).copied()
    }
}
