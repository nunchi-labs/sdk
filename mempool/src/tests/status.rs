use crate::status::{StatusCache, TxStatus};

#[test]
fn fifo_eviction_drops_oldest() {
    let mut cache = StatusCache::new(2);
    cache.insert(1u64, TxStatus::Pending);
    cache.insert(2, TxStatus::Pending);
    cache.insert(3, TxStatus::Pending);
    assert_eq!(cache.get(&1), None);
    assert_eq!(cache.get(&2), Some(TxStatus::Pending));
    assert_eq!(cache.get(&3), Some(TxStatus::Pending));
}

#[test]
fn update_in_place_keeps_ring_slot() {
    let mut cache = StatusCache::new(2);
    cache.insert(1u64, TxStatus::Pending);
    cache.insert(2, TxStatus::Pending);
    cache.insert(1, TxStatus::Finalized { height: 7 });
    cache.insert(3, TxStatus::Pending);
    assert_eq!(cache.get(&1), None);
    assert_eq!(cache.get(&2), Some(TxStatus::Pending));
}

#[test]
fn zero_capacity_retains_nothing() {
    let mut cache = StatusCache::new(0);
    cache.insert(1u64, TxStatus::Pending);
    assert_eq!(cache.get(&1), None);
}
