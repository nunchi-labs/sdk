//! Reusable engine tuning and support types.

use commonware_consensus::types::ViewDelta;
use commonware_glue::stateful::{
    db::SyncEngineConfig,
    PruneConfig,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use std::{
    num::{NonZero, NonZeroU16, NonZeroUsize},
    time::Duration,
};

pub const MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
pub const DEQUE_SIZE: usize = 10;
pub const ACTIVITY_TIMEOUT: ViewDelta = ViewDelta::new(256);
pub const SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER: u64 = 10;
pub const PRUNABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(4_096);
pub const IMMUTABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(262_144);
pub const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
pub const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 3MB
pub const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
pub const FREEZER_VALUE_COMPRESSION: Option<u8> = Some(3);
pub const REPLAY_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024); // 8MB
pub const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024); // 1MB
pub const PAGE_CACHE_PAGE_SIZE: NonZeroU16 = NZU16!(4_096); // 4KB
pub const PAGE_CACHE_CAPACITY: NonZero<usize> = NZUsize!(8_192); // 32MB
pub const MAX_REPAIR: NonZero<usize> = NZUsize!(50);
pub const MAX_PENDING_ACKS: NonZero<usize> = NZUsize!(16);
pub const STATE_SYNC_FETCH_BATCH_SIZE: NonZero<u64> = NZU64!(1_024);
pub const STATE_SYNC_APPLY_BATCH_SIZE: usize = 4_096;
pub const STATE_SYNC_MAX_OUTSTANDING_REQUESTS: usize = 8;
pub const STATE_SYNC_UPDATE_CHANNEL_SIZE: NonZero<usize> = NZUsize!(256);
pub const STATE_SYNC_MAX_RETAINED_ROOTS: usize = 32;
pub const STATE_SYNC_RESOLVER_INITIAL: Duration = Duration::from_secs(1);
pub const STATE_SYNC_RESOLVER_TIMEOUT: Duration = Duration::from_secs(2);
pub const STATE_SYNC_RESOLVER_RETRY: Duration = Duration::from_millis(100);
/// Prune cadence in finalized heights (retention floors are independent of this).
pub const PRUNE_MAINTENANCE_INTERVAL: NonZero<usize> = NZUsize!(32);
/// Finalized blocks retained in marshal beyond `max_pending_acks + 1` (~1 epoch buffer).
pub const PRUNE_RETAINED_MARSHAL_BLOCKS: usize = 200;
/// Extra QMDB history beyond the ack window for serving lagging state-sync peers.
pub const PRUNE_RETAINED_QMDB_BLOCKS: usize = 200;

pub fn state_sync_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: STATE_SYNC_FETCH_BATCH_SIZE,
        apply_batch_size: STATE_SYNC_APPLY_BATCH_SIZE,
        max_outstanding_requests: STATE_SYNC_MAX_OUTSTANDING_REQUESTS,
        update_channel_size: STATE_SYNC_UPDATE_CHANNEL_SIZE,
        max_retained_roots: STATE_SYNC_MAX_RETAINED_ROOTS,
    }
}

/// Periodic marshal + QMDB pruning; `max_pending_acks` must match marshal's config.
pub fn state_prune_config() -> PruneConfig {
    PruneConfig {
        max_pending_acks: MAX_PENDING_ACKS,
        maintenance_interval: PRUNE_MAINTENANCE_INTERVAL,
        retained_marshal_blocks: PRUNE_RETAINED_MARSHAL_BLOCKS,
        retained_qmdb_blocks: PRUNE_RETAINED_QMDB_BLOCKS,
    }
}
