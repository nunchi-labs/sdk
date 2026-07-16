//! Reusable engine tuning and support types.

use commonware_consensus::types::ViewDelta;
use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::{
    db::{AttachableResolver, Shared, SyncEngineConfig},
    PruneConfig,
};
use commonware_utils::{channel::oneshot, NZUsize, NZU16, NZU64};
use nunchi_common::{QmdbBackend, QmdbOperation};
use std::{
    future::Future,
    num::{NonZero, NonZeroU16, NonZeroUsize},
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
/// Prune cadence in finalized heights (retention floors are independent of this).
pub const PRUNE_MAINTENANCE_INTERVAL: NonZero<usize> = NZUsize!(32);
/// Finalized blocks retained in marshal beyond `max_pending_acks + 1` (~1 epoch buffer).
pub const PRUNE_RETAINED_MARSHAL_BLOCKS: usize = 200;
/// Extra QMDB history beyond the ack window; 0 is safe until peer state sync is enabled.
pub const PRUNE_RETAINED_QMDB_BLOCKS: usize = 0;

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

/// Placeholder for a peer state-sync resolver.
///
/// `commonware_glue::stateful::db::p2p::standard::Actor` would slot in here, but as of
/// commonware 2026.7.0 it requires `Op: Codec<Cfg = ()>`, which only fixed-encoding QMDB
/// operations satisfy; the shared state database is variable-value (`Vec<u8>`), whose
/// operation codec config is `((), (RangeCfg, ()))`. Until upstream threads the codec config
/// through its resolver (or a chain moves to fixed-size values), peer state sync stays disabled:
/// engines must not call [`SyncPlan::with_floor`](commonware_glue::stateful::SyncPlan::with_floor)
/// (attaching a floor selects the QMDB peer-sync path that would call this resolver). Nodes
/// recover via marshal backfill. Floor-probe actors still run in service mode so they can
/// answer peers once a real resolver exists.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoStateSyncResolver;

#[derive(Debug, thiserror::Error)]
#[error("peer state sync resolver is not configured")]
pub struct NoStateSyncError;

impl<E> AttachableResolver<QmdbBackend<E>> for NoStateSyncResolver
where
    E: commonware_storage::Context + Send + Sync + 'static,
{
    fn attach_database(&self, _db: Shared<QmdbBackend<E>>) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }
}

impl commonware_storage::qmdb::sync::resolver::Resolver for NoStateSyncResolver {
    type Family = commonware_storage::mmr::Family;
    type Digest = Digest;
    type Op = QmdbOperation;
    type Error = NoStateSyncError;

    fn get_operations<'a>(
        &'a self,
        _op_count: commonware_storage::mmr::Location,
        _start_loc: commonware_storage::mmr::Location,
        _max_ops: NonZero<u64>,
        _include_pinned_nodes: bool,
        _cancel_rx: oneshot::Receiver<()>,
    ) -> impl Future<
        Output = Result<
            commonware_storage::qmdb::sync::resolver::FetchResult<
                Self::Family,
                Self::Op,
                Self::Digest,
            >,
            Self::Error,
        >,
    > + Send
           + 'a {
        std::future::ready(Err(NoStateSyncError))
    }
}
