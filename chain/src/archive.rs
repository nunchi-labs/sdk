use bytes::Bytes;
use commonware_consensus::types::Height;
use commonware_cryptography::sha256;
use commonware_runtime::BufferPooler;
use commonware_storage::{
    archive::{immutable, Archive as _, Identifier},
    Context as StorageContext,
};
use futures::future::BoxFuture;
use futures::lock::Mutex as AsyncMutex;
use nunchi_common::{Event, EventLimits, TransactionReceipt};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, MutexGuard},
};
use thiserror::Error;

use crate::events::{FinalizedEventReportError, FinalizedEventReporter, FinalizedEvents};

/// Maximum number of event batches returned by a single archive stream query.
pub const MAX_EVENT_STREAM_LIMIT: usize = 1_000;

/// Default number of event batches returned by an archive stream query.
pub const DEFAULT_EVENT_STREAM_LIMIT: usize = 100;

/// Maximum number of indexed events returned by a single event-key query.
pub const MAX_EVENT_QUERY_LIMIT: usize = 10_000;

/// Default number of indexed events returned by an event-key query.
pub const DEFAULT_EVENT_QUERY_LIMIT: usize = 1_000;

/// Event index key used by archive queries.
///
/// Indexers normally use ASCII module, kind, and attribute key names, but the
/// committed event format is byte-oriented, so the archive keeps the raw bytes.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventKey {
    pub module: Bytes,
    pub kind: Bytes,
    pub version: u16,
    pub key: Bytes,
}

impl EventKey {
    /// Create an event key from raw committed event bytes.
    pub fn new(
        module: impl Into<Bytes>,
        kind: impl Into<Bytes>,
        version: u16,
        key: impl Into<Bytes>,
    ) -> Self {
        Self {
            module: module.into(),
            kind: kind.into(),
            version,
            key: key.into(),
        }
    }
}

/// A transaction event output with finalized block context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivedTransactionEvents {
    pub height: Height,
    pub block_digest: sha256::Digest,
    pub block_timestamp: u64,
    pub receipts_root: sha256::Digest,
    pub receipt: TransactionReceipt,
    pub events: Vec<Event>,
}

/// A single finalized event with block and transaction context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivedEvent {
    pub height: Height,
    pub block_digest: sha256::Digest,
    pub block_timestamp: u64,
    pub receipts_root: sha256::Digest,
    pub tx_index: u32,
    pub tx_digest: sha256::Digest,
    pub event_index: u32,
    pub event: Event,
}

/// Errors returned by finalized event archives.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EventArchiveError {
    #[error("event archive lock poisoned")]
    LockPoisoned,
    #[error("height {height} is already archived with a different block")]
    HeightConflict { height: u64 },
    #[error("block {block_digest:?} is already archived at height {height}")]
    BlockDigestConflict {
        block_digest: sha256::Digest,
        height: u64,
    },
    #[error("storage error: {0}")]
    Storage(String),
}

/// Query surface used by event RPC servers.
pub trait EventArchiveQuery: Clone + Send + Sync + 'static {
    fn batch_by_height(&self, height: Height)
        -> Result<Option<FinalizedEvents>, EventArchiveError>;

    fn batch_by_block_digest(
        &self,
        block_digest: sha256::Digest,
    ) -> Result<Option<FinalizedEvents>, EventArchiveError>;

    fn transactions_by_digest(
        &self,
        tx_digest: sha256::Digest,
    ) -> Result<Vec<ArchivedTransactionEvents>, EventArchiveError>;

    fn events_by_key(
        &self,
        key: &EventKey,
        from_height: Option<Height>,
        limit: usize,
    ) -> Result<Vec<ArchivedEvent>, EventArchiveError>;

    fn stream_from(
        &self,
        from_height: Height,
        limit: usize,
    ) -> Result<Vec<FinalizedEvents>, EventArchiveError>;
}

/// In-process finalized event archive with secondary indexes for indexers.
#[derive(Clone, Default)]
pub struct FinalizedEventArchive {
    inner: Arc<Mutex<ArchiveInner>>,
}

/// Persistent finalized event archive backed by Commonware immutable storage.
///
/// Queries are served from a rebuilt in-process index. Finalized reports are
/// written to storage first and then indexed locally.
pub struct PersistentFinalizedEventArchive<E>
where
    E: BufferPooler + StorageContext,
{
    storage: Arc<AsyncMutex<immutable::Archive<E, sha256::Digest, FinalizedEvents>>>,
    index: FinalizedEventArchive,
}

#[derive(Default)]
struct ArchiveInner {
    batches_by_height: BTreeMap<Height, FinalizedEvents>,
    heights_by_block: HashMap<sha256::Digest, Height>,
    transactions_by_digest: HashMap<sha256::Digest, Vec<ArchivedTransactionEvents>>,
    events_by_key: BTreeMap<EventKey, Vec<ArchivedEvent>>,
}

impl FinalizedEventArchive {
    /// Create an empty finalized event archive.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a finalized event batch and update all secondary indexes.
    ///
    /// Re-inserting the exact same batch is a no-op. Reusing a height or block
    /// digest for different finalized output is rejected.
    pub fn insert(&self, batch: FinalizedEvents) -> Result<(), EventArchiveError> {
        let mut inner = self.lock()?;
        if let Some(existing) = inner.batches_by_height.get(&batch.height) {
            if existing == &batch {
                return Ok(());
            }
            return Err(EventArchiveError::HeightConflict {
                height: batch.height.get(),
            });
        }
        if let Some(height) = inner.heights_by_block.get(&batch.block_digest) {
            return Err(EventArchiveError::BlockDigestConflict {
                block_digest: batch.block_digest,
                height: height.get(),
            });
        }

        index_batch(&mut inner, &batch);
        inner
            .heights_by_block
            .insert(batch.block_digest, batch.height);
        inner.batches_by_height.insert(batch.height, batch);
        Ok(())
    }

    /// Return an archived batch by finalized height.
    pub fn batch_by_height(
        &self,
        height: Height,
    ) -> Result<Option<FinalizedEvents>, EventArchiveError> {
        Ok(self.lock()?.batches_by_height.get(&height).cloned())
    }

    /// Return an archived batch by finalized block digest.
    pub fn batch_by_block_digest(
        &self,
        block_digest: sha256::Digest,
    ) -> Result<Option<FinalizedEvents>, EventArchiveError> {
        let inner = self.lock()?;
        let Some(height) = inner.heights_by_block.get(&block_digest) else {
            return Ok(None);
        };
        Ok(inner.batches_by_height.get(height).cloned())
    }

    /// Return archived transaction event outputs matching a transaction digest.
    pub fn transactions_by_digest(
        &self,
        tx_digest: sha256::Digest,
    ) -> Result<Vec<ArchivedTransactionEvents>, EventArchiveError> {
        Ok(self
            .lock()?
            .transactions_by_digest
            .get(&tx_digest)
            .cloned()
            .unwrap_or_default())
    }

    /// Return finalized events matching an event key, ordered by height and emission position.
    pub fn events_by_key(
        &self,
        key: &EventKey,
        from_height: Option<Height>,
        limit: usize,
    ) -> Result<Vec<ArchivedEvent>, EventArchiveError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let inner = self.lock()?;
        let Some(events) = inner.events_by_key.get(key) else {
            return Ok(Vec::new());
        };
        Ok(events
            .iter()
            .filter(|event| from_height.is_none_or(|height| event.height >= height))
            .take(limit)
            .cloned()
            .collect())
    }

    /// Return finalized event batches starting at `from_height`, ordered by height.
    pub fn stream_from(
        &self,
        from_height: Height,
        limit: usize,
    ) -> Result<Vec<FinalizedEvents>, EventArchiveError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        Ok(self
            .lock()?
            .batches_by_height
            .range(from_height..)
            .take(limit)
            .map(|(_, batch)| batch.clone())
            .collect())
    }

    fn lock(&self) -> Result<MutexGuard<'_, ArchiveInner>, EventArchiveError> {
        self.inner
            .lock()
            .map_err(|_| EventArchiveError::LockPoisoned)
    }
}

impl<E> PersistentFinalizedEventArchive<E>
where
    E: BufferPooler + StorageContext,
{
    /// Open a persistent archive and rebuild its query indexes.
    pub async fn init(
        context: E,
        config: immutable::Config<EventLimits>,
    ) -> Result<Self, EventArchiveError> {
        let storage = immutable::Archive::init(context, config)
            .await
            .map_err(storage_error)?;
        let index = FinalizedEventArchive::new();
        let ranges = storage.ranges().collect::<Vec<_>>();
        for (start, end) in ranges {
            for height in start..=end {
                if let Some(batch) = storage
                    .get(Identifier::Index(height))
                    .await
                    .map_err(storage_error)?
                {
                    index.insert(batch)?;
                }
            }
        }
        Ok(Self {
            storage: Arc::new(AsyncMutex::new(storage)),
            index,
        })
    }

    /// Return the in-process query archive rebuilt from persistent storage.
    pub fn query_archive(&self) -> FinalizedEventArchive {
        self.index.clone()
    }

    /// Store a finalized batch durably and update the query index.
    pub async fn insert(&self, batch: FinalizedEvents) -> Result<(), EventArchiveError> {
        if let Some(existing) = self.index.batch_by_height(batch.height)? {
            if existing == batch {
                return Ok(());
            }
            return Err(EventArchiveError::HeightConflict {
                height: batch.height.get(),
            });
        }
        if let Some(existing) = self.index.batch_by_block_digest(batch.block_digest)? {
            return Err(EventArchiveError::BlockDigestConflict {
                block_digest: batch.block_digest,
                height: existing.height.get(),
            });
        }

        self.storage
            .lock()
            .await
            .put_sync(batch.height.get(), batch.block_digest, batch.clone())
            .await
            .map_err(storage_error)?;
        self.index.insert(batch)
    }
}

impl<E> Clone for PersistentFinalizedEventArchive<E>
where
    E: BufferPooler + StorageContext,
{
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            index: self.index.clone(),
        }
    }
}

impl<E> EventArchiveQuery for PersistentFinalizedEventArchive<E>
where
    E: BufferPooler + StorageContext + Send + Sync + 'static,
{
    fn batch_by_height(
        &self,
        height: Height,
    ) -> Result<Option<FinalizedEvents>, EventArchiveError> {
        self.index.batch_by_height(height)
    }

    fn batch_by_block_digest(
        &self,
        block_digest: sha256::Digest,
    ) -> Result<Option<FinalizedEvents>, EventArchiveError> {
        self.index.batch_by_block_digest(block_digest)
    }

    fn transactions_by_digest(
        &self,
        tx_digest: sha256::Digest,
    ) -> Result<Vec<ArchivedTransactionEvents>, EventArchiveError> {
        self.index.transactions_by_digest(tx_digest)
    }

    fn events_by_key(
        &self,
        key: &EventKey,
        from_height: Option<Height>,
        limit: usize,
    ) -> Result<Vec<ArchivedEvent>, EventArchiveError> {
        self.index.events_by_key(key, from_height, limit)
    }

    fn stream_from(
        &self,
        from_height: Height,
        limit: usize,
    ) -> Result<Vec<FinalizedEvents>, EventArchiveError> {
        self.index.stream_from(from_height, limit)
    }
}

impl<E> FinalizedEventReporter for PersistentFinalizedEventArchive<E>
where
    E: BufferPooler + StorageContext + Send + Sync + 'static,
{
    fn report(
        &self,
        events: FinalizedEvents,
    ) -> BoxFuture<'static, Result<(), FinalizedEventReportError>> {
        let archive = self.clone();
        Box::pin(async move {
            archive
                .insert(events)
                .await
                .map_err(|error| FinalizedEventReportError::new(error.to_string()))
        })
    }
}

impl EventArchiveQuery for FinalizedEventArchive {
    fn batch_by_height(
        &self,
        height: Height,
    ) -> Result<Option<FinalizedEvents>, EventArchiveError> {
        FinalizedEventArchive::batch_by_height(self, height)
    }

    fn batch_by_block_digest(
        &self,
        block_digest: sha256::Digest,
    ) -> Result<Option<FinalizedEvents>, EventArchiveError> {
        FinalizedEventArchive::batch_by_block_digest(self, block_digest)
    }

    fn transactions_by_digest(
        &self,
        tx_digest: sha256::Digest,
    ) -> Result<Vec<ArchivedTransactionEvents>, EventArchiveError> {
        FinalizedEventArchive::transactions_by_digest(self, tx_digest)
    }

    fn events_by_key(
        &self,
        key: &EventKey,
        from_height: Option<Height>,
        limit: usize,
    ) -> Result<Vec<ArchivedEvent>, EventArchiveError> {
        FinalizedEventArchive::events_by_key(self, key, from_height, limit)
    }

    fn stream_from(
        &self,
        from_height: Height,
        limit: usize,
    ) -> Result<Vec<FinalizedEvents>, EventArchiveError> {
        FinalizedEventArchive::stream_from(self, from_height, limit)
    }
}

impl FinalizedEventReporter for FinalizedEventArchive {
    fn report(
        &self,
        events: FinalizedEvents,
    ) -> BoxFuture<'static, Result<(), FinalizedEventReportError>> {
        let archive = self.clone();
        Box::pin(async move {
            archive
                .insert(events)
                .map_err(|error| FinalizedEventReportError::new(error.to_string()))
        })
    }
}

fn index_batch(inner: &mut ArchiveInner, batch: &FinalizedEvents) {
    for transaction in &batch.transactions {
        let archived_transaction = ArchivedTransactionEvents {
            height: batch.height,
            block_digest: batch.block_digest,
            block_timestamp: batch.block_timestamp,
            receipts_root: batch.receipts_root,
            receipt: transaction.receipt,
            events: transaction.events.clone(),
        };
        inner
            .transactions_by_digest
            .entry(transaction.receipt.tx_digest)
            .or_default()
            .push(archived_transaction);

        for (event_index, event) in transaction.events.iter().enumerate() {
            let archived_event = ArchivedEvent {
                height: batch.height,
                block_digest: batch.block_digest,
                block_timestamp: batch.block_timestamp,
                receipts_root: batch.receipts_root,
                tx_index: transaction.receipt.tx_index,
                tx_digest: transaction.receipt.tx_digest,
                event_index: event_index as u32,
                event: event.clone(),
            };
            for attribute in &event.attributes {
                let key = EventKey::new(
                    event.module.clone(),
                    event.kind.clone(),
                    event.version,
                    attribute.key.clone(),
                );
                inner
                    .events_by_key
                    .entry(key)
                    .or_default()
                    .push(archived_event.clone());
            }
        }
    }
}

fn storage_error(error: commonware_storage::archive::Error) -> EventArchiveError {
    EventArchiveError::Storage(error.to_string())
}
