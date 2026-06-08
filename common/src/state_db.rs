//! Shared, authenticated key-value state backing every Nunchi module.
//!
//! A single physical [`commonware_storage::qmdb`] authenticated database holds the state for *all*
//! modules. Each module is handed a [`Namespace`] that deterministically maps its logical keys into
//! a disjoint region of the shared digest keyspace, so modules can extend the same backend without
//! colliding. Because the backend is authenticated, [`StateDb::root`] is a succinct commitment to
//! the entire cross-module state.
//!
//! Modules never touch the raw backend directly. They program against the [`StateDb`] trait and
//! layer their own typed accessors on top (see `nunchi-coins`' `LedgerDB` for an example).

use std::future::Future;
use std::{collections::BTreeMap, sync::Arc};

use commonware_codec::Read;
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_glue::stateful::db::{
    any::{AnyMerkleized, AnyUnmerkleized},
    Unmerkleized as _,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, BufferPooler};
use commonware_storage::{
    index::unordered::Index as UnorderedIndex,
    journal::contiguous::variable::Config as JournalConfig,
    journal::contiguous::variable::Journal as VariableJournal,
    merkle::{full::Config as MerkleConfig, Location},
    mmr::Family,
    qmdb::{
        any::{
            unordered::variable::{Db as AnyDb, Operation as AnyOperation, Update as AnyUpdate},
            VariableConfig,
        },
        Error as QmdbError,
    },
    translator::TwoCap,
    Context,
};
use commonware_utils::{sync::AsyncRwLock, NZUsize, NZU16, NZU64};
use thiserror::Error;

/// Errors surfaced by the shared state backend.
#[derive(Debug, Error)]
pub enum StateError {
    /// A failure originating from the underlying authenticated storage.
    #[error("state backend error: {0}")]
    Backend(String),
}

/// A deterministic, collision-resistant view into the shared keyspace owned by a single module.
///
/// Modules declare a stable namespace tag (typically their signing domain separator) and a small
/// `table` discriminant per logical map. Keys are length-prefixed before hashing so that distinct
/// `(tag, table, logical)` triples can never alias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Namespace {
    tag: &'static [u8],
}

impl Namespace {
    /// Create a namespace from a stable, module-unique tag.
    pub const fn new(tag: &'static [u8]) -> Self {
        Self { tag }
    }

    /// Derive the physical storage key for a logical entry within `table`.
    ///
    /// `table` discriminates the module's logical maps so two maps with same-shaped keys (e.g. a
    /// 32-byte account id vs. a 32-byte coin id) land in disjoint sub-keyspaces. Modules typically
    /// pass a `#[repr(u8)]` enum here.
    pub fn key(&self, table: impl Into<u8>, logical: &[u8]) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(&(self.tag.len() as u32).to_be_bytes());
        hasher.update(self.tag);
        hasher.update(&[table.into()]);
        hasher.update(logical);
        hasher.finalize()
    }
}

/// Namespaced read/write access shared across modules.
///
/// Reads observe staged writes (read-your-writes) so a module can apply a multi-step operation
/// before either committing a direct database or merkleizing a speculative batch.
pub trait StateStore {
    /// Read the committed-or-staged value for `key`.
    fn get(&self, key: &Digest)
        -> impl Future<Output = Result<Option<Vec<u8>>, StateError>> + Send;

    /// Stage an upsert. Visible to subsequent [`StateStore::get`] calls.
    fn set(&mut self, key: Digest, value: Vec<u8>);

    /// Stage a deletion. Visible to subsequent [`StateStore::get`] calls.
    fn remove(&mut self, key: Digest);
}

/// Directly committed authenticated state.
pub trait CommitState {
    /// Flush all staged writes, returning the new authenticated state root.
    fn commit(&mut self) -> impl Future<Output = Result<Digest, StateError>> + Send;

    /// The most recently committed authenticated state root.
    fn root(&self) -> Digest;
}

/// An authenticated, namespaced key-value store shared across modules.
pub trait StateDb: StateStore + CommitState {}

impl<T: StateStore + CommitState> StateDb for T {}

/// The concrete authenticated backend: an unordered, variable-value QMDB keyed by SHA-256 digests.
pub type QmdbBackend<E> = AnyDb<Family, E, Digest, Vec<u8>, Sha256, TwoCap, Sequential>;
pub type QmdbOperation = AnyOperation<Family, Digest, Vec<u8>>;
pub type QmdbUpdate = AnyUpdate<Digest, Vec<u8>>;
pub type QmdbJournal<E> = VariableJournal<E, QmdbOperation>;
pub type QmdbIndex = UnorderedIndex<TwoCap, Location<Family>>;
pub type QmdbConfig = VariableConfig<TwoCap, <QmdbOperation as Read>::Cfg, Sequential>;
pub type QmdbDatabaseSet<E> = Arc<AsyncRwLock<QmdbBackend<E>>>;
pub type QmdbUnmerkleized<E> =
    AnyUnmerkleized<Family, E, QmdbJournal<E>, QmdbIndex, Sha256, QmdbUpdate, Sequential>;
pub type QmdbMerkleized<E> =
    AnyMerkleized<Family, E, QmdbJournal<E>, QmdbIndex, Sha256, QmdbUpdate, Sequential>;

fn backend_err(err: QmdbError<Family>) -> StateError {
    StateError::Backend(err.to_string())
}

/// A [`StateDb`] backed by a [`commonware_storage::qmdb`] authenticated database.
///
/// One instance is shared by every module in a node; namespacing keeps their data disjoint.
pub struct QmdbState<E: Context> {
    db: QmdbBackend<E>,
    overlay: BTreeMap<Digest, Option<Vec<u8>>>,
    root: Digest,
}

impl<E: Context + BufferPooler> QmdbState<E> {
    /// Build the QMDB configuration used by direct and stateful state backends.
    pub fn config(context: &E, partition: &str) -> QmdbConfig {
        let page_cache = CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(1024));
        Self::config_with_page_cache(partition, page_cache)
    }

    /// Build the QMDB configuration with a caller-provided page cache.
    pub fn config_with_page_cache(partition: &str, page_cache: CacheRef) -> QmdbConfig {
        VariableConfig {
            merkle_config: MerkleConfig {
                journal_partition: format!("{partition}-merkle-journal"),
                metadata_partition: format!("{partition}-merkle-metadata"),
                items_per_blob: NZU64!(4096),
                write_buffer: NZUsize!(65536),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: JournalConfig {
                partition: format!("{partition}-log-journal"),
                items_per_section: NZU64!(4096),
                compression: None,
                codec_config: ((), (commonware_codec::RangeCfg::from(..), ())),
                page_cache,
                write_buffer: NZUsize!(65536),
            },
            translator: TwoCap,
        }
    }

    /// Open (or recover) the shared store. `partition` namespaces the on-disk storage partitions so
    /// multiple independent stores can coexist within one runtime (e.g. across tests).
    pub async fn init(context: E, partition: &str) -> Result<Self, StateError> {
        let cfg = Self::config(&context, partition);
        let db = QmdbBackend::init(context, cfg).await.map_err(backend_err)?;
        let root = db.root();
        Ok(Self {
            db,
            overlay: BTreeMap::new(),
            root,
        })
    }
}

impl<E: Context> StateStore for QmdbState<E> {
    async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(staged) = self.overlay.get(key) {
            return Ok(staged.clone());
        }
        self.db.get(key).await.map_err(backend_err)
    }

    fn set(&mut self, key: Digest, value: Vec<u8>) {
        self.overlay.insert(key, Some(value));
    }

    fn remove(&mut self, key: Digest) {
        self.overlay.insert(key, None);
    }
}

impl<E: Context> CommitState for QmdbState<E> {
    async fn commit(&mut self) -> Result<Digest, StateError> {
        if !self.overlay.is_empty() {
            let mut batch = self.db.new_batch();
            for (key, value) in std::mem::take(&mut self.overlay) {
                batch = batch.write(key, value);
            }
            let merkleized = batch.merkleize(&self.db, None).await.map_err(backend_err)?;
            self.db.apply_batch(merkleized).await.map_err(backend_err)?;
        }
        self.db.commit().await.map_err(backend_err)?;
        self.root = self.db.root();
        Ok(self.root)
    }

    fn root(&self) -> Digest {
        self.root
    }
}

/// A speculative QMDB batch used by `commonware_glue::stateful` execution.
pub struct QmdbBatch<E: Context> {
    inner: Option<QmdbUnmerkleized<E>>,
}

impl<E: Context> QmdbBatch<E> {
    pub fn new(inner: QmdbUnmerkleized<E>) -> Self {
        Self { inner: Some(inner) }
    }

    pub async fn merkleize(mut self) -> Result<QmdbMerkleized<E>, StateError> {
        self.inner
            .take()
            .expect("QMDB batch already consumed")
            .merkleize()
            .await
            .map_err(backend_err)
    }

    fn inner(&self) -> &QmdbUnmerkleized<E> {
        self.inner.as_ref().expect("QMDB batch already consumed")
    }

    fn replace(&mut self, next: QmdbUnmerkleized<E>) {
        self.inner = Some(next);
    }
}

impl<E: Context> StateStore for QmdbBatch<E> {
    async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
        self.inner().get(key).await.map_err(backend_err)
    }

    fn set(&mut self, key: Digest, value: Vec<u8>) {
        let inner = self.inner.take().expect("QMDB batch already consumed");
        self.replace(inner.write(key, Some(value)));
    }

    fn remove(&mut self, key: Digest) {
        let inner = self.inner.take().expect("QMDB batch already consumed");
        self.replace(inner.write(key, None));
    }
}

/// Read-only access to a QMDB database set owned by a `Stateful` actor.
#[derive(Clone)]
pub struct QmdbReader<E: Context> {
    db: QmdbDatabaseSet<E>,
}

impl<E: Context> QmdbReader<E> {
    pub fn new(db: QmdbDatabaseSet<E>) -> Self {
        Self { db }
    }

    pub async fn root(&self) -> Digest {
        self.db.read().await.root()
    }
}

impl<E: Context> StateStore for QmdbReader<E> {
    async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
        self.db.read().await.get(key).await.map_err(backend_err)
    }

    fn set(&mut self, _key: Digest, _value: Vec<u8>) {
        panic!("QmdbReader is read-only");
    }

    fn remove(&mut self, _key: Digest) {
        panic!("QmdbReader is read-only");
    }
}
