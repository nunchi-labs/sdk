//! Shared, authenticated key-value state backing every Nunchi module.
//!
//! A single physical [`commonware_storage::qmdb`] authenticated database holds the state for *all*
//! modules. Each module is handed a [`Namespace`] that deterministically maps its logical keys into
//! a disjoint region of the shared digest keyspace, so modules can extend the same backend without
//! colliding. Because the backend is authenticated, [`CommitState::root`] is a succinct commitment to
//! the entire cross-module state.
//!
//! Modules never touch the raw backend directly. They program against the [`StateDb`] trait and
//! layer their own typed accessors on top (see `nunchi-coins`' `LedgerDB` for an example).

use std::future::Future;
use std::num::NonZeroU64;
use std::{collections::BTreeMap, sync::Arc};

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_glue::stateful::db::{
    any::{AnyMerkleized, AnyUnmerkleized},
    ManagedDb as _, Shared, Unmerkleized as _,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, BufferPooler};
use commonware_storage::{
    index::unordered::Index as UnorderedIndex,
    journal::contiguous::variable::Config as JournalConfig,
    journal::contiguous::variable::Journal as VariableJournal,
    merkle::{full::Config as MerkleConfig, Location, Proof},
    mmr::Family,
    qmdb::{
        any::{
            unordered::variable::{Db as AnyDb, Operation as AnyOperation, Update as AnyUpdate},
            VariableConfig,
        },
        sync::Target,
        verify_proof, Error as QmdbError,
    },
    translator::TwoCap,
    Context,
};
use commonware_utils::{sync::TracedAsyncRwLock, NZUsize, NZU16, NZU64};
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

impl<T: StateStore + Send + Sync + ?Sized> StateStore for &mut T {
    async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
        (**self).get(key).await
    }

    fn set(&mut self, key: Digest, value: Vec<u8>) {
        (**self).set(key, value);
    }

    fn remove(&mut self, key: Digest) {
        (**self).remove(key);
    }
}

impl<T: CommitState + Send + ?Sized> CommitState for &mut T {
    async fn commit(&mut self) -> Result<Digest, StateError> {
        (**self).commit().await
    }

    fn root(&self) -> Digest {
        (**self).root()
    }
}

/// The concrete authenticated backend: an unordered, variable-value QMDB keyed by SHA-256 digests.
pub type QmdbBackend<E> = AnyDb<Family, E, Digest, Vec<u8>, Sha256, TwoCap, Sequential>;
pub type QmdbOperation = AnyOperation<Family, Digest, Vec<u8>>;
pub type QmdbUpdate = AnyUpdate<Digest, Vec<u8>>;
pub type QmdbJournal<E> = VariableJournal<E, QmdbOperation>;
pub type QmdbIndex = UnorderedIndex<TwoCap, Location<Family>>;
pub type QmdbConfig = VariableConfig<TwoCap, <QmdbOperation as Read>::Cfg, Sequential>;
pub type QmdbDatabaseSet<E> = Shared<QmdbBackend<E>>;

/// Wrap an opened backend in the shared lock type expected by `commonware-glue`.
pub fn shared_database<E: Context>(db: QmdbBackend<E>) -> QmdbDatabaseSet<E> {
    Arc::new(TracedAsyncRwLock::new("stateful.db", db))
}
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
            // Bounded location-to-key cache during snapshot rebuild on open/recovery.
            // Matches commonware's sync examples (`1 << 16`).
            init_cache_size: Some(NZUsize!(1 << 16)),
        }
    }

    /// Open (or recover) the shared store. `partition` namespaces the on-disk storage partitions so
    /// multiple independent stores can coexist within one runtime (e.g. across tests).
    pub async fn init(context: E, partition: &str) -> Result<Self, StateError> {
        let cfg = Self::config(&context, partition);
        Self::init_with_config(context, cfg).await
    }

    /// Open (or recover) the shared store with a caller-provided QMDB config.
    pub async fn init_with_config(context: E, cfg: QmdbConfig) -> Result<Self, StateError> {
        let db = QmdbBackend::init(context, cfg).await.map_err(backend_err)?;
        let root = db.root();
        Ok(Self {
            db,
            overlay: BTreeMap::new(),
            root,
        })
    }

    /// Return the committed sync target for the underlying authenticated database.
    pub fn sync_target(&self) -> Target<Family, Digest> {
        self.db.sync_target()
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
            // Stage the write-set keys so merkleize reuses locations resolved at read time
            // instead of re-probing the index for each mutation.
            let overlay = std::mem::take(&mut self.overlay);
            let keys: Vec<Digest> = overlay.keys().copied().collect();
            let key_refs: Vec<&Digest> = keys.iter().collect();
            let (_values, staged) = self
                .db
                .new_batch()
                .stage(&key_refs, &self.db)
                .await
                .map_err(backend_err)?;
            let updates: Vec<(usize, Option<Vec<u8>>)> = keys
                .iter()
                .enumerate()
                .map(|(i, key)| (i, overlay[key].clone()))
                .collect();
            let merkleized = staged
                .merkleize(updates, Vec::new(), None, &self.db)
                .await
                .map_err(backend_err)?;
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

/// An inclusion proof over a contiguous range of authenticated operations, verifiable against a
/// committed [`CommitState::root`].
///
/// This is the low-level proof surface: it authenticates that a set of QMDB operations is committed
/// under a given root, and [`StateProof::operations`] exposes those operations so a verifier can
/// confirm a specific key/value is among them (see [`verify_state_update`]). Proofs can be generated
/// against the latest committed root ([`QmdbState::proof`]) or a historical finalized root such as a
/// foreign block's state root ([`QmdbState::historical_proof`]). Targeting a single key directly
/// (key -> operation location) is still a follow-up, not covered here.
pub struct StateProof {
    proof: Proof<Family, Digest>,
    start: Location<Family>,
    operations: Vec<QmdbOperation>,
}

impl StateProof {
    /// The authenticated operations covered by this proof.
    pub fn operations(&self) -> &[QmdbOperation] {
        &self.operations
    }

    /// The operation location the proof starts at. Together with [`StateProof::operations`] this
    /// gives the operation range the proof authenticates, so a caller can check the range lines up
    /// with a finalized block's state range.
    pub fn start(&self) -> Location<Family> {
        self.start
    }
}

impl<E: Context> QmdbState<E> {
    /// The active operation range in the committed authenticated log.
    pub fn operation_bounds(&self) -> std::ops::Range<Location<Family>> {
        self.db.bounds()
    }

    /// Generate an inclusion proof for up to `max_ops` operations starting at `start`, verifiable
    /// against the committed [`CommitState::root`] with [`verify_state_proof`].
    pub async fn proof(
        &self,
        start: Location<Family>,
        max_ops: NonZeroU64,
    ) -> Result<StateProof, StateError> {
        let (proof, operations) = self.db.proof(start, max_ops).await.map_err(backend_err)?;
        Ok(StateProof {
            proof,
            start,
            operations,
        })
    }

    /// Generate an inclusion proof against a historical root instead of the latest committed one.
    ///
    /// `historical_size` is the total operation count of the log at the point the historical root
    /// was produced; it selects which past state the proof is verified against. Callers must take
    /// it from the finalized block (or state commitment) whose root they intend to verify against,
    /// for example the `state_range` end of a foreign block; passing a mismatched size yields a
    /// proof that will not verify. The returned proof is checked with [`verify_state_proof`] (or
    /// [`verify_state_update`]) against that block's `state_root`.
    pub async fn historical_proof(
        &self,
        historical_size: Location<Family>,
        start: Location<Family>,
        max_ops: NonZeroU64,
    ) -> Result<StateProof, StateError> {
        let (proof, operations) = self
            .db
            .historical_proof(historical_size, start, max_ops)
            .await
            .map_err(backend_err)?;
        Ok(StateProof {
            proof,
            start,
            operations,
        })
    }
}

/// Verify that the operations in `proof` are committed by the authenticated state `root`.
///
/// Standalone (no database handle), so a remote verifier can check a proof against a state root it
/// obtained elsewhere (for example a finalized foreign block).
pub fn verify_state_proof(proof: &StateProof, root: &Digest) -> bool {
    verify_proof::<Sha256, Family, QmdbOperation>(
        &proof.proof,
        proof.start,
        &proof.operations,
        root,
    )
}

/// Verify that `proof` is committed by `root` and authenticates an update writing `value` to `key`.
///
/// This checks that the exact `key`/`value` write appears among the proof's authenticated
/// operations. It proves operation membership, not latest-value semantics: a later update to the
/// same key is not ruled out, so this only establishes that the write happened at some point in the
/// authenticated history. That is sufficient for append-only or content-addressed records (such as
/// bridge transfer records keyed by the hash of their contents), where a key is written at most
/// once and never overwritten.
pub fn verify_state_update(proof: &StateProof, root: &Digest, key: &Digest, value: &[u8]) -> bool {
    verify_state_proof(proof, root)
        && proof.operations.iter().any(|op| match op {
            QmdbOperation::Update(update) => &update.0 == key && update.1.as_slice() == value,
            _ => false,
        })
}

/// Decoding limits for [`StateProof`], bounding attacker-controlled allocation when a proof is read
/// off the wire.
///
/// A [`StateProof`] is otherwise self-describing, but its length-prefixed vectors (proof digests,
/// operations, operation values) must be capped so a malicious sender cannot force an unbounded
/// allocation. Callers pick bounds appropriate for the message that carries the proof.
#[derive(Clone, Copy, Debug)]
pub struct StateProofCfg {
    /// Maximum number of internal Merkle digests accepted in the proof.
    pub max_proof_digests: usize,
    /// Accepted range for the number of operations the proof carries.
    pub operations: RangeCfg<usize>,
    /// Accepted range for the byte length of each operation's value.
    pub value_len: RangeCfg<usize>,
}

impl Write for StateProof {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.start.write(buf);
        self.operations.write(buf);
    }
}

impl EncodeSize for StateProof {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.start.encode_size() + self.operations.encode_size()
    }
}

impl Read for StateProof {
    type Cfg = StateProofCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let proof = Proof::<Family, Digest>::read_cfg(buf, &cfg.max_proof_digests)?;
        let start = Location::<Family>::read_cfg(buf, &())?;
        // Operation cfg mirrors the unordered/variable layout: key cfg is `()`, value cfg is the
        // byte-length range; the outer range caps the number of operations.
        let operation_cfg = ((), (cfg.value_len, ()));
        let operations = Vec::<QmdbOperation>::read_cfg(buf, &(cfg.operations, operation_cfg))?;
        Ok(StateProof {
            proof,
            start,
            operations,
        })
    }
}

/// A speculative QMDB batch used by `commonware_glue::stateful` execution.
///
/// Mutations accumulate in [`QmdbBatch::pending`] so [`QmdbBatch::merkleize`] can use the
/// staged read-then-write path (location reuse) instead of write-then-merkleize.
pub struct QmdbBatch<E: Context> {
    inner: Option<QmdbUnmerkleized<E>>,
    pending: BTreeMap<Digest, Option<Vec<u8>>>,
}

impl<E: Context> QmdbBatch<E> {
    pub fn new(inner: QmdbUnmerkleized<E>) -> Self {
        Self {
            inner: Some(inner),
            pending: BTreeMap::new(),
        }
    }

    pub async fn merkleize(mut self) -> Result<QmdbMerkleized<E>, StateError> {
        let batch = self.inner.take().expect("QMDB batch already consumed");
        if self.pending.is_empty() {
            return batch.merkleize().await.map_err(backend_err);
        }
        let pending = std::mem::take(&mut self.pending);
        let keys: Vec<Digest> = pending.keys().copied().collect();
        let key_refs: Vec<&Digest> = keys.iter().collect();
        let (_values, staged) = batch.stage(&key_refs).await.map_err(backend_err)?;
        let updates: Vec<(usize, Option<Vec<u8>>)> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| (i, pending[key].clone()))
            .collect();
        staged
            .merkleize(updates, Vec::new())
            .await
            .map_err(backend_err)
    }

    fn inner(&self) -> &QmdbUnmerkleized<E> {
        self.inner.as_ref().expect("QMDB batch already consumed")
    }
}

impl<E: Context> StateStore for QmdbBatch<E> {
    async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(staged) = self.pending.get(key) {
            return Ok(staged.clone());
        }
        self.inner().get(key).await.map_err(backend_err)
    }

    fn set(&mut self, key: Digest, value: Vec<u8>) {
        self.pending.insert(key, Some(value));
    }

    fn remove(&mut self, key: Digest) {
        self.pending.insert(key, None);
    }
}

/// Stages writes in memory over a borrowed [`StateStore`], folding them into the underlying
/// store only on [`Overlay::commit`].
///
/// Dropping an overlay discards its staged writes, so a multi-step operation that fails partway
/// through leaves the underlying store untouched.
pub struct Overlay<'a, S> {
    inner: &'a mut S,
    staged: BTreeMap<Digest, Option<Vec<u8>>>,
}

impl<'a, S: StateStore> Overlay<'a, S> {
    pub fn new(inner: &'a mut S) -> Self {
        Self {
            inner,
            staged: BTreeMap::new(),
        }
    }

    /// Fold the staged writes into the underlying store.
    pub fn commit(self) {
        let Self { inner, staged } = self;
        for (key, value) in staged {
            match value {
                Some(value) => inner.set(key, value),
                None => inner.remove(key),
            }
        }
    }
}

impl<S: StateStore + Sync> StateStore for Overlay<'_, S> {
    async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(staged) = self.staged.get(key) {
            return Ok(staged.clone());
        }
        self.inner.get(key).await
    }

    fn set(&mut self, key: Digest, value: Vec<u8>) {
        self.staged.insert(key, Some(value));
    }

    fn remove(&mut self, key: Digest) {
        self.staged.insert(key, None);
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
