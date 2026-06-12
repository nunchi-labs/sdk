use crate::application::Application;
use crate::execution::NodeHandle;
use crate::{
    Block, EpochProvider, Finalization, Provider, PublicKey, Scheme, StateCommitment,
    BLOCKS_PER_EPOCH, NAMESPACE,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    marshal::{
        self,
        core::Actor as MarshalActor,
        resolver,
        standard::{Deferred, Standard},
        Update,
    },
    simplex::elector::Random,
    types::{FixedEpocher, Height, ViewDelta},
    Reporters,
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::Output,
        primitives::{group, variant::MinSig},
    },
    certificate::Scheme as _,
    ed25519::{self, Batch},
    sha256::Digest,
    BatchVerifier, Digestible, Signer,
};
use commonware_glue::stateful::{
    db::{AttachableResolver, ManagedDb as _, SyncEngineConfig},
    Config as StatefulConfig, Mailbox as StatefulMailbox, Stateful as StatefulActor, SyncPlan,
};
use commonware_p2p::{Blocker, Manager, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef, spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics,
    Network, Spawner, Storage, ThreadPooler,
};
use commonware_storage::archive::immutable;
use commonware_utils::{channel::oneshot, sync::AsyncRwLock, union, NZUsize, NZU16, NZU64};
use futures::{future::try_join_all, lock::Mutex as AsyncMutex};
use governor::clock::Clock as GClock;
use nunchi_coins::Transaction;
use nunchi_common::{QmdbBackend, QmdbOperation, QmdbState};
use nunchi_dkg::{self as dkg, orchestrator, PeerConfig, UpdateCallBack, MAX_SUPPORTED_MODE};
use nunchi_mempool::{Mempool, PoolConfig};
use rand::{CryptoRng, Rng};
use rand_core::CryptoRngCore;
use std::{
    future::Future,
    marker::PhantomData,
    num::{NonZero, NonZeroU16, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{error, info, warn};

const MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
const DEQUE_SIZE: usize = 10;
const ACTIVITY_TIMEOUT: ViewDelta = ViewDelta::new(256);
const SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER: u64 = 10;
const PRUNABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(4_096);
const IMMUTABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(262_144);
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 3MB
const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_VALUE_COMPRESSION: Option<u8> = Some(3);
const REPLAY_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024); // 8MB
const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024); // 1MB
const PAGE_CACHE_PAGE_SIZE: NonZeroU16 = NZU16!(4_096); // 4KB
const PAGE_CACHE_CAPACITY: NonZero<usize> = NZUsize!(8_192); // 32MB
const MAX_REPAIR: NonZero<usize> = NZUsize!(50);
const MAX_PENDING_ACKS: NonZero<usize> = NZUsize!(16);
const STATE_SYNC_FETCH_BATCH_SIZE: NonZero<u64> = NZU64!(1_024);
const STATE_SYNC_APPLY_BATCH_SIZE: usize = 4_096;
const STATE_SYNC_MAX_OUTSTANDING_REQUESTS: usize = 8;
const STATE_SYNC_UPDATE_CHANNEL_SIZE: NonZero<usize> = NZUsize!(256);
const STATE_SYNC_MAX_RETAINED_ROOTS: usize = 32;

/// Configuration for the [Engine].
pub struct Config<B: Blocker<PublicKey = PublicKey>, P: Manager<PublicKey = PublicKey>, S: Strategy>
{
    pub blocker: B,
    pub manager: P,
    pub partition_prefix: String,
    pub blocks_freezer_table_initial_size: u32,
    pub finalized_freezer_table_initial_size: u32,
    pub signer: ed25519::PrivateKey,
    pub output: Output<MinSig, PublicKey>,
    pub share: Option<group::Share>,
    pub peer_config: PeerConfig<PublicKey>,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub strategy: S,
    pub max_block_transactions: usize,
    pub pool_config: PoolConfig,
}

type DkgActor<E, P> = dkg::Actor<E, P, Block>;
type DkgMailbox = dkg::Mailbox<Block>;
type StatefulApp<E> = StatefulActor<E, Application, Scheme, Standard<Block>, NoStateSyncResolver>;
type StatefulAppMailbox<E> = StatefulMailbox<E, Application>;
type Marshaled<E> = Deferred<E, Scheme, StatefulAppMailbox<E>, Block, FixedEpocher>;
type SchemeProvider = Provider<Scheme, ed25519::PrivateKey>;
type FinalizationsArchive<E> = immutable::Archive<E, Digest, Finalization>;
type BlocksArchive<E> = immutable::Archive<E, Digest, Block>;
type Marshal<E, S> = MarshalActor<
    E,
    Standard<Block>,
    SchemeProvider,
    FinalizationsArchive<E>,
    BlocksArchive<E>,
    FixedEpocher,
    S,
>;
type Orchestrator<E, B, S> = orchestrator::Actor<E, B, Marshaled<E>, Scheme, Random, S, Block>;

/// The engine that drives the coins-chain [Application].
#[allow(clippy::type_complexity)]
pub struct Engine<E, B, P, S>
where
    E: BufferPooler
        + Spawner
        + Metrics
        + CryptoRngCore
        + CryptoRng
        + Rng
        + Clock
        + GClock
        + Storage
        + ThreadPooler
        + Network,
    B: Blocker<PublicKey = PublicKey>,
    P: Manager<PublicKey = PublicKey>,
    S: Strategy,
{
    context: ContextCell<E>,
    config: Config<B, P, S>,
    dkg: DkgActor<E, P>,
    dkg_mailbox: DkgMailbox,
    buffer: buffered::Engine<E, PublicKey, Block, P>,
    buffered_mailbox: buffered::Mailbox<PublicKey, Block>,
    marshal: Marshal<E, S>,
    orchestrator: Orchestrator<E, B, S>,
    orchestrator_mailbox: orchestrator::Mailbox<MinSig, PublicKey>,
    mempool: Handle<()>,
    stateful: StatefulApp<E>,
    stateful_mailbox: StatefulAppMailbox<E>,
}

/// Placeholder for the peer state-sync resolver.
///
/// `commonware_glue::stateful::db::p2p::standard::Actor` would slot in here, but as of
/// commonware 2026.5.0 it requires `Op: Codec<Cfg = ()>`, which only fixed-encoding QMDB
/// operations satisfy; the shared state database is variable-value (`Vec<u8>`), whose
/// operation codec config is `((), (RangeCfg, ()))`. Until upstream threads the codec config
/// through its resolver (or this chain moves to fixed-size values), peer state sync stays
/// disabled: no startup path attaches a state-sync floor, so every node recovers exclusively
/// via marshal backfill and this resolver is never asked to fetch.
#[derive(Clone, Copy, Debug, Default)]
struct NoStateSyncResolver;

#[derive(Debug, thiserror::Error)]
#[error("peer state sync resolver is not configured")]
struct NoStateSyncError;

impl<E> AttachableResolver<QmdbBackend<E>> for NoStateSyncResolver
where
    E: commonware_storage::Context + Send + Sync + 'static,
{
    fn attach_database(
        &self,
        _db: Arc<AsyncRwLock<QmdbBackend<E>>>,
    ) -> impl Future<Output = ()> + Send {
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

impl<E, B, P, S> Engine<E, B, P, S>
where
    E: BufferPooler
        + Spawner
        + Metrics
        + CryptoRngCore
        + CryptoRng
        + Rng
        + Clock
        + GClock
        + Storage
        + ThreadPooler
        + Network
        + Send
        + 'static,
    B: Blocker<PublicKey = PublicKey>,
    P: Manager<PublicKey = PublicKey>,
    S: Strategy,
    Batch: BatchVerifier<PublicKey = PublicKey>,
{
    /// Create a new [Engine].
    pub async fn new(context: E, config: Config<B, P, S>) -> (Self, NodeHandle<E>) {
        let (mempool, submitter) = Mempool::<Transaction>::new(config.pool_config.clone());
        let mempool = mempool.start(context.child("mempool"));

        let page_cache = CacheRef::from_pooler(&context, PAGE_CACHE_PAGE_SIZE, PAGE_CACHE_CAPACITY);
        let consensus_namespace = union(NAMESPACE, b"_CONSENSUS");
        let num_participants =
            commonware_utils::NZU32!(config.peer_config.max_participants_per_round());

        let (dkg, dkg_mailbox) = dkg::Actor::new(
            context.child("dkg"),
            dkg::Config {
                manager: config.manager.clone(),
                signer: config.signer.clone(),
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: config.partition_prefix.clone(),
                peer_config: config.peer_config.clone(),
                max_supported_mode: MAX_SUPPORTED_MODE,
                namespace: NAMESPACE.to_vec(),
                epoch_length: BLOCKS_PER_EPOCH,
            },
        );

        let (buffer, buffered_mailbox) = buffered::Engine::new(
            context.child("buffer"),
            buffered::Config {
                public_key: config.signer.public_key(),
                mailbox_size: MAILBOX_SIZE,
                deque_size: DEQUE_SIZE,
                priority: true,
                codec_config: num_participants,
                peer_provider: config.manager.clone(),
            },
        );

        let start = Instant::now();
        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalizations-by-height-metadata",
                    config.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalizations-by-height-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: config.finalized_freezer_table_initial_size,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_key_partition: format!(
                    "{}-finalizations-by-height-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: page_cache.clone(),
                freezer_key_write_buffer: WRITE_BUFFER,
                freezer_value_partition: format!(
                    "{}-finalizations-by-height-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_write_buffer: WRITE_BUFFER,
                freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
                freezer_value_compression: FREEZER_VALUE_COMPRESSION,
                ordinal_partition: format!(
                    "{}-finalizations-by-height-ordinal",
                    config.partition_prefix
                ),
                ordinal_write_buffer: WRITE_BUFFER,
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: Scheme::certificate_codec_config_unbounded(),
                replay_buffer: REPLAY_BUFFER,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");
        info!(elapsed = ?start.elapsed(), "restored finalizations by height archive");

        let start = Instant::now();
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalized_blocks-metadata",
                    config.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalized_blocks-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: config.blocks_freezer_table_initial_size,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_key_partition: format!(
                    "{}-finalized_blocks-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: page_cache.clone(),
                freezer_key_write_buffer: WRITE_BUFFER,
                freezer_value_partition: format!(
                    "{}-finalized_blocks-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_write_buffer: WRITE_BUFFER,
                freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
                freezer_value_compression: FREEZER_VALUE_COMPRESSION,
                ordinal_partition: format!("{}-finalized_blocks-ordinal", config.partition_prefix),
                ordinal_write_buffer: WRITE_BUFFER,
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: num_participants,
                replay_buffer: REPLAY_BUFFER,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

        let certificate_verifier = <SchemeProvider as EpochProvider>::certificate_verifier(
            &consensus_namespace,
            &config.output,
        );
        let provider = Provider::new(
            consensus_namespace.clone(),
            config.signer.clone(),
            certificate_verifier,
        );
        // The genesis block commits to the root of an empty state database. Derive it from a
        // dedicated, never-written partition (rather than hardcoding the digest) so it stays
        // correct across QMDB versions and is identical on fresh boots and restarts alike.
        let genesis_state = {
            let empty = QmdbBackend::init(
                context.child("genesis_state"),
                QmdbState::<E>::config_with_page_cache(
                    &format!("{}-genesis-coins", config.partition_prefix),
                    page_cache.clone(),
                ),
            )
            .await
            .expect("failed to initialize empty state database for genesis commitment");
            let target = empty.sync_target().await;
            StateCommitment {
                root: target.root,
                range: target.range,
            }
        };
        let applied_height = Arc::new(AsyncMutex::new(Height::zero()));
        let app = Application::with_dkg(
            submitter.clone(),
            config.max_block_transactions,
            dkg_mailbox.clone(),
            applied_height.clone(),
            genesis_state,
        );
        let genesis = app.genesis_block();
        let genesis_digest = genesis.digest();
        // The sync plan drives both marshal (its startup anchor below) and the stateful actor
        // (via `StatefulConfig::plan`), so the two always agree on the startup decision. No
        // finalized floor is ever attached here, so nodes recover via marshal backfill.
        let plan =
            SyncPlan::<_, Scheme, Standard<Block>>::init(&context, config.partition_prefix.clone())
                .await;
        let (marshal, marshal_mailbox, _processed_height) = MarshalActor::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: provider.clone(),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                start: plan.marshal_start(genesis),
                partition_prefix: format!("{}_marshal", config.partition_prefix),
                mailbox_size: MAILBOX_SIZE,
                view_retention_timeout: ViewDelta::new(
                    ACTIVITY_TIMEOUT
                        .get()
                        .saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
                ),
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                page_cache: page_cache.clone(),
                replay_buffer: REPLAY_BUFFER,
                key_write_buffer: WRITE_BUFFER,
                value_write_buffer: WRITE_BUFFER,
                block_codec_config: num_participants,
                max_repair: MAX_REPAIR,
                max_pending_acks: MAX_PENDING_ACKS,
                strategy: config.strategy.clone(),
            },
        )
        .await;

        let db_config = QmdbState::<E>::config_with_page_cache(
            &format!("{}-coins", config.partition_prefix),
            page_cache,
        );
        let (stateful, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application: app,
                db_config,
                input_provider: submitter.clone(),
                marshal: marshal_mailbox.clone(),
                max_pending_acks: MAX_PENDING_ACKS,
                mailbox_size: MAILBOX_SIZE,
                plan,
                resolvers: NoStateSyncResolver,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: STATE_SYNC_FETCH_BATCH_SIZE,
                    apply_batch_size: STATE_SYNC_APPLY_BATCH_SIZE,
                    max_outstanding_requests: STATE_SYNC_MAX_OUTSTANDING_REQUESTS,
                    update_channel_size: STATE_SYNC_UPDATE_CHANNEL_SIZE,
                    max_retained_roots: STATE_SYNC_MAX_RETAINED_ROOTS,
                },
            },
        );
        let node_handle = NodeHandle::new(submitter, stateful_mailbox.clone(), applied_height);

        let application = Deferred::new(
            context.child("application"),
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            FixedEpocher::new(BLOCKS_PER_EPOCH),
        );

        let (orchestrator, orchestrator_mailbox) = orchestrator::Actor::new(
            context.child("orchestrator"),
            orchestrator::Config {
                oracle: config.blocker.clone(),
                application: application.clone(),
                provider,
                marshal: marshal_mailbox,
                strategy: config.strategy.clone(),
                leader_timeout: config.leader_timeout,
                certification_timeout: config.certification_timeout,
                muxer_size: MAILBOX_SIZE.get(),
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: format!("{}_consensus", config.partition_prefix),
                epoch_length: BLOCKS_PER_EPOCH,
                genesis_digest,
                _phantom: PhantomData,
            },
        );

        let engine = Self {
            context: ContextCell::new(context),
            config,
            dkg,
            dkg_mailbox,
            buffer,
            buffered_mailbox,
            marshal,
            orchestrator,
            orchestrator_mailbox,
            mempool,
            stateful,
            stateful_mailbox,
        };
        (engine, node_handle)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start(
        mut self,
        votes: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        certificates: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        broadcast: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        dkg: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        marshal: (
            resolver::handler::Receiver<Digest>,
            resolver::p2p::Mailbox<Digest, PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<MinSig, PublicKey>>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(
                votes,
                certificates,
                resolver,
                broadcast,
                dkg,
                marshal,
                callback
            )
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        self,
        votes: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        certificates: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        broadcast: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        dkg: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        marshal: (
            resolver::handler::Receiver<Digest>,
            resolver::p2p::Mailbox<Digest, PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<MinSig, PublicKey>>,
    ) {
        let dkg_handle = self.dkg.start(
            Some(self.config.output),
            self.config.share,
            self.orchestrator_mailbox,
            dkg,
            callback,
        );
        let buffer_handle = self.buffer.start(broadcast);
        let reporters =
            Reporters::<Update<Block>, _, _>::from((self.stateful_mailbox, self.dkg_mailbox));
        let marshal_handle = self
            .marshal
            .start(reporters, self.buffered_mailbox, marshal);
        let stateful_handle = self.stateful.start();
        let orchestrator_handle = self.orchestrator.start(votes, certificates, resolver);

        if let Err(e) = try_join_all(vec![
            dkg_handle,
            buffer_handle,
            marshal_handle,
            stateful_handle,
            orchestrator_handle,
            self.mempool,
        ])
        .await
        {
            error!(?e, "engine failed");
        } else {
            warn!("engine stopped");
        }
    }
}
