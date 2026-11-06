use crate::execution::NodeHandle;
use crate::{
    application, Block, BlockCommitment, EngineVariant, EpochProvider, Finalization,
    NoopTransaction, Provider, PublicKey, Scheme, BLOCKS_PER_EPOCH,
};
use commonware_coding::{CodecConfig, ReedSolomon};
use commonware_consensus::{
    marshal::{
        self,
        coding::{
            shards,
            types::{coding_config_for_participants, CodedBlock},
            Marshaled, MarshaledConfig,
        },
        core::Actor as MarshalActor,
        resolver,
        store::Certificates,
    },
    simplex::{
        elector::{Random, RandomVersion},
        types::Activity as SimplexActivity,
    },
    types::{Epoch, FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::Output,
        primitives::{group, variant::MinSig},
    },
    ed25519::{self, Batch},
    sha256::Digest,
    BatchVerifier, Committable, Hasher, Sha256, Signer,
};
use commonware_glue::stateful::{
    db::ManagedDb as _,
    probe::{Config as ProbeConfig, Probe},
    Config as StatefulConfig, Mailbox as StatefulMailbox, PruneConfig, Stateful as StatefulActor,
    SyncPlan,
};
use commonware_p2p::{Blocker, Manager, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef, spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics,
    Network, Spawner, Storage, Strategizer,
};
use commonware_storage::archive::{immutable, Identifier as ArchiveIdentifier};
use commonware_utils::{union, NZDuration};
use futures::{future::try_join_all, lock::Mutex as AsyncMutex};
use governor::clock::Clock as GClock;
use nunchi_bridge::{BridgeExtension, BridgeMailbox};
use nunchi_chain::engine::*;
use nunchi_chain::state_sync::{
    Actor as StateSyncActor, Config as StateSyncConfig, FloorProvider, Mailbox as StateSyncMailbox,
};
use nunchi_common::{QmdbBackend, QmdbState};
use nunchi_dkg::{self as dkg, orchestrator, PeerConfig, UpdateCallBack, MAX_SUPPORTED_MODE};
use nunchi_mempool::{Mempool, PoolConfig};
use rand::{CryptoRng, Rng};
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{info, warn};

/// Configuration for the bridge-chain engine.
pub struct Config<B: Blocker<PublicKey = PublicKey>, P: Manager<PublicKey = PublicKey>, S: Strategy>
{
    pub blocker: B,
    pub manager: P,
    pub namespace: Vec<u8>,
    pub partition_prefix: String,
    pub blocks_freezer_table_initial_size: u32,
    pub finalized_freezer_table_initial_size: u32,
    pub signer: ed25519::PrivateKey,
    pub dkg_storage_key: dkg::StorageKey,
    pub output: Output<MinSig, PublicKey>,
    pub share: Option<group::Share>,
    pub peer_config: PeerConfig<PublicKey>,
    pub min_block_interval_ms: NonZeroU64,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub strategy: S,
    /// Discover a finalized floor and perform peer QMDB state sync on a fresh database.
    pub state_sync: bool,
    /// Maximum number of marshal acknowledgements that may remain pending.
    pub max_pending_acks: NonZeroUsize,
    pub prune_config: PruneConfig,
    pub pool_config: PoolConfig,
    pub bridge: BridgeMailbox,
    pub bridge_handle: Handle<()>,
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("invalid prune configuration: {0}")]
    PruneConfig(#[from] PruneConfigError),
    #[error("bridge-chain does not authenticate DKG progress in QMDB; state_sync = true is unsupported")]
    UnsupportedDkgStateSync,
}

pub fn validate_state_sync(enabled: bool) -> Result<(), StartupError> {
    if enabled {
        return Err(StartupError::UnsupportedDkgStateSync);
    }
    Ok(())
}

type DkgActor<E, P> = nunchi_chain::DkgActor<E, P, NoopTransaction, BridgeExtension>;
type DkgMailbox = nunchi_chain::DkgMailbox<NoopTransaction, BridgeExtension>;
type StatefulApp<E> =
    StatefulActor<E, crate::Application, Scheme, EngineVariant, StateSyncMailbox<E>>;
type StatefulAppMailbox<E> = StatefulMailbox<E, crate::Application>;
type LimitedStatefulAppMailbox<E> = VerifyLimiter<StatefulAppMailbox<E>>;
type MarshaledApp<E, S> = BoxedAutomaton<
    Marshaled<
        E,
        LimitedStatefulAppMailbox<E>,
        Block,
        ReedSolomon<Sha256>,
        Sha256,
        SchemeProvider,
        S,
        FixedEpocher,
    >,
>;
type SchemeProvider = Provider<Scheme, ed25519::PrivateKey>;
type FinalizationsArchive<E> = immutable::Archive<E, Digest, Finalization>;
type BlocksArchive<E> = immutable::Archive<
    E,
    Digest,
    EngineStoredBlock<NoopTransaction, BridgeExtension>,
>;
type Marshal<E, S> = MarshalActor<
    E,
    EngineVariant,
    SchemeProvider,
    FinalizationsArchive<E>,
    BlocksArchive<E>,
    FixedEpocher,
    S,
>;
type Orchestrator<E, B, S> = orchestrator::Actor<
    E,
    B,
    MarshaledApp<E, S>,
    Scheme,
    Random,
    S,
    EngineVariant,
    orchestrator::NoopReporter<SimplexActivity<Scheme, BlockCommitment>>,
>;
type ShardsEngine<E, B, P, S> = shards::Engine<
    E,
    SchemeProvider,
    B,
    P,
    ReedSolomon<Sha256>,
    Sha256,
    Block,
    PublicKey,
    S,
>;
type ShardMailbox = shards::Mailbox<Block, ReedSolomon<Sha256>, Sha256, PublicKey>;

/// The engine that drives a bridge-chain validator.
#[allow(clippy::type_complexity)]
pub struct Engine<E, B, P, S>
where
    E: BufferPooler
        + Spawner
        + Metrics
        + CryptoRng
        + Rng
        + Clock
        + GClock
        + Storage
        + Strategizer
        + Network,
    B: Blocker<PublicKey = PublicKey>,
    P: Manager<PublicKey = PublicKey>,
    S: Strategy,
{
    context: ContextCell<E>,
    config: Config<B, P, S>,
    dkg: DkgActor<E, P>,
    dkg_mailbox: DkgMailbox,
    shards: ShardsEngine<E, B, P, S>,
    shard_mailbox: ShardMailbox,
    marshal: Marshal<E, S>,
    probe_handle: Handle<()>,
    state_sync_handle: Handle<()>,
    orchestrator: Orchestrator<E, B, S>,
    orchestrator_mailbox: orchestrator::Mailbox<MinSig, PublicKey>,
    mempool: Handle<()>,
    stateful: StatefulApp<E>,
    stateful_mailbox: StatefulAppMailbox<E>,
}

impl<E, B, P, S> Engine<E, B, P, S>
where
    E: BufferPooler
        + Spawner
        + Metrics
        + CryptoRng
        + Rng
        + Clock
        + GClock
        + Storage
        + Strategizer
        + Network
        + Send
        + 'static,
    B: Blocker<PublicKey = PublicKey>,
    P: Manager<PublicKey = PublicKey>,
    S: Strategy,
    Batch: BatchVerifier<PublicKey = PublicKey>,
{
    /// Create a new bridge-chain engine.
    pub async fn new(
        context: E,
        config: Config<B, P, S>,
        probe_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        state_sync_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Result<(Self, NodeHandle<E>), StartupError> {
        let prune_config = validate_state_prune_config(config.prune_config, config.max_pending_acks)?;
        validate_state_sync(config.state_sync)?;
        let (mempool, submitter) = Mempool::<NoopTransaction>::new(config.pool_config.clone());
        let mempool = mempool.start(context.child("mempool"));

        let page_cache = CacheRef::from_pooler(&context, PAGE_CACHE_PAGE_SIZE, PAGE_CACHE_CAPACITY);
        let consensus_namespace = union(&config.namespace, b"_CONSENSUS");
        let num_participants =
            commonware_utils::NZU32!(config.peer_config.max_participants_per_round());
        let block_codec_config = (num_participants, ());

        let (dkg, dkg_mailbox) = dkg::Actor::new(
            context.child("dkg"),
            dkg::Config {
                manager: config.manager.clone(),
                signer: config.signer.clone(),
                mailbox_size: MAILBOX_SIZE,
                execution: dkg::Execution::default(),
                partition_prefix: config.partition_prefix.clone(),
                peer_config: config.peer_config.clone(),
                secondary_nodes: Default::default(),
                max_supported_mode: MAX_SUPPORTED_MODE,
                namespace: config.namespace.clone(),
                storage_protector: dkg::StorageProtector::new(config.dkg_storage_key),
                epoch_length: BLOCKS_PER_EPOCH,
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
                codec_config: (),
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
                codec_config: block_codec_config,
                replay_buffer: REPLAY_BUFFER,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

        let recovered_floor = if let Some(height) = Certificates::last_index(&finalizations_by_height)
        {
            Certificates::get(
                &finalizations_by_height,
                ArchiveIdentifier::Index(height.get()),
            )
            .await
            .expect("failed to read recovered finalization floor")
        } else {
            None
        };

        let certificate_verifier = <SchemeProvider as EpochProvider>::certificate_verifier(
            &consensus_namespace,
            &config.output,
        );
        let floor_verifier = certificate_verifier
            .clone()
            .expect("threshold scheme must support epoch-independent certificates");
        let provider = Provider::new(
            consensus_namespace,
            config.signer.clone(),
            certificate_verifier,
        );
        let n_coding_participants = u16::try_from(config.output.players().len())
            .expect("participant count must fit in u16");
        assert!(
            n_coding_participants >= 4,
            "erasure-coded marshal requires at least 4 participants, got {n_coding_participants}"
        );
        let coding_config = coding_config_for_participants(n_coding_participants);
        let genesis_parent = nunchi_chain::genesis_parent(n_coding_participants);
        let (shards, shard_mailbox) = shards::Engine::new(
            context.child("shards"),
            shards::Config {
                scheme_provider: provider.clone(),
                blocker: config.blocker.clone(),
                shard_codec_cfg: CodecConfig {
                    maximum_shard_size: MAX_SHARD_SIZE,
                },
                block_codec_cfg: block_codec_config,
                strategy: config.strategy.clone(),
                mailbox_size: MAILBOX_SIZE,
                peer_buffer_size: SHARD_PEER_BUFFER_SIZE,
                background_channel_capacity: SHARD_BACKGROUND_CHANNEL_CAPACITY,
                peer_provider: config.manager.clone(),
            },
        );
        let floor_sizing_scheme =
            provider.scheme_for_epoch(&orchestrator::EpochTransition {
                epoch: Epoch::zero(),
                poly: Some(config.output.public().clone()),
                share: config.share.clone(),
                dealers: config.peer_config.dealers(0),
            });
        let floor_provider = FloorProvider::new(floor_verifier, floor_sizing_scheme);
        let state_partition = format!("{}-bridge", config.partition_prefix);
        let db_config =
            QmdbState::<E>::config_with_page_cache(&state_partition, page_cache.clone());
        let empty_state = {
            let empty = QmdbBackend::init(
                context.child("empty_genesis_state"),
                QmdbState::<E>::config_with_page_cache(
                    &format!("{}-empty-genesis-bridge", config.partition_prefix),
                    page_cache.clone(),
                ),
            )
            .await
            .expect("failed to initialize empty state database for genesis commitment");
            let target = empty.sync_target();
            nunchi_chain::StateCommitment {
                root: target.root,
                range: target.range,
            }
        };
        let applied_height = Arc::new(AsyncMutex::new(Height::zero()));
        let bridge = BridgeExtension::new(config.bridge.clone());
        let app = application(
            submitter.clone(),
            bridge,
            applied_height.clone(),
            empty_state,
            Sha256::hash(&[config.namespace.as_slice()]),
            config.min_block_interval_ms,
        )
        .with_genesis_parent(genesis_parent);
        let genesis = app.genesis_block();
        let coded_genesis = CodedBlock::new(genesis.clone(), coding_config, &config.strategy);
        let genesis_commitment = coded_genesis.commitment();
        let mut plan =
            SyncPlan::<_, Scheme, EngineVariant>::init(&context, config.partition_prefix.clone())
                .await;
        let (state_sync, state_sync_mailbox) = StateSyncActor::new(
            context.child("state_sync_resolver"),
            StateSyncConfig {
                peer_provider: config.manager.clone(),
                blocker: config.blocker.clone(),
                database: None,
                operation_codec_config: nunchi_common::qmdb_operation_codec_config(),
                mailbox_size: MAILBOX_SIZE,
                me: Some(config.signer.public_key()),
                timeout: STATE_SYNC_RESOLVER_TIMEOUT,
                fetch_retry_timeout: STATE_SYNC_RESOLVER_RETRY,
                max_serve_ops: STATE_SYNC_FETCH_BATCH_SIZE,
                priority_requests: false,
                priority_responses: false,
            },
        );
        let state_sync_handle = state_sync.start(state_sync_network);
        let (probe, probe_mailbox) = Probe::new(ProbeConfig {
            context: context.child("probe"),
            provider: floor_provider,
            strategy: config.strategy.clone(),
            capacity: MAILBOX_SIZE,
            blocker: config.blocker.clone(),
            minimum_epoch: Epoch::zero(),
            retry_timeout: NZDuration!(Duration::from_secs(1)),
        });
        let probe_handle = probe.start(probe_network);
        if plan.should_state_sync(config.state_sync) && plan.floor().is_none() {
            let floor = probe_mailbox
                .subscribe()
                .await
                .expect("state-sync floor probe stopped");
            plan = plan.with_floor(floor);
        }
        let marshal_start = recovered_floor
            .clone()
            .map_or_else(|| plan.marshal_start(coded_genesis), marshal::Start::Floor);
        let (marshal, marshal_mailbox, marshal_floor) = MarshalActor::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: provider.clone(),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                start: marshal_start,
                partition_prefix: format!("{}_marshal", config.partition_prefix),
                mailbox_size: MAILBOX_SIZE,
                view_retention: ViewDelta::new(
                    ACTIVITY_TIMEOUT
                        .get()
                        .saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
                ),
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                page_cache: page_cache.clone(),
                replay_buffer: REPLAY_BUFFER,
                key_write_buffer: WRITE_BUFFER,
                value_write_buffer: WRITE_BUFFER,
                block_codec_config,
                max_repair: MAX_REPAIR,
                max_pending_acks: config.max_pending_acks,
                strategy: config.strategy.clone(),
            },
        )
        .await;
        probe_mailbox.attach(marshal_mailbox.clone());

        let (stateful, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application: app,
                db_config,
                provider: submitter,
                marshal: (marshal_mailbox.clone(), marshal_floor),
                mailbox_size: MAILBOX_SIZE,
                plan,
                resolvers: state_sync_mailbox,
                sync_config: state_sync_config(),
                prune_config: Some(prune_config),
            },
        );
        let node_handle = NodeHandle::new(
            config.bridge.clone(),
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            applied_height,
        );

        let verify_limiter_context = context.child("application_verify");
        let application = BoxedAutomaton::new(Marshaled::new(
            context.child("application"),
            MarshaledConfig {
                application: VerifyLimiter::new(
                    &verify_limiter_context,
                    stateful_mailbox.clone(),
                    APPLICATION_VERIFY_CONCURRENCY,
                ),
                marshal: marshal_mailbox.clone(),
                shards: shard_mailbox.clone(),
                scheme_provider: provider.clone(),
                strategy: config.strategy.clone(),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            },
        ));

        let (orchestrator, orchestrator_mailbox) = orchestrator::Actor::new(
            context.child("orchestrator"),
            orchestrator::Config {
                oracle: config.blocker.clone(),
                application,
                provider,
                marshal: marshal_mailbox,
                reporter: orchestrator::NoopReporter::default(),
                elector: Random::new(RandomVersion::V1),
                strategy: config.strategy.clone(),
                leader_timeout: config.leader_timeout,
                certification_timeout: config.certification_timeout,
                muxer_size: MAILBOX_SIZE.get(),
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: format!("{}_consensus", config.partition_prefix),
                epoch_length: BLOCKS_PER_EPOCH,
                genesis_digest: genesis_commitment,
                recovered_floor,
                startup_finalization: None,
                startup_floor: None,
            },
        );

        let engine = Self {
            context: ContextCell::new(context),
            config,
            dkg,
            dkg_mailbox,
            shards,
            shard_mailbox,
            marshal,
            probe_handle,
            state_sync_handle,
            orchestrator,
            orchestrator_mailbox,
            mempool,
            stateful,
            stateful_mailbox,
        };
        Ok((engine, node_handle))
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
        marshal_shards: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        dkg: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        marshal: (
            resolver::handler::Receiver<BlockCommitment>,
            resolver::p2p::Mailbox<BlockCommitment, PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<MinSig, PublicKey>>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(
                votes,
                certificates,
                resolver,
                marshal_shards,
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
        marshal_shards: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        dkg: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        marshal: (
            resolver::handler::Receiver<BlockCommitment>,
            resolver::p2p::Mailbox<BlockCommitment, PublicKey>,
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
        let shards_handle = self.shards.start(marshal_shards);
        let reporters = nunchi_chain::dkg_reporters(self.stateful_mailbox, self.dkg_mailbox);
        let marshal_handle = self
            .marshal
            .start(reporters, self.shard_mailbox, marshal);
        let probe_handle = self.probe_handle;
        let state_sync_handle = self.state_sync_handle;
        let stateful_handle = self.stateful.start();
        let orchestrator_handle = self.orchestrator.start(votes, certificates, resolver);

        match try_join_all(vec![
            dkg_handle,
            shards_handle,
            marshal_handle,
            probe_handle,
            state_sync_handle,
            stateful_handle,
            orchestrator_handle,
            self.mempool,
            self.config.bridge_handle,
        ])
        .await
        {
            Err(e) => panic!("engine failed: {e:?}"),
            Ok(_) => warn!("engine stopped"),
        }
    }
}
