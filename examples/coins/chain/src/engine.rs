use crate::application::{self, Application};
use crate::execution::NodeHandle;
use crate::genesis::{genesis_target, state_commitment, ChainGenesis};
use crate::{
    Block, EpochProvider, Finalization, Provider, PublicKey, Scheme, Transaction, BLOCKS_PER_EPOCH,
    NAMESPACE,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    marshal::{
        self,
        core::Actor as MarshalActor,
        resolver,
        standard::{Deferred, Standard},
    },
    simplex::elector::Random,
    types::{Epoch, FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::Output,
        primitives::{group, variant::MinSig},
    },
    certificate::Verifier as _,
    ed25519::{self, Batch},
    sha256::Digest,
    BatchVerifier, Digestible, Signer,
};
use commonware_glue::stateful::{
    db::ManagedDb as _,
    probe::{Config as ProbeConfig, Probe},
    Config as StatefulConfig, Mailbox as StatefulMailbox, Stateful as StatefulActor, SyncPlan,
};
use commonware_p2p::{Blocker, Manager, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef, spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics,
    Network, Spawner, Storage, Strategizer,
};
use commonware_storage::archive::immutable;
use commonware_utils::{union, NZDuration};
use futures::lock::Mutex as AsyncMutex;
use governor::clock::Clock as GClock;
use nunchi_chain::engine::*;
use nunchi_chain::state_sync::{
    Actor as StateSyncActor, Config as StateSyncConfig, FloorProvider,
    Mailbox as StateSyncMailbox,
};
use nunchi_clob::{ClobActor, ClobConfig, ClobExtension};
use nunchi_common::{QmdbBackend, QmdbState};
use nunchi_dkg::{self as dkg, orchestrator, PeerConfig, UpdateCallBack, MAX_SUPPORTED_MODE};
use nunchi_mempool::{Mempool, PoolConfig};
use rand::{CryptoRng, Rng};
use std::{
    marker::PhantomData,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{info, warn};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("{0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("runtime stopped with code {0}")]
    Stopped(i32),
    #[error("shutdown signal closed unexpectedly")]
    ShutdownSignalClosed,
    #[error("{0} stopped unexpectedly")]
    UnexpectedExit(&'static str),
}

/// Configuration for the [Engine].
pub struct Config<B: Blocker<PublicKey = PublicKey>, P: Manager<PublicKey = PublicKey>, S: Strategy>
{
    pub blocker: B,
    pub manager: P,
    pub partition_prefix: String,
    pub blocks_freezer_table_initial_size: u32,
    pub finalized_freezer_table_initial_size: u32,
    pub signer: ed25519::PrivateKey,
    pub dkg_storage_key: dkg::StorageKey,
    pub output: Output<MinSig, PublicKey>,
    pub share: Option<group::Share>,
    pub peer_config: PeerConfig<PublicKey>,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub strategy: S,
    /// Discover a finalized floor and perform peer QMDB state sync on a fresh database.
    pub state_sync: bool,
    pub max_block_transactions: usize,
    pub pool_config: PoolConfig,
    pub genesis: Option<ChainGenesis>,
}

type DkgActor<E, P> = nunchi_chain::DkgActor<E, P, Transaction, ClobExtension>;
type DkgMailbox = nunchi_chain::DkgMailbox<Transaction, ClobExtension>;
type StatefulApp<E> = StatefulActor<E, Application, Scheme, Standard<Block>, StateSyncMailbox<E>>;
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
    buffer: buffered::Engine<E, PublicKey, Block, P>,
    buffered_mailbox: buffered::Mailbox<PublicKey, Block>,
    marshal: Marshal<E, S>,
    probe_handle: Handle<()>,
    state_sync_handle: Handle<()>,
    orchestrator: Orchestrator<E, B, S>,
    orchestrator_mailbox: orchestrator::Mailbox<MinSig, PublicKey>,
    mempool: Mempool<Transaction>,
    clob: ClobActor,
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
    /// Create a new [Engine].
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
    ) -> (Self, NodeHandle<E>) {
        let (mempool, submitter) = Mempool::<Transaction>::new(config.pool_config.clone());
        let (clob, clob_mailbox) = ClobActor::new(ClobConfig::default());
        if let Some(clob_genesis) = config.genesis.as_ref().and_then(|genesis| genesis.clob.as_ref())
        {
            for market in &clob_genesis.markets {
                clob_mailbox.upsert_market_state(
                    market
                        .market()
                        .expect("invalid CLOB genesis market should fail genesis validation"),
                    0,
                );
            }
        }

        let page_cache = CacheRef::from_pooler(&context, PAGE_CACHE_PAGE_SIZE, PAGE_CACHE_CAPACITY);
        let consensus_namespace = union(NAMESPACE, b"_CONSENSUS");
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
                max_supported_mode: MAX_SUPPORTED_MODE,
                namespace: NAMESPACE.to_vec(),
                storage_protector: dkg::StorageProtector::new(config.dkg_storage_key),
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
                codec_config: block_codec_config,
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
                codec_config: block_codec_config,
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
        let floor_verifier = certificate_verifier
            .clone()
            .expect("threshold scheme must support epoch-independent certificates");
        let provider = Provider::new(
            consensus_namespace.clone(),
            config.signer.clone(),
            certificate_verifier,
        );
        let floor_sizing_scheme =
            provider.scheme_for_epoch(&orchestrator::EpochTransition {
                epoch: Epoch::zero(),
                poly: Some(config.output.public().clone()),
                share: config.share.clone(),
                dealers: config.peer_config.dealers(0),
            });
        let floor_provider = FloorProvider::new(floor_verifier, floor_sizing_scheme);
        let state_partition = format!("{}-coins", config.partition_prefix);
        let db_config =
            QmdbState::<E>::config_with_page_cache(&state_partition, page_cache.clone());

        // Derive the empty-state target from QMDB so the genesis commitment stays coupled to the
        // storage implementation instead of a hardcoded digest.
        let empty_state = {
            let empty = QmdbBackend::init(
                context.child("empty_genesis_state"),
                QmdbState::<E>::config_with_page_cache(
                    &format!("{}-empty-genesis-coins", config.partition_prefix),
                    page_cache.clone(),
                ),
            )
            .await
            .expect("failed to initialize empty state database for genesis commitment");
            state_commitment(empty.sync_target())
        };
        let genesis_state = if let Some(genesis) = &config.genesis {
            let fingerprint = commonware_formatting::hex(
                &genesis
                    .fingerprint()
                    .expect("failed to fingerprint statically configured genesis"),
            );
            let compute_partition = format!("{}-genesis-{}", config.partition_prefix, fingerprint);
            let compute_config =
                QmdbState::<E>::config_with_page_cache(&compute_partition, page_cache.clone());
            let expected = genesis_target(
                context.child("genesis_commitment"),
                compute_config,
                genesis,
                &empty_state,
            )
            .await
            .expect("failed to materialize genesis commitment");

            let mut state =
                QmdbState::init_with_config(context.child("genesis_seed"), db_config.clone())
                    .await
                    .expect("failed to initialize state database for genesis seeding");
            genesis
                .apply_to_state(&mut state, &empty_state)
                .await
                .expect("failed to seed state database with genesis");
            let actual = state_commitment(state.sync_target());
            assert_eq!(
                expected, actual,
                "state database genesis commitment must match the genesis block commitment"
            );
            expected
        } else {
            empty_state
        };
        let applied_height = Arc::new(AsyncMutex::new(Height::zero()));
        let app = Application::with_consensus(
            submitter.clone(),
            config.max_block_transactions,
            ClobExtension::new(clob_mailbox.clone()),
            Some(dkg_mailbox.clone()),
            applied_height.clone(),
            genesis_state,
            application::genesis_payload(),
        );
        let genesis = app.genesis_block();
        let genesis_digest = genesis.digest();
        // The sync plan drives both marshal and stateful startup. Fresh joining nodes can discover
        // a floor and sync QMDB directly; bootstrap nodes leave `state_sync` disabled and start
        // from genesis. Interrupted state sync resumes from its persisted floor.
        let mut plan =
            SyncPlan::<_, Scheme, Standard<Block>>::init(&context, config.partition_prefix.clone())
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
                initial: STATE_SYNC_RESOLVER_INITIAL,
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
                block_codec_config,
                max_repair: MAX_REPAIR,
                max_pending_acks: MAX_PENDING_ACKS,
                strategy: config.strategy.clone(),
            },
        )
        .await;
        // Once startup floor selection is complete, serve our latest finalization to peers.
        probe_mailbox.attach(marshal_mailbox.clone());

        let (stateful, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application: app,
                db_config,
                input_provider: submitter.clone(),
                marshal: marshal_mailbox.clone(),
                mailbox_size: MAILBOX_SIZE,
                plan,
                resolvers: state_sync_mailbox,
                sync_config: state_sync_config(),
                prune_config: Some(state_prune_config()),
            },
        );
        let node_handle = NodeHandle::new(
            submitter,
            clob_mailbox.clone(),
            stateful_mailbox.clone(),
            applied_height,
        );

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
            probe_handle,
            state_sync_handle,
            orchestrator,
            orchestrator_mailbox,
            mempool,
            clob,
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
        mempool: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        clob: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        marshal: (
            resolver::handler::Receiver<Digest>,
            resolver::p2p::Mailbox<Digest, PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<MinSig, PublicKey>>,
    ) -> Handle<Result<(), EngineError>> {
        spawn_cell!(
            self.context,
            self.run(
                votes,
                certificates,
                resolver,
                broadcast,
                dkg,
                mempool,
                clob,
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
        mempool: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        clob: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        marshal: (
            resolver::handler::Receiver<Digest>,
            resolver::p2p::Mailbox<Digest, PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<MinSig, PublicKey>>,
    ) -> Result<(), EngineError> {
        let dkg_handle = self.dkg.start(
            Some(self.config.output),
            self.config.share,
            self.orchestrator_mailbox,
            dkg,
            callback,
        );
        let buffer_handle = self.buffer.start(broadcast);
        let reporters = nunchi_chain::dkg_reporters(self.stateful_mailbox, self.dkg_mailbox);
        let marshal_handle = self
            .marshal
            .start(reporters, self.buffered_mailbox, marshal);
        let probe_handle = self.probe_handle;
        let state_sync_handle = self.state_sync_handle;
        let stateful_handle = self.stateful.start();
        let orchestrator_handle = self.orchestrator.start(votes, certificates, resolver);
        let mempool_handle = self
            .mempool
            .start_p2p(self.context.child("mempool"), mempool);
        let clob_handle = self.clob.start_p2p(self.context.child("clob"), clob);

        let mut shutdown = self.context.stopped();
        commonware_macros::select! {
            stopped = &mut shutdown => match stopped {
                Ok(0) => {
                    warn!("engine stopped");
                    Ok(())
                }
                Ok(code) => Err(EngineError::Stopped(code)),
                Err(_) => Err(EngineError::ShutdownSignalClosed),
            },
            result = dkg_handle => unexpected_exit("dkg", result),
            result = buffer_handle => unexpected_exit("buffer", result),
            result = marshal_handle => unexpected_exit("marshal", result),
            result = probe_handle => unexpected_exit("probe", result),
            result = state_sync_handle => unexpected_exit("state sync resolver", result),
            result = stateful_handle => unexpected_exit("stateful", result),
            result = orchestrator_handle => unexpected_exit("orchestrator", result),
            result = mempool_handle => unexpected_exit("mempool", result),
            result = clob_handle => unexpected_exit("clob", result),
        }
    }
}

fn unexpected_exit(
    component: &'static str,
    result: Result<(), commonware_runtime::Error>,
) -> Result<(), EngineError> {
    match result {
        Ok(()) => Err(EngineError::UnexpectedExit(component)),
        Err(error) => Err(error.into()),
    }
}
