use crate::execution::NodeHandle;
use crate::{
    application, Block, EpochProvider, Finalization, NoopTransaction, Provider, PublicKey, Scheme,
    BLOCKS_PER_EPOCH,
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    marshal::{
        self,
        core::Actor as MarshalActor,
        resolver,
        standard::{Inline, Standard},
        store::Certificates,
    },
    simplex::elector::Random,
    types::{FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::Output,
        primitives::{group, variant::MinSig},
    },
    certificate::Scheme as _,
    ed25519::{self, Batch},
    sha256::Digest,
    BatchVerifier, Digestible, Hasher, Signer,
};
use commonware_glue::stateful::{
    db::ManagedDb as _, Config as StatefulConfig, Mailbox as StatefulMailbox,
    Stateful as StatefulActor, SyncPlan,
};
use commonware_p2p::{Blocker, Manager, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef, spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics,
    Network, Spawner, Storage, ThreadPooler,
};
use commonware_storage::archive::{immutable, Identifier as ArchiveIdentifier};
use commonware_utils::union;
use futures::{future::try_join_all, lock::Mutex as AsyncMutex};
use governor::clock::Clock as GClock;
use nunchi_bridge::{BridgeExtension, BridgeMailbox};
use nunchi_chain::engine::*;
use nunchi_common::{QmdbBackend, QmdbState};
use nunchi_dkg::{self as dkg, orchestrator, PeerConfig, UpdateCallBack, MAX_SUPPORTED_MODE};
use nunchi_mempool::{Mempool, PoolConfig};
use rand::{CryptoRng, Rng};
use rand_core::CryptoRngCore;
use std::{
    marker::PhantomData,
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
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub strategy: S,
    pub pool_config: PoolConfig,
    pub bridge: BridgeMailbox,
    pub bridge_handle: Handle<()>,
}

type DkgActor<E, P> = nunchi_chain::DkgActor<E, P, NoopTransaction, BridgeExtension>;
type DkgMailbox = nunchi_chain::DkgMailbox<NoopTransaction, BridgeExtension>;
type StatefulApp<E> =
    StatefulActor<E, crate::Application, Scheme, Standard<Block>, NoStateSyncResolver>;
type StatefulAppMailbox<E> = StatefulMailbox<E, crate::Application>;
type LimitedStatefulAppMailbox<E> = VerifyLimiter<StatefulAppMailbox<E>>;
type Marshaled<E> = Inline<E, Scheme, LimitedStatefulAppMailbox<E>, Block, FixedEpocher>;
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

/// The engine that drives a bridge-chain validator.
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
    /// Create a new bridge-chain engine.
    pub async fn new(context: E, config: Config<B, P, S>) -> (Self, NodeHandle<E>) {
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
                max_supported_mode: MAX_SUPPORTED_MODE,
                namespace: config.namespace.clone(),
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
        let provider = Provider::new(
            consensus_namespace,
            config.signer.clone(),
            certificate_verifier,
        );
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
            let target = empty.sync_target().await;
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
            commonware_cryptography::Sha256::hash(&config.namespace),
        );
        let genesis = app.genesis_block();
        let genesis_digest = genesis.digest();
        let plan =
            SyncPlan::<_, Scheme, Standard<Block>>::init(&context, config.partition_prefix.clone())
                .await;
        let marshal_start = recovered_floor
            .clone()
            .map_or_else(|| plan.marshal_start(genesis), marshal::Start::Floor);
        let (marshal, marshal_mailbox, _processed_height) = MarshalActor::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: provider.clone(),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                start: marshal_start,
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

        let (stateful, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application: app,
                db_config,
                input_provider: submitter,
                marshal: marshal_mailbox.clone(),
                max_pending_acks: MAX_PENDING_ACKS,
                mailbox_size: MAILBOX_SIZE,
                plan,
                resolvers: NoStateSyncResolver,
                sync_config: state_sync_config(),
            },
        );
        let node_handle = NodeHandle::new(
            config.bridge.clone(),
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            applied_height,
        );

        let verify_limiter_context = context.child("application_verify");
        let application = Inline::new(
            context.child("application"),
            VerifyLimiter::new(
                &verify_limiter_context,
                stateful_mailbox.clone(),
                APPLICATION_VERIFY_CONCURRENCY,
            ),
            marshal_mailbox.clone(),
            FixedEpocher::new(BLOCKS_PER_EPOCH),
        );

        let (orchestrator, orchestrator_mailbox) = orchestrator::Actor::new(
            context.child("orchestrator"),
            orchestrator::Config {
                oracle: config.blocker.clone(),
                application,
                provider,
                marshal: marshal_mailbox,
                reporter: orchestrator::NoopReporter::default(),
                strategy: config.strategy.clone(),
                leader_timeout: config.leader_timeout,
                certification_timeout: config.certification_timeout,
                muxer_size: MAILBOX_SIZE.get(),
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: format!("{}_consensus", config.partition_prefix),
                epoch_length: BLOCKS_PER_EPOCH,
                genesis_digest,
                recovered_floor,
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
        let reporters = nunchi_chain::dkg_reporters(self.stateful_mailbox, self.dkg_mailbox);
        let marshal_handle = self
            .marshal
            .start(reporters, self.buffered_mailbox, marshal);
        let stateful_handle = self.stateful.start();
        let orchestrator_handle = self.orchestrator.start(votes, certificates, resolver);

        match try_join_all(vec![
            dkg_handle,
            buffer_handle,
            marshal_handle,
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
