use crate::application::Application;
use crate::execution::{ChainState, Executor, Mailbox as ExecutorReporter, NodeHandle};
use crate::txpool::TxPool;
use crate::{Block, Finalization, Scheme, EPOCH, EPOCH_LENGTH, NAMESPACE};
use commonware_broadcast::buffered;
use commonware_consensus::{
    marshal::{
        self,
        core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
        resolver::handler,
        standard::{Deferred, Standard},
        Update,
    },
    simplex::{self, elector::Random, Engine as Consensus},
    types::{Epoch, FixedEpocher, Height, ViewDelta},
    Reporters,
};
use commonware_cryptography::{
    bls12381::primitives::{group, sharing::Sharing, variant::MinSig},
    certificate::{ConstantProvider, Scheme as _},
    ed25519::PublicKey,
    sha256::Digest,
    Digestible,
};
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_resolver::TargetedResolver;
use commonware_runtime::{
    buffer::paged::CacheRef, spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics,
    Spawner, Storage, ThreadPooler,
};
use commonware_storage::archive::immutable;
use commonware_utils::{ordered::Set, NZU16};
use commonware_utils::{NZUsize, NZU64};
use futures::future::try_join_all;
use futures::lock::Mutex as AsyncMutex;
use governor::clock::Clock as GClock;
use governor::Quota;
use nunchi_coins::Ledger;
use nunchi_common::QmdbState;
use rand::{CryptoRng, Rng};
use std::sync::Arc;
use std::{
    num::NonZero,
    time::{Duration, Instant},
};
use tracing::{error, info, warn};

/// To better support peers near tip during network instability, we multiply
/// the consensus activity timeout by this factor.
const SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER: u64 = 10;
const PRUNABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(4_096);
const IMMUTABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(262_144);
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 3MB
const FREEZER_JOURNAL_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_JOURNAL_COMPRESSION: Option<u8> = Some(3);
const REPLAY_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024); // 8MB
const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024); // 1MB
const PAGE_CACHE_PAGE_SIZE: NonZero<u16> = NZU16!(4_096); // 4KB
const PAGE_CACHE_CAPACITY: NonZero<usize> = NZUsize!(8_192); // 32MB
const MAX_REPAIR: NonZero<usize> = NZUsize!(20);
const MAX_PENDING_ACKS: NonZero<usize> = NZUsize!(16);
/// Capacity of the executor's finalized-block mailbox before messages spill to overflow.
const EXECUTOR_MAILBOX_CAPACITY: NonZero<usize> = NZUsize!(1_024);

/// Configuration for the [Engine].
pub struct Config<
    B: Blocker<PublicKey = PublicKey>,
    P: Provider<PublicKey = PublicKey>,
    S: Strategy,
> {
    pub blocker: B,
    pub provider: P,
    pub partition_prefix: String,
    pub blocks_freezer_table_initial_size: u32,
    pub finalized_freezer_table_initial_size: u32,
    pub me: PublicKey,
    pub polynomial: Sharing<MinSig>,
    pub share: group::Share,
    pub participants: Set<PublicKey>,
    pub mailbox_size: usize,
    pub deque_size: usize,

    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub nullify_retry: Duration,
    pub fetch_timeout: Duration,
    pub activity_timeout: ViewDelta,
    pub skip_timeout: ViewDelta,
    pub max_fetch_count: usize,
    pub max_fetch_size: usize,
    pub fetch_concurrent: usize,
    pub fetch_rate_per_peer: Quota,

    pub strategy: S,

    /// Maximum number of transactions a proposed block may carry.
    pub max_block_transactions: usize,
}

type Marshaled<E> = Deferred<E, Scheme, Application, Block, FixedEpocher>;
type FinalizationsArchive<E> = immutable::Archive<E, Digest, Finalization>;
type BlocksArchive<E> = immutable::Archive<E, Digest, Block>;
type Marshal<E, S> = MarshalActor<
    E,
    Standard<Block>,
    ConstantProvider<Scheme, Epoch>,
    FinalizationsArchive<E>,
    BlocksArchive<E>,
    FixedEpocher,
    S,
>;
type ConsensusEngine<E, B, S> = Consensus<
    E,
    Scheme,
    Random,
    B,
    Digest,
    Marshaled<E>,
    Marshaled<E>,
    MarshalMailbox<Scheme, Standard<Block>>,
    S,
>;

struct Archives<E>
where
    E: BufferPooler + Clock + Metrics + Storage,
{
    finalizations_by_height: FinalizationsArchive<E>,
    finalized_blocks: BlocksArchive<E>,
}

struct ConsensusMaterials {
    scheme: Scheme,
    certificate_provider: ConstantProvider<Scheme, Epoch>,
    epocher: FixedEpocher,
    genesis: Block,
    genesis_digest: Digest,
}

struct MarshalInputs<E, S>
where
    E: BufferPooler + Clock + Metrics + Storage,
{
    partition_prefix: String,
    mailbox_size: usize,
    activity_timeout: ViewDelta,
    archives: Archives<E>,
    page_cache: CacheRef,
    provider: ConstantProvider<Scheme, Epoch>,
    epocher: FixedEpocher,
    genesis: Block,
    strategy: S,
}

/// The engine that drives the coins-chain [Application].
#[allow(clippy::type_complexity)]
pub struct Engine<E, B, P, S>
where
    E: BufferPooler + Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = PublicKey>,
    P: Provider<PublicKey = PublicKey>,
    S: Strategy,
{
    context: ContextCell<E>,

    buffer: buffered::Engine<E, PublicKey, Block, P>,
    buffer_mailbox: buffered::Mailbox<PublicKey, Block>,
    marshal: Marshal<E, S>,
    marshaled: Marshaled<E>,

    consensus: ConsensusEngine<E, B, S>,
    executor: Handle<()>,
    txpool: Handle<()>,
    /// The executor's report sink, wired alongside the application as a marshal reporter at start.
    reporter: ExecutorReporter,
}

impl<E, B, P, S> Engine<E, B, P, S>
where
    E: BufferPooler
        + Clock
        + GClock
        + Rng
        + CryptoRng
        + Spawner
        + ThreadPooler
        + Storage
        + Metrics
        + Send
        + 'static,
    B: Blocker<PublicKey = PublicKey>,
    P: Provider<PublicKey = PublicKey>,
    S: Strategy,
{
    /// Create a new [Engine].
    pub async fn new(context: E, cfg: Config<B, P, S>) -> (Self, NodeHandle<E>) {
        let Config {
            blocker,
            provider,
            partition_prefix,
            blocks_freezer_table_initial_size,
            finalized_freezer_table_initial_size,
            me,
            polynomial,
            share,
            participants,
            mailbox_size,
            deque_size,
            leader_timeout,
            certification_timeout,
            nullify_retry,
            fetch_timeout,
            activity_timeout,
            skip_timeout,
            max_fetch_count: _,
            max_fetch_size: _,
            fetch_concurrent,
            fetch_rate_per_peer: _,
            strategy,
            max_block_transactions,
        } = cfg;

        let (txpool, submitter) = TxPool::new();
        let coin_state = QmdbState::init(
            context.child("coins_state"),
            &format!("{partition_prefix}-coins"),
        )
        .await
        .expect("failed to initialize coin state");
        let shared_ledger = Arc::new(AsyncMutex::new(ChainState {
            ledger: Ledger::new(coin_state),
            applied_height: Height::zero(),
        }));
        let executor_context = context.child("coins_executor");
        let (coins_executor, reporter) = Executor::new(
            &executor_context,
            EXECUTOR_MAILBOX_CAPACITY,
            shared_ledger.clone(),
            submitter.clone(),
        );
        // The handle this node exposes to its operator: its transaction ingress and ledger view.
        let node_handle = NodeHandle {
            submitter: submitter.clone(),
            ledger: shared_ledger,
        };
        let txpool = txpool.start(context.child("txpool"));
        let executor = coins_executor.start(executor_context);

        let app = Application::new(submitter, max_block_transactions);

        let page_cache = Self::create_page_cache(&context);
        let (buffer, buffer_mailbox) =
            Self::create_buffer(&context, me, mailbox_size, deque_size, provider);
        let archives = Self::init_archives(
            &context,
            &partition_prefix,
            blocks_freezer_table_initial_size,
            finalized_freezer_table_initial_size,
            &page_cache,
        )
        .await;
        let materials = Self::create_consensus_materials(participants, polynomial, share);
        let (marshal, marshal_mailbox) = Self::init_marshal(
            &context,
            MarshalInputs {
                partition_prefix: partition_prefix.clone(),
                mailbox_size,
                activity_timeout,
                archives,
                page_cache: page_cache.clone(),
                provider: materials.certificate_provider,
                epocher: materials.epocher.clone(),
                genesis: materials.genesis,
                strategy: strategy.clone(),
            },
        )
        .await;
        let marshaled =
            Self::create_marshaled(&context, app, marshal_mailbox.clone(), materials.epocher);
        let consensus = Self::create_consensus(
            &context,
            partition_prefix,
            mailbox_size,
            leader_timeout,
            certification_timeout,
            nullify_retry,
            fetch_timeout,
            activity_timeout,
            skip_timeout,
            fetch_concurrent,
            blocker,
            page_cache,
            materials.scheme,
            materials.genesis_digest,
            marshaled.clone(),
            marshal_mailbox,
            strategy,
        );

        let engine = Self {
            context: ContextCell::new(context),
            buffer,
            buffer_mailbox,
            marshal,
            marshaled,
            consensus,
            executor,
            txpool,
            reporter,
        };
        (engine, node_handle)
    }

    fn create_page_cache(context: &E) -> CacheRef {
        CacheRef::from_pooler(context, PAGE_CACHE_PAGE_SIZE, PAGE_CACHE_CAPACITY)
    }

    fn create_buffer(
        context: &E,
        public_key: PublicKey,
        mailbox_size: usize,
        deque_size: usize,
        provider: P,
    ) -> (
        buffered::Engine<E, PublicKey, Block, P>,
        buffered::Mailbox<PublicKey, Block>,
    ) {
        buffered::Engine::new(
            context.child("buffer"),
            buffered::Config {
                public_key,
                mailbox_size: NZUsize!(mailbox_size),
                deque_size,
                priority: true,
                codec_config: (),
                peer_provider: provider,
            },
        )
    }

    async fn init_archives(
        context: &E,
        partition_prefix: &str,
        blocks_freezer_table_initial_size: u32,
        finalized_freezer_table_initial_size: u32,
        page_cache: &CacheRef,
    ) -> Archives<E> {
        let start = Instant::now();
        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalizations-by-height-metadata",
                    partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalizations-by-height-freezer-table",
                    partition_prefix
                ),
                freezer_table_initial_size: finalized_freezer_table_initial_size,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_key_partition: format!(
                    "{}-finalizations-by-height-freezer-key-journal",
                    partition_prefix
                ),
                freezer_key_page_cache: page_cache.clone(),
                freezer_key_write_buffer: WRITE_BUFFER,
                freezer_value_partition: format!(
                    "{}-finalizations-by-height-freezer-value-journal",
                    partition_prefix
                ),
                freezer_value_write_buffer: WRITE_BUFFER,
                freezer_value_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_value_compression: FREEZER_JOURNAL_COMPRESSION,
                ordinal_partition: format!("{}-finalizations-by-height-ordinal", partition_prefix),
                ordinal_write_buffer: WRITE_BUFFER,
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: Scheme::certificate_codec_config_unbounded(),
                replay_buffer: REPLAY_BUFFER,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");
        info!(elapsed = ?start.elapsed(), "restored finalizations by height archive");

        // Initialize finalized blocks
        let start = Instant::now();
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!("{}-finalized_blocks-metadata", partition_prefix),
                freezer_table_partition: format!(
                    "{}-finalized_blocks-freezer-table",
                    partition_prefix
                ),
                freezer_table_initial_size: blocks_freezer_table_initial_size,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_key_partition: format!(
                    "{}-finalized-blocks-freezer-key-journal",
                    partition_prefix
                ),
                freezer_key_page_cache: page_cache.clone(),
                freezer_key_write_buffer: WRITE_BUFFER,
                freezer_value_partition: format!(
                    "{}-finalized-blocks-freezer-value-journal",
                    partition_prefix
                ),
                freezer_value_write_buffer: WRITE_BUFFER,
                freezer_value_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_value_compression: FREEZER_JOURNAL_COMPRESSION,
                ordinal_partition: format!("{}-finalized-blocks-ordinal", partition_prefix),
                ordinal_write_buffer: WRITE_BUFFER,
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: (),
                replay_buffer: REPLAY_BUFFER,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

        Archives {
            finalizations_by_height,
            finalized_blocks,
        }
    }

    fn create_consensus_materials(
        participants: Set<PublicKey>,
        polynomial: Sharing<MinSig>,
        share: group::Share,
    ) -> ConsensusMaterials {
        let scheme = Scheme::signer(NAMESPACE, participants, polynomial, share)
            .expect("failed to create scheme");
        let certificate_provider = ConstantProvider::new(scheme.clone());
        let epocher = FixedEpocher::new(EPOCH_LENGTH);
        let genesis = Application::genesis();
        let genesis_digest = genesis.digest();

        ConsensusMaterials {
            scheme,
            certificate_provider,
            epocher,
            genesis,
            genesis_digest,
        }
    }

    async fn init_marshal(
        context: &E,
        inputs: MarshalInputs<E, S>,
    ) -> (Marshal<E, S>, MarshalMailbox<Scheme, Standard<Block>>) {
        let (marshal, marshal_mailbox, _) = MarshalActor::init(
            context.child("marshal"),
            inputs.archives.finalizations_by_height,
            inputs.archives.finalized_blocks,
            marshal::Config {
                provider: inputs.provider,
                epocher: inputs.epocher,
                partition_prefix: inputs.partition_prefix,
                mailbox_size: NZUsize!(inputs.mailbox_size),
                view_retention_timeout: ViewDelta::new(
                    inputs
                        .activity_timeout
                        .get()
                        .saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
                ),
                start: marshal::Start::Genesis(inputs.genesis),
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                replay_buffer: REPLAY_BUFFER,
                key_write_buffer: WRITE_BUFFER,
                value_write_buffer: WRITE_BUFFER,
                block_codec_config: (),
                max_repair: MAX_REPAIR,
                max_pending_acks: MAX_PENDING_ACKS,
                page_cache: inputs.page_cache,
                strategy: inputs.strategy,
            },
        )
        .await;

        (marshal, marshal_mailbox)
    }

    fn create_marshaled(
        context: &E,
        app: Application,
        marshal_mailbox: MarshalMailbox<Scheme, Standard<Block>>,
        epocher: FixedEpocher,
    ) -> Marshaled<E> {
        Marshaled::new(context.child("marshaled"), app, marshal_mailbox, epocher)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_consensus(
        context: &E,
        partition_prefix: String,
        mailbox_size: usize,
        leader_timeout: Duration,
        certification_timeout: Duration,
        nullify_retry: Duration,
        fetch_timeout: Duration,
        activity_timeout: ViewDelta,
        skip_timeout: ViewDelta,
        fetch_concurrent: usize,
        blocker: B,
        page_cache: CacheRef,
        scheme: Scheme,
        genesis_digest: Digest,
        marshaled: Marshaled<E>,
        marshal_mailbox: MarshalMailbox<Scheme, Standard<Block>>,
        strategy: S,
    ) -> ConsensusEngine<E, B, S> {
        Consensus::new(
            context.child("consensus"),
            simplex::Config {
                epoch: EPOCH,
                scheme,
                automaton: marshaled.clone(),
                relay: marshaled,
                reporter: marshal_mailbox,
                partition: format!("{}-consensus", partition_prefix),
                mailbox_size: NZUsize!(mailbox_size),
                floor: simplex::Floor::Genesis(genesis_digest),
                leader_timeout,
                certification_timeout,
                timeout_retry: nullify_retry,
                fetch_timeout,
                activity_timeout,
                skip_timeout,
                fetch_concurrent: NZUsize!(fetch_concurrent),
                forwarding: simplex::ForwardingPolicy::Disabled,
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
                blocker,
                page_cache,
                elector: Random,
                strategy,
            },
        )
    }

    /// Start the [simplex::Engine].
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        mut self,
        pending: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        recovered: (
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
        marshal: (
            handler::Receiver<Digest>,
            impl TargetedResolver<
                Key = handler::Key<Digest>,
                Subscriber = handler::Annotation,
                PublicKey = PublicKey,
            >,
        ),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(pending, recovered, resolver, broadcast, marshal)
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        self,
        pending: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        recovered: (
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
        marshal: (
            handler::Receiver<Digest>,
            impl TargetedResolver<
                Key = handler::Key<Digest>,
                Subscriber = handler::Annotation,
                PublicKey = PublicKey,
            >,
        ),
    ) {
        // Start the buffer
        let buffer_handle = self.buffer.start(broadcast);

        let reporters = Reporters::<Update<Block>, _, _>::from((self.marshaled, self.reporter));
        let marshal_handle = self.marshal.start(reporters, self.buffer_mailbox, marshal);

        // Start consensus
        //
        // We start the application prior to consensus to ensure we can handle enqueued events from consensus (otherwise
        // restart could block).
        let consensus_handle = self.consensus.start(pending, recovered, resolver);

        // Wait for any actor to finish. The transaction pool and coin executor run for the engine's
        // lifetime; including them here means a panic in either surfaces as an engine failure.
        let handles: Vec<Handle<()>> = vec![
            buffer_handle,
            marshal_handle,
            consensus_handle,
            self.executor,
            self.txpool,
        ];
        if let Err(e) = try_join_all(handles).await {
            error!(?e, "engine failed");
        } else {
            warn!("engine stopped");
        }
    }
}
