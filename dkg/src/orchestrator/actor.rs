//! Consensus engine orchestrator for epoch transitions.

use crate::{
    orchestrator::{ingress::Message, Mailbox},
    EpochProvider, Provider,
};
use commonware_actor::mailbox;
use commonware_consensus::{
    marshal::{core::Mailbox as MarshalMailbox, standard::Standard},
    simplex::{
        self, elector::Config as Elector, scheme, types::Activity, types::Context,
        types::Finalization, Floor, Plan,
    },
    types::{Epoch, Epocher, FixedEpocher, Height, ViewDelta},
    CertifiableAutomaton, Epochable, Relay, Reporter, Reporters,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Scheme, ed25519, sha256::Digest, Digestible,
};
use commonware_macros::select_loop;
use commonware_p2p::{
    utils::mux::{Builder, MuxHandle, Muxer},
    Blocker, Sender,
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef,
    spawn_cell,
    telemetry::metrics::{
        histogram::Buckets, CounterFamily, EncodeLabelSet, Gauge, GaugeExt, Histogram,
        MetricsExt as _,
    },
    BufferPooler, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage,
};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::U64;
use commonware_utils::{vec::NonEmptyVec, NZUsize, NZU16};
use rand::CryptoRng;
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::{debug, error, info, warn};

const CLEANUP_WATERMARK_KEY: U64 = U64::new(0);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct CleanupStatusLabel {
    status: &'static str,
}

/// Reporter that discards consensus activity.
pub struct NoopReporter<A> {
    _phantom: PhantomData<A>,
}

impl<A> Clone for NoopReporter<A> {
    fn clone(&self) -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<A> Default for NoopReporter<A> {
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<A: Send + 'static> Reporter for NoopReporter<A> {
    type Activity = A;

    fn report(&mut self, _: Self::Activity) -> commonware_actor::Feedback {
        commonware_actor::Feedback::Ok
    }
}

/// Configuration for the orchestrator.
pub struct Config<B, A, S, L, T, Blk, R = NoopReporter<Activity<S, Digest>>>
where
    B: Blocker<PublicKey = ed25519::PublicKey>,
    A: CertifiableAutomaton<Context = Context<Digest, ed25519::PublicKey>, Digest = Digest>
        + Relay<Digest = Digest, PublicKey = ed25519::PublicKey, Plan = Plan<ed25519::PublicKey>>,
    S: Scheme,
    L: Elector<S>,
    T: Strategy,
    Blk: commonware_consensus::Block
        + commonware_consensus::Heightable
        + commonware_consensus::CertifiableBlock<Context = Context<Digest, ed25519::PublicKey>>
        + Digestible<Digest = Digest>
        + Clone,
    R: Reporter<Activity = Activity<S, Digest>> + Clone,
{
    pub oracle: B,
    pub application: A,
    pub provider: Provider<S, ed25519::PrivateKey>,
    pub marshal: MarshalMailbox<S, Standard<Blk>>,
    pub reporter: R,
    pub strategy: T,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,

    pub muxer_size: usize,
    pub mailbox_size: NonZeroUsize,

    // Partition prefix used for orchestrator metadata persistence
    pub partition_prefix: String,
    pub epoch_length: NonZeroU64,
    pub genesis_digest: Digest,
    pub recovered_floor: Option<Finalization<S, Digest>>,
    pub startup_floor: Option<StartupFloor>,

    pub _phantom: PhantomData<L>,
}

/// A certified startup boundary that can anchor the first entered epoch when
/// local finalized block history is absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupFloor {
    pub height: Height,
    pub digest: Digest,
}

impl StartupFloor {
    fn digest_for_epoch(&self, epocher: &FixedEpocher, epoch: Epoch) -> Option<Digest> {
        Self::floor_boundary(epocher, epoch)
            .filter(|boundary| *boundary == self.height)
            .map(|_| self.digest)
    }

    // Epoch zero uses genesis as its floor; every later epoch is anchored by the
    // last finalized block from the previous epoch.
    fn floor_boundary(epocher: &FixedEpocher, epoch: Epoch) -> Option<Height> {
        let previous_epoch = epoch.previous()?;
        Some(
            epocher
                .last(previous_epoch)
                .expect("previous epoch should be covered by epoch strategy"),
        )
    }
}

pub struct Actor<E, B, A, S, L, T, Blk, R = NoopReporter<Activity<S, Digest>>>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + Storage + Network,
    B: Blocker<PublicKey = ed25519::PublicKey>,
    A: CertifiableAutomaton<Context = Context<Digest, ed25519::PublicKey>, Digest = Digest>
        + Relay<Digest = Digest, PublicKey = ed25519::PublicKey, Plan = Plan<ed25519::PublicKey>>,
    S: Scheme,
    L: Elector<S>,
    T: Strategy,
    Blk: commonware_consensus::Block
        + commonware_consensus::Heightable
        + commonware_consensus::CertifiableBlock<Context = Context<Digest, ed25519::PublicKey>>
        + Digestible<Digest = Digest>
        + Clone
        + Send
        + Sync
        + 'static,
    R: Reporter<Activity = Activity<S, Digest>> + Clone,
    Provider<S, ed25519::PrivateKey>:
        EpochProvider<Variant = MinSig, PublicKey = ed25519::PublicKey, Scheme = S>,
{
    context: ContextCell<E>,
    mailbox: mailbox::Receiver<Message<MinSig, ed25519::PublicKey>>,
    application: A,

    oracle: B,
    marshal: MarshalMailbox<S, Standard<Blk>>,
    reporter: R,
    provider: Provider<S, ed25519::PrivateKey>,
    strategy: T,
    leader_timeout: Duration,
    certification_timeout: Duration,

    muxer_size: usize,
    partition_prefix: String,
    epoch_length: NonZeroU64,
    genesis_digest: Digest,
    recovered_floor: Option<Finalization<S, Digest>>,
    startup_floor: Option<StartupFloor>,
    page_cache_ref: CacheRef,

    latest_epoch: Gauge,
    partition_cleanup_total: CounterFamily<CleanupStatusLabel>,
    partition_cleanup_watermark: Gauge,
    partitions_active: Gauge,
    partition_cleanup_duration: Histogram,

    _phantom: PhantomData<L>,
}

impl<E, B, A, S, L, T, Blk, R> Actor<E, B, A, S, L, T, Blk, R>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + Storage + Network,
    B: Blocker<PublicKey = ed25519::PublicKey>,
    A: CertifiableAutomaton<Context = Context<Digest, ed25519::PublicKey>, Digest = Digest>
        + Relay<Digest = Digest, PublicKey = ed25519::PublicKey, Plan = Plan<ed25519::PublicKey>>,
    S: scheme::Scheme<Digest, PublicKey = ed25519::PublicKey>,
    L: Elector<S>,
    T: Strategy,
    Blk: commonware_consensus::Block
        + commonware_consensus::Heightable
        + commonware_consensus::CertifiableBlock<Context = Context<Digest, ed25519::PublicKey>>
        + Digestible<Digest = Digest>
        + Clone
        + Send
        + Sync
        + 'static,
    R: Reporter<Activity = Activity<S, Digest>> + Clone,
    Provider<S, ed25519::PrivateKey>:
        EpochProvider<Variant = MinSig, PublicKey = ed25519::PublicKey, Scheme = S>,
{
    pub fn new(
        context: E,
        config: Config<B, A, S, L, T, Blk, R>,
    ) -> (Self, Mailbox<MinSig, ed25519::PublicKey>) {
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let page_cache_ref = CacheRef::from_pooler(&context, NZU16!(16_384), NZUsize!(10_000));

        // Register latest_epoch gauge for Grafana integration
        let latest_epoch = context.gauge("latest_epoch", "current epoch");
        let partition_cleanup_total = context.family(
            "consensus_partition_cleanup",
            "Total number of consensus partition cleanup outcomes",
        );
        let partition_cleanup_watermark = context.gauge(
            "consensus_partition_cleanup_watermark",
            "Next consensus epoch partition requiring cleanup",
        );
        let partitions_active = context.gauge(
            "consensus_partitions_active",
            "Number of consensus epoch partitions with active engines",
        );
        let partition_cleanup_duration = context.histogram(
            "consensus_partition_cleanup_duration_seconds",
            "Duration of consensus epoch partition cleanup operations",
            Buckets::LOCAL,
        );

        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                application: config.application,
                oracle: config.oracle,
                marshal: config.marshal,
                reporter: config.reporter,
                provider: config.provider,
                strategy: config.strategy,
                leader_timeout: config.leader_timeout,
                certification_timeout: config.certification_timeout,
                muxer_size: config.muxer_size,
                partition_prefix: config.partition_prefix,
                epoch_length: config.epoch_length,
                genesis_digest: config.genesis_digest,
                recovered_floor: config.recovered_floor,
                startup_floor: config.startup_floor,
                page_cache_ref,
                latest_epoch,
                partition_cleanup_total,
                partition_cleanup_watermark,
                partitions_active,
                partition_cleanup_duration,
                _phantom: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    pub fn set_startup_floor(&mut self, startup_floor: StartupFloor) {
        self.startup_floor = Some(startup_floor);
    }

    pub fn start(
        mut self,
        votes: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        ),
        certificates: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(votes, certificates, resolver,))
    }

    async fn run(
        mut self,
        (vote_sender, vote_receiver): (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        ),
        (certificate_sender, certificate_receiver): (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        ),
        (resolver_sender, resolver_receiver): (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        ),
    ) {
        // Start muxers for each physical channel used by consensus
        let (mux, mut vote_mux, mut vote_backup) = Muxer::builder(
            self.context.child("vote_mux"),
            vote_sender,
            vote_receiver,
            self.muxer_size,
        )
        .with_backup()
        .build();
        mux.start();
        let (mux, mut certificate_mux) = Muxer::builder(
            self.context.child("certificate_mux"),
            certificate_sender,
            certificate_receiver,
            self.muxer_size,
        )
        .build();
        mux.start();
        let (mux, mut resolver_mux) = Muxer::new(
            self.context.child("resolver_mux"),
            resolver_sender,
            resolver_receiver,
            self.muxer_size,
        );
        mux.start();

        // Wait for instructions to transition epochs.
        let epocher = FixedEpocher::new(self.epoch_length);
        let mut engines: BTreeMap<Epoch, Handle<()>> = BTreeMap::new();
        let cleanup_partition = format!("{}_cleanup-v1", self.partition_prefix);
        let mut cleanup_metadata = Metadata::<E, U64, U64>::init(
            self.context.child("partition_cleanup_metadata"),
            metadata::Config {
                partition: cleanup_partition,
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize consensus partition cleanup metadata");
        let mut next_epoch_to_clean = cleanup_metadata
            .get(&CLEANUP_WATERMARK_KEY)
            .cloned()
            .unwrap_or_else(|| U64::new(0));
        let _ = self
            .partition_cleanup_watermark
            .try_set(u64::from(&next_epoch_to_clean));
        let mut startup_cleanup_done = false;

        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping orchestrator");
            },
            Some((their_epoch, (from, _))) = vote_backup.recv() else {
                warn!("vote mux backup channel closed, shutting down orchestrator");
                break;
            } => {
                // If a message is received in an unregistered sub-channel in the vote network,
                // ensure we have the boundary finalization.
                let their_epoch = Epoch::new(their_epoch);
                let Some(our_epoch) = engines.keys().last().copied() else {
                    debug!(%their_epoch, ?from, "received message from unregistered epoch with no known epochs");
                    continue;
                };
                if their_epoch <= our_epoch {
                    debug!(%their_epoch, %our_epoch, ?from, "received message from past epoch");
                    continue;
                }

                // If we're not in the committee of the latest epoch we know about and we observe
                // another participant that is ahead of us, ensure we have the boundary finalization.
                // We target only the peer who claims to be ahead. If we receive messages from
                // multiple peers claiming to be ahead, each call adds them to the target set,
                // giving us more peers to try fetching from.
                let boundary_height = epocher.last(our_epoch).expect("our epoch should exist");
                debug!(
                    ?from,
                    %their_epoch,
                    %our_epoch,
                    %boundary_height,
                    "received backup message from future epoch, ensuring boundary finalization"
                );
                self.marshal
                    .hint_finalized(boundary_height, NonEmptyVec::new(from));
            },
            Some(transition) = self.mailbox.recv() else {
                warn!("mailbox closed, shutting down orchestrator");
                break;
            } => match transition {
                Message::Enter(transition) => {
                    // If the epoch is already in the map, ignore.
                    if engines.contains_key(&transition.epoch) {
                        warn!(epoch = %transition.epoch, "entered existing epoch");
                        continue;
                    }

                    if !startup_cleanup_done {
                        assert!(
                            u64::from(&next_epoch_to_clean) <= transition.epoch.get(),
                            "consensus partition cleanup watermark {} is ahead of first entering epoch {}",
                            u64::from(&next_epoch_to_clean),
                            transition.epoch,
                        );
                        if let Some(previous) = transition.epoch.previous() {
                            assert!(
                                !engines.keys().any(|epoch| *epoch <= previous),
                                "refusing to clean a consensus partition with an active engine"
                            );
                            self.cleanup_through(
                                &mut cleanup_metadata,
                                &mut next_epoch_to_clean,
                                previous,
                            )
                            .await;
                        }
                        startup_cleanup_done = true;
                    }

                    let Some(floor) = self.resolve_floor(&epocher, transition.epoch).await else {
                        break;
                    };

                    // Register the new signing scheme with the scheme provider.
                    let scheme = self.provider.scheme_for_epoch(&transition);
                    assert!(self.provider.register(transition.epoch, scheme.clone()));

                    // Enter the new epoch.
                    let handle = self
                        .enter_epoch(
                            transition.epoch,
                            floor,
                            scheme,
                            &mut vote_mux,
                            &mut certificate_mux,
                            &mut resolver_mux,
                        )
                        .await;
                    engines.insert(transition.epoch, handle);
                    let _ = self.latest_epoch.try_set(transition.epoch.get());
                    let _ = self.partitions_active.try_set(engines.len());

                    info!(epoch = %transition.epoch, "entered epoch");
                }
                Message::Exit(epoch) => {
                    // Remove the engine and abort it.
                    let Some(handle) = engines.remove(&epoch) else {
                        warn!(%epoch, "exited non-existent epoch");
                        continue;
                    };
                    handle.abort();
                    // Spawned task handles close their completion channel when aborted.
                    match handle.await {
                        Ok(())
                        | Err(commonware_runtime::Error::Aborted)
                        | Err(commonware_runtime::Error::Closed) => {}
                        Err(error) => {
                            panic!("consensus engine for epoch {epoch} failed while stopping: {error}")
                        }
                    }
                    let _ = self.partitions_active.try_set(engines.len());

                    // Unregister the signing scheme for the epoch.
                    assert!(self.provider.unregister(&epoch));

                    if u64::from(&next_epoch_to_clean) <= epoch.get() {
                        assert!(
                            !engines.keys().any(|active| *active <= epoch),
                            "refusing to clean a consensus partition with an active engine"
                        );
                        self.cleanup_through(
                            &mut cleanup_metadata,
                            &mut next_epoch_to_clean,
                            epoch,
                        )
                        .await;
                    }

                    info!(%epoch, "exited epoch");
                }
            },
        }
    }

    async fn cleanup_through(
        &mut self,
        metadata: &mut Metadata<E, U64, U64>,
        next_epoch_to_clean: &mut U64,
        through: Epoch,
    ) {
        while u64::from(&*next_epoch_to_clean) <= through.get() {
            let epoch = Epoch::new(u64::from(&*next_epoch_to_clean));
            let partition = format!("{}_consensus_{}", self.partition_prefix, epoch);
            let started = std::time::Instant::now();
            let status = match self.context.remove(&partition, None).await {
                Ok(()) => {
                    info!(%epoch, %partition, "removed retired consensus partition");
                    "removed"
                }
                Err(commonware_runtime::Error::PartitionMissing(_)) => {
                    info!(%epoch, %partition, "retired consensus partition already missing");
                    "missing"
                }
                Err(error) => {
                    self.partition_cleanup_total
                        .get_or_create(&CleanupStatusLabel { status: "failed" })
                        .inc();
                    self.partition_cleanup_duration
                        .observe(started.elapsed().as_secs_f64());
                    warn!(%epoch, %partition, %error, "failed to remove retired consensus partition");
                    panic!("failed to remove retired consensus partition {partition}: {error}");
                }
            };
            self.partition_cleanup_total
                .get_or_create(&CleanupStatusLabel { status })
                .inc();
            self.partition_cleanup_duration
                .observe(started.elapsed().as_secs_f64());

            let next = epoch
                .get()
                .checked_add(1)
                .expect("consensus cleanup watermark overflow");
            metadata
                .put_sync(CLEANUP_WATERMARK_KEY, U64::new(next))
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to persist consensus cleanup watermark after removing {partition}: {error}"
                    )
                });
            *next_epoch_to_clean = U64::new(next);
            let _ = self.partition_cleanup_watermark.try_set(next);
        }
    }

    async fn resolve_floor(
        &mut self,
        epocher: &FixedEpocher,
        epoch: Epoch,
    ) -> Option<Floor<S, Digest>> {
        if self
            .recovered_floor
            .as_ref()
            .is_some_and(|floor| floor.epoch() == epoch)
        {
            return Some(Floor::Finalized(
                self.recovered_floor
                    .take()
                    .expect("matching recovered floor must exist"),
            ));
        }

        let Some(boundary_height) = StartupFloor::floor_boundary(epocher, epoch) else {
            return Some(Floor::Genesis(self.genesis_digest));
        };

        if let Some(block) = self.marshal.get_block(boundary_height).await {
            return Some(Floor::Genesis(block.digest()));
        }

        if let Some(digest) = self
            .startup_floor
            .as_ref()
            .and_then(|startup_floor| startup_floor.digest_for_epoch(epocher, epoch))
        {
            return Some(Floor::Genesis(digest));
        }

        error!(
            %boundary_height,
            %epoch,
            "refusing to enter epoch without recovered floor, certified startup boundary, or local finalized boundary block"
        );
        None
    }

    async fn enter_epoch(
        &mut self,
        epoch: Epoch,
        floor: Floor<S, Digest>,
        scheme: S,
        vote_mux: &mut MuxHandle<
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        >,
        certificate_mux: &mut MuxHandle<
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        >,
        resolver_mux: &mut MuxHandle<
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        >,
    ) -> Handle<()> {
        // Start the new engine
        let elector = L::default();
        let context = self
            .context
            .child("consensus_engine")
            .with_attribute("epoch", epoch);
        let engine = simplex::Engine::new(
            context,
            simplex::Config {
                scheme,
                elector,
                blocker: self.oracle.clone(),
                automaton: self.application.clone(),
                relay: self.application.clone(),
                reporter: Reporters::from((self.marshal.clone(), self.reporter.clone())),
                partition: format!("{}_consensus_{}", self.partition_prefix, epoch),
                mailbox_size: NZUsize!(1024),
                epoch,
                floor,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                leader_timeout: self.leader_timeout,
                certification_timeout: self.certification_timeout,
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(256),
                skip_timeout: ViewDelta::new(10),
                fetch_concurrent: NZUsize!(32),
                page_cache: self.page_cache_ref.clone(),
                strategy: self.strategy.clone(),
                forwarding: simplex::ForwardingPolicy::Disabled,
            },
        );

        // Create epoch-specific subchannels
        let vote = vote_mux.register(epoch.get()).await.unwrap();
        let certificate = certificate_mux.register(epoch.get()).await.unwrap();
        let resolver = resolver_mux.register(epoch.get()).await.unwrap();
        engine.start(vote, certificate, resolver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZU64;

    #[test]
    fn startup_floor_only_matches_previous_epoch_boundary() {
        let epocher = FixedEpocher::new(NZU64!(10));
        let digest = Digest([9; 32]);
        let floor = StartupFloor {
            height: Height::new(19),
            digest,
        };

        assert_eq!(
            floor.digest_for_epoch(&epocher, Epoch::new(2)),
            Some(digest)
        );
        assert_eq!(floor.digest_for_epoch(&epocher, Epoch::new(1)), None);
        assert_eq!(floor.digest_for_epoch(&epocher, Epoch::zero()), None);
    }

    #[test]
    fn non_boundary_startup_floor_is_not_inferred() {
        let epocher = FixedEpocher::new(NZU64!(10));
        let floor = StartupFloor {
            height: Height::new(12),
            digest: Digest([7; 32]),
        };

        assert_eq!(floor.digest_for_epoch(&epocher, Epoch::new(2)), None);
    }
}
