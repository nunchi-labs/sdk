//! Consensus engine orchestrator for epoch transitions.

use crate::{
    orchestrator::{ingress::Message, Mailbox},
    EpochProvider, Provider,
};
use commonware_actor::mailbox;
use commonware_consensus::{
    marshal::{core::Mailbox as MarshalMailbox, standard::Standard},
    simplex::{
        self, elector::Config as Elector, scheme, types::Activity, types::Context, Floor, Plan,
    },
    types::{Epoch, Epocher, FixedEpocher, Height, ViewDelta},
    CertifiableAutomaton, Relay, Reporter, Reporters,
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
    telemetry::metrics::{Gauge, GaugeExt, MetricsExt as _},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage,
};
use commonware_utils::{vec::NonEmptyVec, NZUsize, NZU16};
use rand_core::CryptoRngCore;
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::{debug, info, warn};

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

    pub _phantom: PhantomData<L>,
}

pub struct Actor<E, B, A, S, L, T, Blk, R = NoopReporter<Activity<S, Digest>>>
where
    E: BufferPooler + Spawner + Metrics + CryptoRngCore + Clock + Storage + Network,
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
    page_cache_ref: CacheRef,

    latest_epoch: Gauge,

    _phantom: PhantomData<L>,
}

impl<E, B, A, S, L, T, Blk, R> Actor<E, B, A, S, L, T, Blk, R>
where
    E: BufferPooler + Spawner + Metrics + CryptoRngCore + Clock + Storage + Network,
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
                page_cache_ref,
                latest_epoch,
                _phantom: PhantomData,
            },
            Mailbox::new(sender),
        )
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

                    // DKG state does not persist the consensus floor; derive it from marshal's
                    // finalized boundary block when entering each epoch.
                    let floor = match Self::floor_boundary(&epocher, transition.epoch) {
                        Some(boundary_height) => self
                            .marshal
                            .get_block(boundary_height)
                            .await
                            .unwrap_or_else(|| {
                                panic!(
                                    "missing finalized boundary block at height {} for epoch {}",
                                    boundary_height, transition.epoch
                                )
                            })
                            .digest(),
                        None => self.genesis_digest,
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

                    info!(epoch = %transition.epoch, "entered epoch");
                }
                Message::Exit(epoch) => {
                    // Remove the engine and abort it.
                    let Some(handle) = engines.remove(&epoch) else {
                        warn!(%epoch, "exited non-existent epoch");
                        continue;
                    };
                    handle.abort();

                    // Unregister the signing scheme for the epoch.
                    assert!(self.provider.unregister(&epoch));

                    info!(%epoch, "exited epoch");
                }
            },
        }
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

    async fn enter_epoch(
        &mut self,
        epoch: Epoch,
        floor: Digest,
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
                floor: Floor::Genesis(floor),
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
