use super::{
    state::{
        Dealer, Epoch as EpochState, Player, Reconciliation,
        ReconciliationPhase, Storage,
    },
    Mailbox, Message as MailboxMessage, PostUpdate, Update, UpdateCallBack,
};
use crate::{
    orchestrator::{self, EpochTransition},
    protector::StorageProtector,
    public::{transition_logs, DkgProtocolConfig, PublicCheckpoint, N3F1_FAULT_MODEL},
    setup::PeerConfig,
    validate_share, ReshareBlock, STATE_FORMAT_VERSION,
};
use commonware_actor::mailbox::{self, Receiver as ActorReceiver};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::types::{Epoch, EpochPhase, Epocher, FixedEpocher, Height};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{
            observe, DealerPrivMsg, DealerPubMsg, Info, Logs, Output, PlayerAck,
        },
        primitives::{
            group::Share,
            sharing::{Mode, ModeVersion},
            variant::{MinSig, Variant},
        },
    },
    ed25519::{self, Batch},
    sha256::Sha256,
    transcript::Summary,
    BatchVerifier, Hasher, PublicKey, Signer,
};
use commonware_macros::select_loop;
use commonware_math::algebra::Random;
use commonware_p2p::{utils::mux::Muxer, Manager, Receiver, Recipients, Sender, TrackedPeers};
use commonware_parallel::Sequential;
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{Counter, EncodeStruct, GaugeExt, GaugeFamily, MetricsExt as _},
    Buf, BufMut, BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner,
    Storage as RuntimeStorage,
};
use commonware_utils::{ordered::Set, Acknowledgement as _, N3f1, NZU32};
use rand::CryptoRng;
use std::{
    collections::BTreeMap,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
};
use tracing::{debug, error, info, warn};

/// Per-peer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
struct Peer<P: PublicKey> {
    peer: P,
}

/// Wire message type for DKG protocol communication.
pub enum Message<V: Variant, P: PublicKey> {
    /// A dealer message containing public and private components for a player.
    Dealer(DealerPubMsg<V>, DealerPrivMsg),
    /// A player acknowledgment sent back to a dealer.
    Ack(PlayerAck<P>),
}

impl<V: Variant, P: PublicKey> Write for Message<V, P> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Dealer(pub_msg, priv_msg) => {
                0u8.write(writer);
                pub_msg.write(writer);
                priv_msg.write(writer);
            }
            Self::Ack(ack) => {
                1u8.write(writer);
                ack.write(writer);
            }
        }
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for Message<V, P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealer(pub_msg, priv_msg) => pub_msg.encode_size() + priv_msg.encode_size(),
            Self::Ack(ack) => ack.encode_size(),
        }
    }
}

impl<V: Variant, P: PublicKey> Read for Message<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let tag = u8::read(reader)?;
        match tag {
            0 => {
                let pub_msg = DealerPubMsg::read_cfg(reader, cfg)?;
                let priv_msg = DealerPrivMsg::read(reader)?;
                Ok(Self::Dealer(pub_msg, priv_msg))
            }
            1 => {
                let ack = PlayerAck::read(reader)?;
                Ok(Self::Ack(ack))
            }
            _ => Err(CodecError::Invalid("dkg::Message", "Invalid type")),
        }
    }
}

pub struct Config<P> {
    pub manager: P,
    pub signer: ed25519::PrivateKey,
    pub mailbox_size: NonZeroUsize,
    pub execution: Execution,
    pub partition_prefix: String,
    pub peer_config: PeerConfig<ed25519::PublicKey>,
    pub max_supported_mode: ModeVersion,
    pub namespace: Vec<u8>,
    pub storage_protector: StorageProtector,
    pub epoch_length: NonZeroU64,
}

/// Authenticated public state used to reconcile protected DKG storage before
/// the actor enters consensus.
pub struct AuthenticatedBootstrap {
    pub config: DkgProtocolConfig,
    pub checkpoint: PublicCheckpoint,
    pub logs: Vec<crate::DealerLog>,
    pub initial_share: Option<Share>,
}

enum Bootstrap {
    Legacy {
        output: Option<Output<MinSig, ed25519::PublicKey>>,
        share: Option<Share>,
    },
    Authenticated(Box<AuthenticatedBootstrap>),
}

/// Execution mode for the DKG actor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Execution {
    /// Run on the runtime's shared executor.
    #[default]
    Shared,
    /// With a large validator set, run on a dedicated runtime thread.
    Dedicated,
}

pub struct Actor<E, P, B>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + RuntimeStorage,
    P: Manager<PublicKey = ed25519::PublicKey>,
    B: ReshareBlock,
{
    context: ContextCell<E>,
    manager: P,
    mailbox: ActorReceiver<MailboxMessage<B>>,
    signer: ed25519::PrivateKey,
    execution: Execution,
    peer_config: PeerConfig<ed25519::PublicKey>,
    partition_prefix: String,
    max_supported_mode: ModeVersion,
    namespace: Vec<u8>,
    storage_protector: StorageProtector,
    epoch_length: NonZeroU64,

    successful_epochs: Counter,
    failed_epochs: Counter,
    our_reveals: Counter,
    all_reveals: Counter,
    latest_share: GaugeFamily<Peer<ed25519::PublicKey>>,
    latest_ack: GaugeFamily<Peer<ed25519::PublicKey>>,
}

impl<E, P, B> Actor<E, P, B>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + RuntimeStorage,
    P: Manager<PublicKey = ed25519::PublicKey>,
    B: ReshareBlock,
    Batch: BatchVerifier<PublicKey = ed25519::PublicKey>,
{
    /// Create a new DKG [Actor] and its associated [Mailbox].
    pub fn new(context: E, config: Config<P>) -> (Self, Mailbox<B>) {
        // Create mailbox
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);

        // Create metrics
        let successful_epochs = context.counter("successful_epochs", "successful epochs");
        let failed_epochs = context.counter("failed_epochs", "failed epochs");
        let our_reveals = context.counter("our_reveals", "our share was revealed");
        let all_reveals = context.counter("all_reveals", "all share reveals");
        let latest_share = context.family(
            "latest_share",
            "epoch of latest valid share received per dealer",
        );
        let latest_ack = context.family(
            "latest_ack",
            "epoch of latest valid ack received per player",
        );

        (
            Self {
                context: ContextCell::new(context),
                manager: config.manager,
                mailbox,
                signer: config.signer,
                execution: config.execution,
                peer_config: config.peer_config,
                partition_prefix: config.partition_prefix,
                max_supported_mode: config.max_supported_mode,
                namespace: config.namespace,
                storage_protector: config.storage_protector,
                epoch_length: config.epoch_length,

                successful_epochs,
                failed_epochs,
                our_reveals,
                all_reveals,
                latest_share,
                latest_ack,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the DKG actor.
    pub fn start(
        self,
        output: Option<Output<MinSig, ed25519::PublicKey>>,
        share: Option<Share>,
        orchestrator: orchestrator::Mailbox<MinSig, ed25519::PublicKey>,
        dkg: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<MinSig, ed25519::PublicKey>>,
    ) -> Handle<()> {
        self.start_inner(
            Bootstrap::Legacy { output, share },
            orchestrator,
            dkg,
            callback,
        )
    }

    /// Start after reconciling protected storage with authenticated QMDB
    /// checkpoint and log state.
    pub fn start_authenticated(
        self,
        bootstrap: AuthenticatedBootstrap,
        orchestrator: orchestrator::Mailbox<MinSig, ed25519::PublicKey>,
        dkg: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<MinSig, ed25519::PublicKey>>,
    ) -> Handle<()> {
        self.start_inner(
            Bootstrap::Authenticated(Box::new(bootstrap)),
            orchestrator,
            dkg,
            callback,
        )
    }

    fn start_inner(
        mut self,
        bootstrap: Bootstrap,
        orchestrator: orchestrator::Mailbox<MinSig, ed25519::PublicKey>,
        dkg: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<MinSig, ed25519::PublicKey>>,
    ) -> Handle<()> {
        match self.execution {
            Execution::Shared => spawn_cell!(
                self.context,
                self.run(bootstrap, orchestrator, dkg, callback)
            ),
            Execution::Dedicated => {
                let context = self.context.take();
                context.dedicated().spawn(move |context| {
                    self.context.restore(context);
                    self.run(bootstrap, orchestrator, dkg, callback)
                })
            }
        }
    }

    async fn run(
        mut self,
        bootstrap: Bootstrap,
        mut orchestrator: orchestrator::Mailbox<MinSig, ed25519::PublicKey>,
        (sender, receiver): (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        mut callback: Box<dyn UpdateCallBack<MinSig, ed25519::PublicKey>>,
    ) {
        let max_read_size = NZU32!(self.peer_config.max_participants_per_round());
        let epocher = FixedEpocher::new(self.epoch_length);
        let self_pk = self.signer.public_key();

        // Initialize persistent state
        let mut storage = match Storage::init(
            self.context.child("storage"),
            &self.partition_prefix,
            self.storage_protector.clone(),
            self.namespace.clone(),
            self_pk.clone(),
            max_read_size,
            self.max_supported_mode,
        )
        .await
        {
            Ok(storage) => storage,
            Err(err) => {
                error!(%err, "failed to initialize DKG storage");
                return;
            }
        };
        match bootstrap {
            Bootstrap::Legacy { output, share } => {
                if storage.epoch().is_none() {
                    let initial_state = EpochState {
                        round: 0,
                        rng_seed: Summary::random(self.context.as_present_mut()),
                        output,
                        share,
                    };
                    if let Err(err) = storage.set_epoch(Epoch::zero(), initial_state).await {
                        error!(%err, "failed to persist initial DKG epoch");
                        return;
                    }
                }
            }
            Bootstrap::Authenticated(bootstrap) => {
                if let Err(err) = self
                    .reconcile_authenticated(&mut storage, *bootstrap, &self_pk)
                    .await
                {
                    error!(%err, "failed to reconcile authenticated DKG state");
                    return;
                }
            }
        }

        // Start a muxer for the physical channel used by DKG/reshare
        let (mux, mut dkg_mux) = Muxer::new(self.context.child("dkg_mux"), sender, receiver, 100);
        mux.start();

        'actor: loop {
            // Get latest epoch and state
            let (epoch, epoch_state) = storage.epoch().expect("epoch should be initialized");
            let is_dkg = epoch_state.output.is_none();

            // Prune everything older than the previous epoch
            if let Some(prev) = epoch.previous() {
                if let Err(err) = storage.prune(prev).await {
                    error!(%epoch, %prev, %err, "failed to prune DKG storage");
                    break 'actor;
                }
            }

            // Initialize dealer and player sets
            let (dealers, players, next_players) = if is_dkg {
                (
                    self.peer_config.participants.clone(),
                    self.peer_config.dealers(0),
                    Set::<ed25519::PublicKey>::default(),
                )
            } else {
                // In reshare mode, the initial dealer set must exactly match the players that
                // hold shares from the prior output.
                let dealers = self.peer_config.dealers(epoch_state.round);
                let previous_players = epoch_state.output.as_ref().unwrap().players();
                if epoch_state.round == 0 {
                    assert_eq!(
                        &dealers, previous_players,
                        "dealers for round 0 must equal previous output players"
                    );
                } else {
                    assert!(
                        dealers
                            .iter()
                            .all(|d| previous_players.position(d).is_some()),
                        "dealers for round {} must be drawn from previous output players",
                        epoch_state.round
                    );
                }

                (
                    dealers,
                    self.peer_config.dealers(epoch_state.round + 1),
                    self.peer_config.dealers(epoch_state.round + 2),
                )
            };

            // Primary = dealers (drive the DKG round/running consensus)
            // Secondary = current players + next-epoch players (give time to sync)
            //
            // Overlapping keys are deduplicated as primary (so we don't need to do any filtering here)
            self.manager.track(
                epoch.get(),
                TrackedPeers::new(
                    dealers.clone(),
                    Set::from_iter_dedup(players.iter().chain(next_players.iter()).cloned()),
                ),
            );

            let am_dealer = dealers.position(&self_pk).is_some();
            let am_player = players.position(&self_pk).is_some();

            // Inform the orchestrator of the epoch transition
            let transition: EpochTransition<MinSig, ed25519::PublicKey> = EpochTransition {
                epoch,
                poly: epoch_state.output.as_ref().map(|o| o.public().clone()),
                share: epoch_state.share.clone(),
                dealers: dealers.clone(),
            };
            orchestrator.enter(transition);

            // Register a channel for this round
            let (mut round_sender, mut round_receiver) = dkg_mux
                .register(epoch.get())
                .await
                .expect("should be able to create channel");

            // Prepare round info
            let round = Info::new::<N3f1>(
                &self.namespace,
                epoch.get(),
                epoch_state.output.clone(),
                Mode::NonZeroCounter,
                dealers,
                players.clone(),
            )
            .expect("round info configuration should be correct");

            // Initialize dealer state if we are a dealer (factory handles log submission check)
            let mut dealer_state: Option<Dealer<MinSig, ed25519::PrivateKey>> = (am_dealer
                && (is_dkg || epoch_state.share.is_some()))
                .then(|| {
                    storage.create_dealer::<ed25519::PrivateKey, N3f1>(
                        epoch,
                        self.signer.clone(),
                        round.clone(),
                        epoch_state.share.clone(),
                        epoch_state.rng_seed,
                    )
                })
                .flatten();

            // Initialize player state if we are a player
            let mut player_state: Option<Player<MinSig, ed25519::PrivateKey>> = am_player
                .then(|| {
                    storage.create_player::<ed25519::PrivateKey, N3f1>(
                        epoch,
                        self.signer.clone(),
                        round.clone(),
                    )
                })
                .flatten();

            select_loop! {
                self.context,
                on_stopped => {
                    break 'actor;
                },
                // Process incoming network messages
                network_msg = round_receiver.recv() => {
                    match network_msg {
                        Ok((sender_pk, msg_bytes)) => {
                            let msg = match Message::<MinSig, ed25519::PublicKey>::read_cfg(
                                &mut msg_bytes.clone(),
                                &max_read_size,
                            ) {
                                Ok(m) => m,
                                Err(e) => {
                                    warn!(?epoch, ?sender_pk, ?e, "failed to parse message");
                                    continue;
                                }
                            };
                            match msg {
                                Message::Dealer(pub_msg, priv_msg) => {
                                    if let Some(ref mut ps) = player_state {
                                        let response = ps
                                            .handle::<_, N3f1>(
                                                &mut storage,
                                                epoch,
                                                sender_pk.clone(),
                                                pub_msg,
                                                priv_msg,
                                            )
                                            .await;
                                        if let Some(ack) = response {
                                            let _ = self
                                                .latest_share
                                                .get_or_create_by(&sender_pk)
                                                .try_set_max(epoch.get());

                                            let payload =
                                                Message::<MinSig, ed25519::PublicKey>::Ack(ack).encode();
                                            let sent = round_sender.send(
                                                Recipients::One(sender_pk.clone()),
                                                payload,
                                                true,
                                            );
                                            if sent.is_empty() {
                                                warn!(
                                                    ?epoch,
                                                    dealer = ?sender_pk,
                                                    "failed to send ack"
                                                );
                                            }
                                        }
                                    }
                                }
                                Message::Ack(ack) => {
                                    if let Some(ref mut ds) = dealer_state {
                                        let added = ds
                                            .handle(&mut storage, epoch, sender_pk.clone(), ack)
                                            .await;
                                        if added {
                                            let _ = self
                                                .latest_ack
                                                .get_or_create_by(&sender_pk)
                                                .try_set_max(epoch.get());
                                        }
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            // Network closed
                            warn!(?err, "network closed");
                            break 'actor;
                        }
                    }
                },
                Some(mailbox_msg) = self.mailbox.recv() else {
                    warn!("dkg actor mailbox closed");
                    break 'actor;
                } => match mailbox_msg {
                    MailboxMessage::Act { response } => {
                        let outcome = dealer_state.as_ref().and_then(|ds| ds.finalized());
                        if outcome.is_some() {
                            info!("including reshare outcome in proposed block");
                        }
                        if response.send(outcome).is_err() {
                            warn!("dkg actor could not send response to Act");
                        }
                    }
                    MailboxMessage::Finalized { block, response } => {
                        let bounds = epocher
                            .containing(block.height())
                            .expect("block height covered by epoch strategy");
                        let block_epoch = bounds.epoch();
                        let phase = bounds.phase();
                        let relative_height = bounds.relative();
                        info!(epoch = %block_epoch, relative_height = %relative_height, "processing finalized block");

                        // Skip blocks from previous epochs (can happen on restart if we
                        // persisted state but crashed before acknowledging)
                        if block_epoch < epoch {
                            response.acknowledge();
                            continue;
                        }

                        // Process dealer log from block if present
                        if let Some(log) = block.reshare_log() {
                            if let Some((dealer, dealer_log)) = log.clone().check(&round) {
                                // If we see our dealing outcome in a finalized block,
                                // make sure to take it, so that we don't post
                                // it in subsequent blocks
                                if dealer == self_pk {
                                    if let Some(ref mut ds) = dealer_state {
                                        ds.take_finalized();
                                    }
                                }
                                if let Err(err) =
                                    storage.append_log(epoch, dealer, dealer_log).await
                                {
                                    error!(%epoch, %err, "failed to persist DKG log");
                                    break 'actor;
                                }
                            }
                        }

                        // In the first half of the epoch, continuously distribute shares
                        if phase == EpochPhase::Early {
                            if let Some(ref mut ds) = dealer_state {
                                Self::distribute_shares(
                                    &self_pk,
                                    &mut storage,
                                    epoch,
                                    ds,
                                    player_state.as_mut(),
                                    &mut round_sender,
                                )
                                .await;
                            }
                        }

                        // At or past the midpoint, finalize dealer if not already done.
                        if matches!(phase, EpochPhase::Midpoint | EpochPhase::Late) {
                            if let Some(ref mut ds) = dealer_state {
                                ds.finalize::<N3f1>();
                            }
                        }

                        // Continue if not the last block in the epoch
                        if block.height() != bounds.last() {
                            // Acknowledge block processing
                            response.acknowledge();
                            continue;
                        }

                        // Finalize the round before acknowledging
                        //
                        // TODO(#3453): Minimize end-of-epoch processing via pre-verify
                        let checked_logs = storage.logs(epoch);
                        let (success, next_round, next_output, next_share) =
                            if let Some(previous_output) = epoch_state.output.as_ref() {
                                let protocol_config = DkgProtocolConfig {
                                    state_format_version: STATE_FORMAT_VERSION,
                                    namespace: self.namespace.clone(),
                                    epoch_length: self.epoch_length,
                                    participants: self.peer_config.participants.clone(),
                                    num_participants_per_round: self
                                        .peer_config
                                        .num_participants_per_round
                                        .clone(),
                                    mode: Mode::NonZeroCounter,
                                    mode_version: 0,
                                    fault_model: N3F1_FAULT_MODEL,
                                    trusted_initial_identity: *previous_output.public().public(),
                                };
                                let checkpoint = PublicCheckpoint {
                                    format_version: STATE_FORMAT_VERSION,
                                    protocol_config_digest: protocol_config
                                        .digest()
                                        .expect("actor DKG configuration should be valid"),
                                    epoch,
                                    successful_round: epoch_state.round,
                                    activation_height: epoch
                                        .previous()
                                        .and_then(|previous| epocher.last(previous))
                                        .unwrap_or(Height::zero()),
                                    output: previous_output.clone(),
                                };
                                let public = match transition_logs::<_, _, Batch>(
                                    &protocol_config,
                                    &checkpoint,
                                    checked_logs.clone(),
                                    block.height(),
                                    self.context.as_present_mut(),
                                    &Sequential,
                                ) {
                                    Ok(public) => public,
                                    Err(err) => {
                                        error!(%epoch, %err, "failed public DKG transition");
                                        break 'actor;
                                    }
                                };
                                if !public.succeeded {
                                    (
                                        false,
                                        epoch_state.round,
                                        epoch_state.output.clone(),
                                        epoch_state.share.clone(),
                                    )
                                } else if let Some(ps) = player_state.take() {
                                    let mut player_logs = Logs::<_, _, N3f1>::new(round.clone());
                                    for (dealer, log) in checked_logs {
                                        player_logs.record(dealer, log);
                                    }
                                    match ps.finalize::<N3f1, Batch>(
                                        self.context.as_present_mut(),
                                        player_logs,
                                        &Sequential,
                                    ) {
                                        Ok((player_output, player_share))
                                            if player_output == public.checkpoint.output =>
                                        {
                                            if let Err(err) = validate_share(
                                                &player_output,
                                                &self_pk,
                                                &player_share,
                                            ) {
                                                error!(%epoch, %err, "derived DKG share is invalid");
                                                break 'actor;
                                            }
                                            (
                                                true,
                                                public.checkpoint.successful_round,
                                                Some(player_output),
                                                Some(player_share),
                                            )
                                        }
                                        Err(
                                            commonware_cryptography::bls12381::dkg::feldman_desmedt::Error::MissingPlayerDealing,
                                        ) => (
                                            true,
                                            public.checkpoint.successful_round,
                                            Some(public.checkpoint.output),
                                            None,
                                        ),
                                        Ok(_) | Err(_) => {
                                            error!(%epoch, "player result conflicts with public DKG transition");
                                            break 'actor;
                                        }
                                    }
                                } else {
                                    (
                                        true,
                                        public.checkpoint.successful_round,
                                        Some(public.checkpoint.output),
                                        None,
                                    )
                                }
                            } else {
                                let mut logs = Logs::<_, _, N3f1>::new(round.clone());
                                for (dealer, log) in checked_logs {
                                    logs.record(dealer, log);
                                }
                                if let Some(ps) = player_state.take() {
                                    match ps.finalize::<N3f1, Batch>(
                                        self.context.as_present_mut(),
                                        logs,
                                        &Sequential,
                                    ) {
                                        Ok((new_output, new_share)) => (
                                            true,
                                            epoch_state.round + 1,
                                            Some(new_output),
                                            Some(new_share),
                                        ),
                                        Err(_) => (
                                            false,
                                            epoch_state.round,
                                            epoch_state.output.clone(),
                                            epoch_state.share.clone(),
                                        ),
                                    }
                                } else {
                                    match observe::<_, _, N3f1, Batch>(
                                        self.context.as_present_mut(),
                                        logs,
                                        &Sequential,
                                    ) {
                                        Ok(output) => (
                                            true,
                                            epoch_state.round + 1,
                                            Some(output),
                                            None,
                                        ),
                                        Err(_) => (
                                            false,
                                            epoch_state.round,
                                            epoch_state.output.clone(),
                                            epoch_state.share.clone(),
                                        ),
                                    }
                                }
                            };
                        if success {
                            info!(?epoch, "epoch succeeded");
                            self.successful_epochs.inc();

                            // Record reveals
                            let output = next_output.as_ref().expect("output exists on success");
                            let revealed = output.revealed();
                            self.all_reveals.inc_by(revealed.len() as u64);
                            if revealed.position(&self_pk).is_some() {
                                self.our_reveals.inc();
                            }
                        } else {
                            warn!(?epoch, "epoch failed");
                            self.failed_epochs.inc();
                        }
                        if let Err(err) = storage
                            .set_epoch(
                                epoch.next(),
                                EpochState {
                                    round: next_round,
                                    rng_seed: Summary::random(self.context.as_present_mut()),
                                    output: next_output.clone(),
                                    share: next_share.clone(),
                                },
                            )
                            .await
                        {
                            error!(%epoch, %err, "failed to persist next DKG epoch");
                            break 'actor;
                        }

                        // Acknowledge block processing before callback
                        response.acknowledge();

                        // Send the callback.
                        let update = if success {
                            Update::Success {
                                epoch,
                                output: next_output.expect("ceremony output exists"),
                                share: next_share.clone(),
                            }
                        } else {
                            Update::Failure { epoch }
                        };

                        // Exit the engine for this epoch now that the boundary is finalized
                        orchestrator.exit(epoch);

                        // If the update is stop, wait forever.
                        if let PostUpdate::Stop = callback.on_update(update).await {
                            // Close the mailbox to prevent accepting any new messages
                            drop(self.mailbox);
                            // Keep running until killed to keep the orchestrator mailbox alive
                            info!("DKG complete; waiting for shutdown...");
                            futures::future::pending::<()>().await;
                            break 'actor;
                        }

                        break;
                    }
                },
            }
        }
        info!("exiting DKG actor");
    }

    async fn reconcile_authenticated(
        &mut self,
        storage: &mut Storage<E, MinSig, ed25519::PublicKey>,
        bootstrap: AuthenticatedBootstrap,
        self_pk: &ed25519::PublicKey,
    ) -> Result<(), ReconciliationError> {
        bootstrap
            .config
            .validate_checkpoint(&bootstrap.checkpoint)?;
        if bootstrap.config.namespace != self.namespace
            || bootstrap.config.epoch_length != self.epoch_length
            || bootstrap.config.participants != self.peer_config.participants
            || bootstrap.config.num_participants_per_round
                != self.peer_config.num_participants_per_round
        {
            return Err(ReconciliationError::LocalConfigurationMismatch);
        }
        let info = bootstrap.config.round_info(&bootstrap.checkpoint)?;
        let checkpoint_digest = Sha256::hash(&bootstrap.checkpoint.encode());
        if let Some(reconciliation) = storage.reconciliation() {
            if reconciliation.phase == ReconciliationPhase::Importing
                && (reconciliation.checkpoint_digest != checkpoint_digest
                    || reconciliation.target_epoch != bootstrap.checkpoint.epoch)
            {
                return Err(ReconciliationError::ImportInProgressConflict);
            }
        }
        let importing = Reconciliation {
            format_version: STATE_FORMAT_VERSION,
            checkpoint_digest,
            target_epoch: bootstrap.checkpoint.epoch,
            phase: ReconciliationPhase::Importing,
        };
        let complete = Reconciliation {
            phase: ReconciliationPhase::Complete,
            ..importing.clone()
        };
        let mut logs = BTreeMap::new();
        for signed in bootstrap.logs {
            let (dealer, log) = signed
                .check(&info)
                .ok_or(ReconciliationError::InvalidAuthenticatedLog)?;
            if let Some(existing) = logs.insert(dealer, log.clone()) {
                if existing != log {
                    return Err(ReconciliationError::ConflictingAuthenticatedLog);
                }
            }
        }

        let target_epoch = bootstrap.checkpoint.epoch;
        let mut rewrite_state = false;
        let share = match storage.epoch() {
            None if target_epoch == Epoch::zero() => {
                if let Some(share) = bootstrap.initial_share {
                    validate_share(&bootstrap.checkpoint.output, self_pk, &share)?;
                    Some(share)
                } else {
                    None
                }
            }
            None => None,
            Some((local_epoch, _)) if local_epoch > target_epoch => {
                return Err(ReconciliationError::LocalStateAhead)
            }
            Some((local_epoch, _)) if local_epoch < target_epoch => {
                rewrite_state = true;
                None
            }
            Some((_, local)) => {
                if local.round != bootstrap.checkpoint.successful_round
                    || local.output.as_ref() != Some(&bootstrap.checkpoint.output)
                {
                    return Err(ReconciliationError::MatchingEpochConflict);
                }
                if let Some(share) = local.share.as_ref() {
                    validate_share(&bootstrap.checkpoint.output, self_pk, share)?;
                }
                for (dealer, log) in &logs {
                    if let Some(existing) = storage.logs(target_epoch).get(dealer) {
                        if existing != log {
                            return Err(ReconciliationError::ConflictingAuthenticatedLog);
                        }
                    }
                }
                storage.set_reconciliation(importing).await?;
                for (dealer, log) in logs {
                    storage.append_log(target_epoch, dealer, log).await?;
                }
                storage.set_reconciliation(complete).await?;
                return Ok(());
            }
        };

        storage.set_reconciliation(importing).await?;
        for (dealer, log) in logs {
            if let Some(existing) = storage.logs(target_epoch).get(&dealer) {
                if existing != &log {
                    return Err(ReconciliationError::ConflictingAuthenticatedLog);
                }
                continue;
            }
            storage.append_log(target_epoch, dealer, log).await?;
        }
        if rewrite_state || storage.epoch().is_none() {
            storage
                .set_epoch(
                    target_epoch,
                    EpochState {
                        round: bootstrap.checkpoint.successful_round,
                        rng_seed: Summary::random(self.context.as_present_mut()),
                        output: Some(bootstrap.checkpoint.output),
                        share,
                    },
                )
                .await?;
        }
        storage.set_reconciliation(complete).await?;
        Ok(())
    }

    async fn distribute_shares<S: Sender<PublicKey = ed25519::PublicKey>>(
        self_pk: &ed25519::PublicKey,
        storage: &mut Storage<E, MinSig, ed25519::PublicKey>,
        epoch: Epoch,
        dealer_state: &mut Dealer<MinSig, ed25519::PrivateKey>,
        mut player_state: Option<&mut Player<MinSig, ed25519::PrivateKey>>,
        sender: &mut S,
    ) {
        for (player, pub_msg, priv_msg) in dealer_state.shares_to_distribute().collect::<Vec<_>>() {
            // Handle self-dealing if we are both dealer and player
            if player == *self_pk {
                if let Some(ref mut ps) = player_state {
                    // Handle as player
                    let ack = match ps
                        .handle::<_, N3f1>(storage, epoch, self_pk.clone(), pub_msg, priv_msg)
                        .await
                    {
                        Some(ack) => ack,
                        _ => continue,
                    };

                    // Handle our own ack as dealer
                    dealer_state
                        .handle(storage, epoch, self_pk.clone(), ack)
                        .await;
                }
                continue;
            }

            // Send to remote player
            let payload = Message::<MinSig, ed25519::PublicKey>::Dealer(pub_msg, priv_msg).encode();
            let success = sender.send(Recipients::One(player.clone()), payload, true);
            if success.is_empty() {
                debug!(?epoch, ?player, "failed to send share");
            } else {
                debug!(?epoch, ?player, "sent share");
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum ReconciliationError {
    #[error("authenticated public DKG state error: {0}")]
    Public(#[from] crate::public::Error),
    #[error("protected DKG storage error: {0}")]
    Storage(#[from] crate::state::Error),
    #[error("local DKG protocol configuration differs from authenticated state")]
    LocalConfigurationMismatch,
    #[error("authenticated dealer log is invalid")]
    InvalidAuthenticatedLog,
    #[error("authenticated dealer logs conflict")]
    ConflictingAuthenticatedLog,
    #[error("protected DKG state is ahead of authenticated QMDB state")]
    LocalStateAhead,
    #[error("protected DKG state conflicts with authenticated QMDB at the same epoch")]
    MatchingEpochConflict,
    #[error("a different authenticated DKG checkpoint import is already in progress")]
    ImportInProgressConflict,
}
