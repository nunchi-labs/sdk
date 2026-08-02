use super::{
    state::{
        CreateDealerError, CreatePlayerError, Dealer, Epoch as EpochState, ExactInsert, Player,
        Reconciliation, ReconciliationPhase, Storage,
    },
    Mailbox, Message as MailboxMessage, PostUpdate, Update, UpdateCallBack,
};
use crate::{
    orchestrator::{self, EpochTransition},
    protector::StorageProtector,
    public::{transition_logs, DkgProtocolConfig, PublicCheckpoint, N3F1_FAULT_MODEL},
    recovery::{
        BundleProtector, DurableReceipt, RecoveryAssociatedData,
        RecoveryError, RecoveryMetadata, RecoveryPublication, RecoveryReadCfg, RecoverySink,
        BUNDLE_AD_DOMAIN, RECOVERY_ENVELOPE_VERSION,
    },
    setup::PeerConfig,
    validate_share, ReshareBlock, STATE_FORMAT_VERSION,
};
use commonware_actor::mailbox::{self, Receiver as ActorReceiver};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::types::{Epoch, EpochPhase, Epocher, FixedEpocher, Height};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{
            observe, Dealer as CryptoDealer, DealerPrivMsg, DealerPubMsg, Info, Logs, Output,
            Player as CryptoPlayer, PlayerAck,
        },
        primitives::{
            group::Share,
            sharing::{Mode, ModeVersion},
            variant::{MinSig, Variant},
        },
    },
    ed25519::{self, Batch},
    sha256::Sha256,
    transcript::{Summary, Transcript},
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
    time::UNIX_EPOCH,
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
    Prepared,
}

/// Authenticated DKG startup mode selected from pre-mutation storage state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupMode {
    GenesisInitialize,
    NormalReplay,
    DisasterRestore,
}

enum RecoveryPreparation {
    Disabled,
    Enabled {
        protector: BundleProtector,
        sink: Box<dyn RecoverySink>,
    },
}

/// Recovery startup configuration. Constructors prevent disabled startup from
/// carrying a sink or claiming recovery durability.
pub struct RecoveryConfig {
    state_sync: bool,
    preparation: RecoveryPreparation,
}

impl RecoveryConfig {
    pub const fn disabled(state_sync: bool) -> Self {
        Self {
            state_sync,
            preparation: RecoveryPreparation::Disabled,
        }
    }

    pub fn enabled(
        state_sync: bool,
        protector: BundleProtector,
        sink: Box<dyn RecoverySink>,
    ) -> Self {
        Self {
            state_sync,
            preparation: RecoveryPreparation::Enabled {
                protector,
                sink,
            },
        }
    }
}

enum RecoveryPolicy {
    DisabledOrdinary,
    Enabled {
        protector: BundleProtector,
        sink: Box<dyn RecoverySink>,
        associated_data: Box<RecoveryAssociatedData<ed25519::PublicKey>>,
        last_receipt: DurableReceipt,
    },
}

/// Typed, secret-free authenticated startup failure.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("protected DKG storage initialization failed")]
    Storage,
    #[error("authenticated DKG state reconciliation failed")]
    Reconciliation,
    #[error("partial or corrupt protected DKG storage")]
    InvalidPrimaryStorage,
    #[error("disaster restore requires recovery to be enabled")]
    RecoveryDisabled,
    #[error("no valid recovery candidate")]
    NoValidRecoveryCandidate,
    #[error("recovery operation failed: {0}")]
    Recovery(#[from] RecoveryError),
    #[error("system clock is before the Unix epoch")]
    ClockBeforeEpoch,
    #[error("system clock cannot be represented as Unix milliseconds")]
    ClockOverflow,
}

/// Fully initialized DKG state. This value is non-cloneable and consumed by
/// `start`, so no protocol endpoint can run before preparation succeeds.
pub struct PreparedDkg<E, P, B>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + RuntimeStorage,
    P: Manager<PublicKey = ed25519::PublicKey>,
    B: ReshareBlock,
{
    actor: Actor<E, P, B>,
    mode: StartupMode,
}

impl<E, P, B> PreparedDkg<E, P, B>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + RuntimeStorage,
    P: Manager<PublicKey = ed25519::PublicKey>,
    B: ReshareBlock,
    Batch: BatchVerifier<PublicKey = ed25519::PublicKey>,
{
    pub const fn mode(&self) -> StartupMode {
        self.mode
    }

    pub fn start(
        self,
        orchestrator: orchestrator::Mailbox<MinSig, ed25519::PublicKey>,
        dkg: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        callback: Box<dyn UpdateCallBack<MinSig, ed25519::PublicKey>>,
    ) -> Handle<()> {
        self.actor
            .start_inner(Bootstrap::Prepared, orchestrator, dkg, callback)
    }
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
    prepared_storage: Option<Storage<E, MinSig, ed25519::PublicKey>>,
    authoritative_checkpoint: Option<PublicCheckpoint>,
    recovery_policy: RecoveryPolicy,

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
                prepared_storage: None,
                authoritative_checkpoint: None,
                recovery_policy: RecoveryPolicy::DisabledOrdinary,

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

    /// Prepare authenticated DKG state without starting any protocol actor.
    pub async fn prepare_authenticated(
        mut self,
        bootstrap: AuthenticatedBootstrap,
        recovery: RecoveryConfig,
    ) -> Result<PreparedDkg<E, P, B>, StartupError> {
        bootstrap
            .config
            .validate_checkpoint(&bootstrap.checkpoint)
            .map_err(|_| StartupError::Reconciliation)?;
        if bootstrap.config.namespace != self.namespace
            || bootstrap.config.epoch_length != self.epoch_length
            || bootstrap.config.participants != self.peer_config.participants
            || bootstrap.config.num_participants_per_round
                != self.peer_config.num_participants_per_round
        {
            return Err(StartupError::Reconciliation);
        }

        let self_pk = self.signer.public_key();
        let max_read_size = NZU32!(self.peer_config.max_participants_per_round());
        let mut storage = Storage::init(
            self.context.child("storage"),
            &self.partition_prefix,
            self.storage_protector.clone(),
            self.namespace.clone(),
            self_pk.clone(),
            max_read_size,
            self.max_supported_mode,
        )
        .await
        .map_err(|_| StartupError::Storage)?;

        let mode = match storage.inspect() {
            crate::StorageInspection::Empty if recovery.state_sync => StartupMode::DisasterRestore,
            crate::StorageInspection::Empty => StartupMode::GenesisInitialize,
            crate::StorageInspection::Coherent => StartupMode::NormalReplay,
            crate::StorageInspection::Partial | crate::StorageInspection::Importing => {
                return Err(StartupError::InvalidPrimaryStorage);
            }
        };
        if mode == StartupMode::DisasterRestore
            && matches!(recovery.preparation, RecoveryPreparation::Disabled)
        {
            return Err(StartupError::RecoveryDisabled);
        }

        let checkpoint = bootstrap.checkpoint.clone();
        if mode == StartupMode::NormalReplay {
            storage.validate_complete_import(&checkpoint)?;
        }
        let associated_data = RecoveryAssociatedData {
            domain: BUNDLE_AD_DOMAIN.to_owned(),
            domain_version: RECOVERY_ENVELOPE_VERSION,
            protocol_config_digest: checkpoint.protocol_config_digest,
            namespace_digest: Sha256::hash(&self.namespace),
            validator: self_pk.clone(),
            partition_prefix: self.partition_prefix.clone(),
        };

        let mut enabled = match recovery.preparation {
            RecoveryPreparation::Disabled => None,
            RecoveryPreparation::Enabled {
                protector,
                sink,
            } => Some((protector, sink)),
        };

        if mode == StartupMode::DisasterRestore {
            let (protector, sink) = enabled.as_mut().expect("checked enabled policy");
            let candidates = sink.load_candidates().await?;
            let read_cfg = RecoveryReadCfg::new(max_read_size, self.max_supported_mode);
            let checkpoint_digest = Sha256::hash(&checkpoint.encode());
            let mut restored = false;
            for candidate in candidates.iter() {
                if candidate.metadata.checkpoint_epoch != checkpoint.epoch
                    || candidate.metadata.checkpoint_digest != checkpoint_digest
                {
                    continue;
                }
                let Ok(bundle) = protector.decrypt(&candidate.bundle, &associated_data, &read_cfg)
                else {
                    continue;
                };
                if self
                    .validate_recovery_candidate(&bundle, &bootstrap, &self_pk)
                    .is_err()
                {
                    continue;
                }
                match storage
                    .import_recovery_bundle(bundle, &checkpoint, candidate.bundle.digest())
                    .await
                {
                    Ok(()) => {
                        restored = true;
                        break;
                    }
                    Err(RecoveryError::Authentication
                    | RecoveryError::Codec(_)
                    | RecoveryError::TrailingBytes
                    | RecoveryError::UnsupportedFormat(_)
                    | RecoveryError::UnsupportedEnvelope(_)
                    | RecoveryError::InvalidMagic
                    | RecoveryError::Bound(_)
                    | RecoveryError::Identity(_)
                    | RecoveryError::Epoch
                    | RecoveryError::Checkpoint
                    | RecoveryError::Share
                    | RecoveryError::Log) => continue,
                    Err(error) => return Err(StartupError::Recovery(error)),
                }
            }
            if !restored {
                return Err(StartupError::NoValidRecoveryCandidate);
            }
        }

        self.reconcile_authenticated(&mut storage, bootstrap, &self_pk)
            .await
            .map_err(|_| StartupError::Reconciliation)?;

        self.recovery_policy = if let Some((protector, mut sink)) = enabled {
            let receipt = Self::publish_snapshot(
                self.context.as_present_mut(),
                &storage,
                &checkpoint,
                &protector,
                sink.as_mut(),
                &associated_data,
                match mode {
                    StartupMode::GenesisInitialize => RecoveryPublication::GenesisFirst,
                    StartupMode::NormalReplay => RecoveryPublication::NormalReplay,
                    StartupMode::DisasterRestore => RecoveryPublication::DisasterRestore,
                },
            )
            .await?;
            RecoveryPolicy::Enabled {
                protector,
                sink,
                associated_data: Box::new(associated_data),
                last_receipt: receipt,
            }
        } else {
            RecoveryPolicy::DisabledOrdinary
        };
        self.authoritative_checkpoint = Some(checkpoint);
        self.prepared_storage = Some(storage);
        Ok(PreparedDkg { actor: self, mode })
    }

    fn validate_recovery_candidate(
        &self,
        bundle: &crate::DkgRecoveryBundle<MinSig, ed25519::PublicKey>,
        bootstrap: &AuthenticatedBootstrap,
        self_pk: &ed25519::PublicKey,
    ) -> Result<(), RecoveryError> {
        let info = bootstrap
            .config
            .round_info(&bootstrap.checkpoint)
            .map_err(|_| RecoveryError::Checkpoint)?;
        let mut authenticated_logs = BTreeMap::new();
        for signed in &bootstrap.logs {
            let (dealer, log) = signed
                .clone()
                .check(&info)
                .ok_or(RecoveryError::Log)?;
            if authenticated_logs
                .insert(dealer, log.clone())
                .is_some_and(|existing| existing != log)
            {
                return Err(RecoveryError::Log);
            }
        }
        let current = bundle
            .epochs
            .iter()
            .find(|epoch| epoch.epoch == bootstrap.checkpoint.epoch);
        let recovered_logs = current
            .map(|epoch| epoch.logs.iter().cloned().collect::<BTreeMap<_, _>>())
            .unwrap_or_default();
        if recovered_logs != authenticated_logs {
            return Err(RecoveryError::Log);
        }

        if let Some(epoch) = current {
            if !epoch.dealings.is_empty() {
                let dealings = epoch.dealings.iter().map(|dealing| {
                    (
                        dealing.dealer.clone(),
                        dealing.public_message.clone(),
                        dealing.private_message.clone(),
                    )
                });
                let (_, generated) = CryptoPlayer::resume::<N3f1>(
                    info.clone(),
                    self.signer.clone(),
                    &authenticated_logs,
                    dealings,
                )
                .map_err(|_| RecoveryError::Share)?;
                if generated.len() != epoch.dealings.len() {
                    return Err(RecoveryError::Share);
                }
                for dealing in &epoch.dealings {
                    let mut bytes = dealing.acknowledgement.as_ref();
                    let persisted = PlayerAck::read(&mut bytes).map_err(|_| RecoveryError::Share)?;
                    if bytes.has_remaining()
                        || generated.get(&dealing.dealer) != Some(&persisted)
                    {
                        return Err(RecoveryError::Share);
                    }
                }
            }

            if let Some(local) = epoch.local_dealer.as_ref() {
                let (mut dealer, public, private) = CryptoDealer::start::<N3f1>(
                    Transcript::resume(bundle.epoch_state.rng_seed).noise(b"dealer-rng"),
                    info.clone(),
                    self.signer.clone(),
                    bundle.epoch_state.share.clone(),
                )
                .map_err(|_| RecoveryError::Share)?;
                let generated = private.into_iter().collect::<BTreeMap<_, _>>();
                let (persisted_public, recipients, signed_log) = match local {
                    crate::RecoveryDealer::Active {
                        public_message,
                        recipients,
                    } => (public_message, recipients, None),
                    crate::RecoveryDealer::Finalized {
                        public_message,
                        recipients,
                        signed_log,
                    } => (public_message, recipients, Some(signed_log)),
                };
                if &public != persisted_public || generated.len() != recipients.len() {
                    return Err(RecoveryError::Share);
                }
                for recipient in recipients {
                    match recipient {
                        crate::RecipientState::Unacknowledged {
                            player,
                            private_message,
                        } => {
                            if generated.get(player) != Some(private_message) {
                                return Err(RecoveryError::Share);
                            }
                        }
                        crate::RecipientState::Acknowledged {
                            player,
                            private_message,
                            ack,
                        } => {
                            if generated.get(player) != Some(private_message)
                                || dealer
                                    .receive_player_ack(player.clone(), ack.clone())
                                    .is_err()
                            {
                                return Err(RecoveryError::Share);
                            }
                        }
                    }
                }
                if let Some(signed_log) = signed_log {
                    let mut bytes = signed_log.as_ref();
                    let signed = crate::DealerLog::read_cfg(&mut bytes, &bootstrap.config.max_participants_per_round().try_into().map_err(|_| RecoveryError::Log)?)
                        .map_err(|_| RecoveryError::Log)?;
                    if bytes.has_remaining()
                        || signed.clone().check(&info).map(|(dealer, _)| dealer) != Some(self_pk.clone())
                    {
                        return Err(RecoveryError::Log);
                    }
                }
            }
        }
        Ok(())
    }

    async fn publish_snapshot(
        context: &mut E,
        storage: &Storage<E, MinSig, ed25519::PublicKey>,
        checkpoint: &PublicCheckpoint,
        protector: &BundleProtector,
        sink: &mut dyn RecoverySink,
        associated_data: &RecoveryAssociatedData<ed25519::PublicKey>,
        operation: RecoveryPublication,
    ) -> Result<DurableReceipt, StartupError> {
        let current = context.current();
        let elapsed = current
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StartupError::ClockBeforeEpoch)?;
        let created_at_ms = u64::try_from(elapsed.as_millis())
            .map_err(|_| StartupError::ClockOverflow)?;
        let bundle = storage.recovery_bundle(checkpoint.clone(), created_at_ms)?;
        let checkpoint_digest = bundle.checkpoint_digest;
        let checkpoint_epoch = bundle.checkpoint.epoch;
        let encrypted = protector.encrypt(&bundle, associated_data, context)?;
        let bundle_digest = encrypted.digest();
        let metadata = RecoveryMetadata {
            checkpoint_epoch,
            created_at_ms,
            checkpoint_digest,
        };
        let receipt = sink.publish(operation, encrypted, metadata).await?;
        if receipt.manifest_generation == 0 {
            return Err(RecoveryError::Receipt("manifest generation").into());
        }
        if receipt.checkpoint_epoch != checkpoint_epoch {
            return Err(RecoveryError::Receipt("checkpoint epoch").into());
        }
        if receipt.created_at_ms != created_at_ms {
            return Err(RecoveryError::Receipt("creation time").into());
        }
        if receipt.checkpoint_digest != checkpoint_digest {
            return Err(RecoveryError::Receipt("checkpoint digest").into());
        }
        if receipt.bundle_digest != bundle_digest {
            return Err(RecoveryError::Receipt("bundle digest").into());
        }
        Ok(receipt)
    }

    async fn export_authoritative(
        &mut self,
        storage: &Storage<E, MinSig, ed25519::PublicKey>,
    ) -> Result<(), StartupError> {
        let RecoveryPolicy::Enabled {
            protector,
            sink,
            associated_data,
            last_receipt,
        } = &mut self.recovery_policy
        else {
            return Ok(());
        };
        let checkpoint = self
            .authoritative_checkpoint
            .as_ref()
            .ok_or(RecoveryError::Checkpoint)?
            .clone();
        let receipt = Self::publish_snapshot(
            self.context.as_present_mut(),
            storage,
            &checkpoint,
            protector,
            sink.as_mut(),
            associated_data,
            RecoveryPublication::Runtime,
        )
        .await?;
        *last_receipt = receipt;
        Ok(())
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
        let authenticated_bootstrap = matches!(
            &bootstrap,
            Bootstrap::Prepared
        );

        let mut storage = if matches!(&bootstrap, Bootstrap::Prepared) {
            self.prepared_storage
                .take()
                .expect("PreparedDkg must carry initialized storage")
        } else {
            match Storage::init(
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
            Bootstrap::Prepared => {}
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
            let mut dealer_state: Option<Dealer<MinSig, ed25519::PrivateKey>> =
                if am_dealer && (is_dkg || epoch_state.share.is_some()) {
                    match storage.create_dealer::<ed25519::PrivateKey, N3f1>(
                        epoch,
                        self.signer.clone(),
                        round.clone(),
                        epoch_state.share.clone(),
                        epoch_state.rng_seed,
                    ).await {
                        Ok(dealer) => dealer,
                        Err(CreateDealerError::StateMismatch | CreateDealerError::InvalidSignedLog) => {
                            error!(%epoch, "persisted local dealer state is invalid");
                            break 'actor;
                        }
                        Err(err) => {
                            error!(%epoch, %err, "failed to initialize local dealer state");
                            break 'actor;
                        }
                    }
                } else {
                    None
                };
            if dealer_state.is_some() {
                if let Err(err) = self.export_authoritative(&storage).await {
                    error!(%epoch, %err, "failed to durably export local dealer initialization");
                    break 'actor;
                }
            }

            // Initialize player state if we are a player.
            let mut player_state: Option<Player<MinSig, ed25519::PrivateKey>> = if am_player {
                match storage.create_player::<ed25519::PrivateKey, N3f1>(
                    epoch,
                    self.signer.clone(),
                    round.clone(),
                ) {
                    Ok(player) => Some(player),
                    Err(CreatePlayerError::MissingPlayerDealing)
                        if authenticated_bootstrap && epoch_state.share.is_none() =>
                    {
                        warn!(
                            %epoch,
                            validator = ?self_pk,
                            authenticated_bootstrap,
                            has_share = false,
                            "continuing without DKG player state because authenticated public logs have no local private dealings"
                        );
                        None
                    }
                    Err(err) => {
                        error!(
                            %epoch,
                            validator = ?self_pk,
                            authenticated_bootstrap,
                            has_share = epoch_state.share.is_some(),
                            %err,
                            "failed to resume DKG player from protected storage"
                        );
                        break 'actor;
                    }
                }
            } else {
                None
            };

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
                                            if let Err(err) = self.export_authoritative(&storage).await {
                                                error!(%epoch, %err, "failed to durably export player acknowledgement");
                                                break 'actor;
                                            }
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
                                            if let Err(err) = self.export_authoritative(&storage).await {
                                                error!(%epoch, %err, "failed to durably export recipient acknowledgement");
                                                break 'actor;
                                            }
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
                                    let local_matches = storage
                                        .local_dealer(epoch)
                                        .is_some_and(|local| matches!(
                                            local,
                                            crate::RecoveryDealer::Finalized { signed_log, .. }
                                                if signed_log == log.encode()
                                        ));
                                    if !local_matches {
                                        error!(%epoch, "finalized local dealer log conflicts with retained signed bytes");
                                        break 'actor;
                                    }
                                    // The exact signed log is durable in the local-dealer
                                    // record and now also committed by the finalized block.
                                    // Drop the in-memory dealer so later midpoint blocks do
                                    // not attempt to finalize the already-consumed dealer.
                                    dealer_state = None;
                                }
                                let inserted = match storage.append_log(epoch, dealer, dealer_log).await {
                                    Ok(ExactInsert::Inserted) => true,
                                    Ok(ExactInsert::Identical) => false,
                                    Ok(ExactInsert::Conflict) => {
                                        error!(%epoch, "conflicting finalized DKG log");
                                        break 'actor;
                                    }
                                    Err(err) => {
                                        error!(%epoch, %err, "failed to persist DKG log");
                                        break 'actor;
                                    }
                                };
                                if inserted {
                                    if let Err(err) = self.export_authoritative(&storage).await {
                                        error!(%epoch, %err, "failed to durably export finalized dealer log");
                                        break 'actor;
                                    }
                                }
                            }
                        }

                        // In the first half of the epoch, continuously distribute shares
                        if phase == EpochPhase::Early {
                            if let Some(ref mut ds) = dealer_state {
                                let changed = Self::distribute_shares(
                                    &self_pk,
                                    &mut storage,
                                    epoch,
                                    ds,
                                    player_state.as_mut(),
                                    &mut round_sender,
                                )
                                .await;
                                if changed {
                                    if let Err(err) = self.export_authoritative(&storage).await {
                                        error!(%epoch, %err, "failed to durably export distribution updates");
                                        break 'actor;
                                    }
                                }
                            }
                        }

                        // At or past the midpoint, finalize dealer if not already done.
                        if matches!(phase, EpochPhase::Midpoint | EpochPhase::Late) {
                            if let Some(ref mut ds) = dealer_state {
                                let changed = ds.finalized().is_none();
                                if !ds.finalize::<_, N3f1>(&mut storage, epoch).await {
                                    error!(%epoch, "failed to persist finalized local dealer log");
                                    break 'actor;
                                }
                                if changed {
                                    if let Err(err) = self.export_authoritative(&storage).await {
                                        error!(%epoch, %err, "failed to durably export finalized local dealer");
                                        break 'actor;
                                    }
                                }
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
                        let (success, next_round, next_output, next_share, next_checkpoint) =
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
                                let checkpoint = self.authoritative_checkpoint.clone().unwrap_or_else(|| PublicCheckpoint {
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
                                });
                                if checkpoint.epoch != epoch
                                    || checkpoint.successful_round != epoch_state.round
                                    || &checkpoint.output != previous_output
                                {
                                    error!(%epoch, "authoritative checkpoint conflicts with active epoch state");
                                    break 'actor;
                                }
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
                                let next_checkpoint = public.checkpoint.clone();
                                if !public.succeeded {
                                    (
                                        false,
                                        epoch_state.round,
                                        epoch_state.output.clone(),
                                        epoch_state.share.clone(),
                                        Some(next_checkpoint),
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
                                                Some(next_checkpoint),
                                            )
                                        }
                                        Err(
                                            commonware_cryptography::bls12381::dkg::feldman_desmedt::Error::MissingPlayerDealing,
                                        ) => (
                                            true,
                                            public.checkpoint.successful_round,
                                            Some(public.checkpoint.output),
                                            None,
                                            Some(next_checkpoint),
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
                                        Some(next_checkpoint),
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
                                            None,
                                        ),
                                        Err(_) => (
                                            false,
                                            epoch_state.round,
                                            epoch_state.output.clone(),
                                            epoch_state.share.clone(),
                                            None,
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
                                            None,
                                        ),
                                        Err(_) => (
                                            false,
                                            epoch_state.round,
                                            epoch_state.output.clone(),
                                            epoch_state.share.clone(),
                                            None,
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

                        if let Some(next_checkpoint) = next_checkpoint {
                            if next_checkpoint.epoch != epoch.next()
                                || next_checkpoint.successful_round != next_round
                                || Some(&next_checkpoint.output) != next_output.as_ref()
                            {
                                error!(%epoch, "next checkpoint conflicts with persisted boundary state");
                                break 'actor;
                            }
                            self.authoritative_checkpoint = Some(next_checkpoint);
                        }
                        if let Err(err) = self.export_authoritative(&storage).await {
                            error!(%epoch, %err, "failed to durably export next epoch state");
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
    ) -> bool {
        let mut changed = false;
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
                    changed = true;

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
        changed
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
