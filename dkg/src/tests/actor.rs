use super::super::*;
use crate::state::{Epoch as EpochState, Storage};
use crate::{orchestrator::Message, protector::StorageProtector, ContinueOnUpdate, PeerConfig};
use bytes::{Buf, BufMut};
use commonware_actor::{mailbox, Feedback};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_consensus::types::Epoch;
use commonware_consensus::{types::Height, Heightable};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{deal, Dealer, DealerLog, Player, Verdict},
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey as Ed25519PublicKey},
    sha256,
    transcript::Summary,
    Digest as _, Digestible, Hasher, PublicKey, Signer,
};
use commonware_macros::test_traced;
use commonware_math::algebra::Random;
use commonware_p2p::{utils::mocks::inert_channel, PeerSetSubscription, Provider};
use commonware_runtime::{deterministic, Clock, Runner, Supervisor as _};
use commonware_utils::{channel::mpsc, N3f1, NZUsize, TryCollect, NZU32, NZU64};
use core::marker::PhantomData;
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

const TEST_STORAGE_KEY: [u8; 32] = [7u8; 32];

#[derive(Clone)]
struct TestBlock {
    height: Height,
    parent: sha256::Digest,
}

impl Write for TestBlock {
    fn write(&self, writer: &mut impl BufMut) {
        self.height.write(writer);
        self.parent.write(writer);
    }
}

impl Read for TestBlock {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::read(reader)?,
            parent: sha256::Digest::read(reader)?,
        })
    }
}

impl EncodeSize for TestBlock {
    fn encode_size(&self) -> usize {
        self.height.encode_size() + self.parent.encode_size()
    }
}

impl Digestible for TestBlock {
    type Digest = sha256::Digest;

    fn digest(&self) -> Self::Digest {
        sha256::Digest::EMPTY
    }
}

impl Heightable for TestBlock {
    fn height(&self) -> Height {
        self.height
    }
}

impl commonware_consensus::Block for TestBlock {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl crate::ReshareBlock for TestBlock {
    fn reshare_log(&self) -> Option<&crate::DealerLog> {
        None
    }
}

#[derive(Clone, Debug)]
struct NoopManager<P: PublicKey>(PhantomData<P>);

impl<P: PublicKey> Default for NoopManager<P> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<P: PublicKey> Provider for NoopManager<P> {
    type PublicKey = P;

    async fn peer_set(&mut self, _: u64) -> Option<commonware_p2p::TrackedPeers<Self::PublicKey>> {
        None
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
        let (_, rx) = mpsc::unbounded_channel();
        rx
    }
}

impl<P: PublicKey> commonware_p2p::Manager for NoopManager<P> {
    fn track<R>(&mut self, _: u64, _: R) -> Feedback
    where
        R: Into<commonware_p2p::TrackedPeers<Self::PublicKey>> + Send,
    {
        Feedback::Ok
    }
}

fn peer_config(
    total: u64,
    per_round: Vec<u32>,
) -> (
    PeerConfig<Ed25519PublicKey>,
    BTreeMap<Ed25519PublicKey, PrivateKey>,
) {
    let participants = (0..total)
        .map(|seed| {
            let signer = PrivateKey::from_seed(seed);
            (signer.public_key(), signer)
        })
        .collect::<BTreeMap<_, _>>();
    let peer_config = PeerConfig {
        num_participants_per_round: per_round,
        participants: participants.keys().cloned().try_collect().unwrap(),
    };
    (peer_config, participants)
}

fn finalized_dkg_log(
    namespace: &[u8],
    epoch: Epoch,
    dealers: commonware_utils::ordered::Set<Ed25519PublicKey>,
    players: commonware_utils::ordered::Set<Ed25519PublicKey>,
    participants: &BTreeMap<Ed25519PublicKey, PrivateKey>,
    dealer_pk: &Ed25519PublicKey,
) -> DealerLog<MinSig, Ed25519PublicKey> {
    let round = commonware_cryptography::bls12381::dkg::feldman_desmedt::Info::new::<N3f1>(
        namespace,
        epoch.get(),
        None,
        Mode::NonZeroCounter,
        dealers,
        players,
    )
    .expect("round info should be valid");
    let dealer_signer = participants
        .get(dealer_pk)
        .cloned()
        .expect("dealer signer should exist");
    let (mut dealer, public, private) = Dealer::<MinSig, _>::start::<N3f1>(
        commonware_utils::test_rng(),
        round.clone(),
        dealer_signer,
        None,
    )
    .expect("dealer should start");

    for (player_pk, private) in private {
        let player_signer = participants
            .get(&player_pk)
            .cloned()
            .expect("player signer should exist");
        let mut player = Player::new(round.clone(), player_signer).expect("player should start");
        let Verdict::Valid(ack) =
            player.dealer_message::<N3f1>(dealer_pk.clone(), public.clone(), private)
        else {
            panic!("valid dealing should be acknowledged");
        };
        dealer.receive_player_ack(player_pk, ack).unwrap();
    }

    dealer
        .finalize::<N3f1>()
        .check(&round)
        .expect("finalized log should check")
        .1
}

struct RecordingRecoverySink {
    publications: Arc<AtomicUsize>,
    candidates: Vec<crate::RecoveryCandidate>,
    operations: Arc<Mutex<Vec<crate::RecoveryPublication>>>,
    receipt_fault: Option<ReceiptFault>,
}

#[derive(Clone, Copy)]
enum ReceiptFault {
    Generation,
    Epoch,
    CreatedAt,
    Checkpoint,
    Bundle,
}

impl RecordingRecoverySink {
    fn new(publications: Arc<AtomicUsize>) -> Self {
        Self {
            publications,
            candidates: Vec::new(),
            operations: Arc::new(Mutex::new(Vec::new())),
            receipt_fault: None,
        }
    }
}

#[async_trait::async_trait]
impl crate::RecoverySink for RecordingRecoverySink {
    async fn load_candidates(
        &mut self,
    ) -> Result<Vec<crate::RecoveryCandidate>, crate::RecoveryError> {
        Ok(self.candidates.clone())
    }

    async fn publish(
        &mut self,
        operation: crate::RecoveryPublication,
        bundle: crate::EncryptedRecoveryBundle,
        metadata: crate::RecoveryMetadata,
    ) -> Result<crate::DurableReceipt, crate::RecoveryError> {
        self.publications.fetch_add(1, Ordering::SeqCst);
        self.operations.lock().unwrap().push(operation);
        let mut receipt = crate::DurableReceipt {
            manifest_generation: 1,
            checkpoint_epoch: metadata.checkpoint_epoch,
            created_at_ms: metadata.created_at_ms,
            checkpoint_digest: metadata.checkpoint_digest,
            bundle_digest: bundle.digest(),
        };
        match self.receipt_fault {
            Some(ReceiptFault::Generation) => receipt.manifest_generation = 0,
            Some(ReceiptFault::Epoch) => receipt.checkpoint_epoch = Epoch::new(u64::MAX),
            Some(ReceiptFault::CreatedAt) => {
                receipt.created_at_ms = receipt.created_at_ms.wrapping_add(1);
            }
            Some(ReceiptFault::Checkpoint) => {
                receipt.checkpoint_digest = sha256::Sha256::hash(b"wrong checkpoint");
            }
            Some(ReceiptFault::Bundle) => {
                receipt.bundle_digest = sha256::Sha256::hash(b"wrong bundle");
            }
            None => {}
        }
        Ok(receipt)
    }
}

#[test_traced]
fn authenticated_preparation_gates_all_protocol_startup_modes() {
    deterministic::Runner::seeded(21).start(|context| async move {
        let (peer_config, participants) = peer_config(4, vec![4]);
        let signer = participants.values().next().unwrap().clone();
        let (output, shares) = deal::<MinSig, _, N3f1>(
            commonware_utils::test_rng(),
            Mode::NonZeroCounter,
            peer_config.participants.clone(),
        )
        .unwrap();
        let protocol = crate::DkgProtocolConfig {
            state_format_version: crate::STATE_FORMAT_VERSION,
            namespace: b"test_dkg".to_vec(),
            epoch_length: NZU64!(200),
            participants: peer_config.participants.clone(),
            num_participants_per_round: vec![4],
            mode: Mode::NonZeroCounter,
            mode_version: 0,
            fault_model: crate::public::N3F1_FAULT_MODEL,
            trusted_initial_identity: *output.public().public(),
        };
        let checkpoint = crate::PublicCheckpoint::genesis(&protocol, output.clone()).unwrap();
        let bootstrap = |share| AuthenticatedBootstrap {
            config: protocol.clone(),
            checkpoint: checkpoint.clone(),
            logs: Vec::new(),
            initial_share: share,
        };
        let config = |partition_prefix: &str| Config {
            manager: NoopManager::<Ed25519PublicKey>::default(),
            signer: signer.clone(),
            mailbox_size: NZUsize!(8),
            execution: Execution::Shared,
            partition_prefix: partition_prefix.to_owned(),
            peer_config: peer_config.clone(),
            max_supported_mode: crate::MAX_SUPPORTED_MODE,
            namespace: b"test_dkg".to_vec(),
            storage_protector: StorageProtector::new(TEST_STORAGE_KEY),
            epoch_length: NZU64!(200),
        };
        let share = shares.get_value(&signer.public_key()).cloned();

        let (actor, _) = Actor::<_, _, TestBlock>::new(context.child("genesis"), config("prepared_genesis"));
        let prepared = actor
            .prepare_authenticated(bootstrap(share.clone()), RecoveryConfig::disabled(false))
            .await
            .unwrap_or_else(|error| panic!("genesis preparation failed: {error}"));
        assert_eq!(prepared.mode(), StartupMode::GenesisInitialize);

        let publications = Arc::new(AtomicUsize::new(0));
        let (actor, _) = Actor::<_, _, TestBlock>::new(context.child("enabled"), config("prepared_enabled"));
        let protectors = crate::RecoveryProtectors::new(TEST_STORAGE_KEY);
        let prepared = actor
            .prepare_authenticated(
                bootstrap(share.clone()),
                RecoveryConfig::enabled(
                    false,
                    protectors.bundle,
                    Box::new(RecordingRecoverySink::new(publications.clone())),
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("enabled preparation failed: {error}"));
        assert_eq!(prepared.mode(), StartupMode::GenesisInitialize);
        assert_eq!(publications.load(Ordering::SeqCst), 1);
        drop(prepared);

        let replay_operations = Arc::new(Mutex::new(Vec::new()));
        let (actor, _) = Actor::<_, _, TestBlock>::new(
            context.child("normal_replay"),
            config("prepared_enabled"),
        );
        let mut replay_sink = RecordingRecoverySink::new(publications.clone());
        replay_sink.operations = replay_operations.clone();
        let prepared = actor
            .prepare_authenticated(
                bootstrap(share.clone()),
                RecoveryConfig::enabled(
                    false,
                    crate::RecoveryProtectors::new(TEST_STORAGE_KEY).bundle,
                    Box::new(replay_sink),
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("normal replay preparation failed: {error}"));
        assert_eq!(prepared.mode(), StartupMode::NormalReplay);
        assert_eq!(
            replay_operations.lock().unwrap().as_slice(),
            &[crate::RecoveryPublication::NormalReplay]
        );

        let (actor, _) = Actor::<_, _, TestBlock>::new(context.child("disabled_restore"), config("prepared_restore"));
        let error = actor
            .prepare_authenticated(bootstrap(share), RecoveryConfig::disabled(true))
            .await
            .err()
            .expect("disabled disaster restore must fail");
        assert!(matches!(error, StartupError::RecoveryDisabled));
    });
}

#[test_traced]
fn authenticated_disaster_restore_skips_invalid_candidates_and_imports_valid_state() {
    deterministic::Runner::seeded(22).start(|context| async move {
        let (peer_config, participants) = peer_config(4, vec![4]);
        let signer = participants.values().next().unwrap().clone();
        let self_pk = signer.public_key();
        let (output, shares) = deal::<MinSig, _, N3f1>(
            commonware_utils::test_rng(),
            Mode::NonZeroCounter,
            peer_config.participants.clone(),
        )
        .unwrap();
        let protocol = crate::DkgProtocolConfig {
            state_format_version: crate::STATE_FORMAT_VERSION,
            namespace: b"test_dkg".to_vec(),
            epoch_length: NZU64!(200),
            participants: peer_config.participants.clone(),
            num_participants_per_round: vec![4],
            mode: Mode::NonZeroCounter,
            mode_version: 0,
            fault_model: crate::public::N3F1_FAULT_MODEL,
            trusted_initial_identity: *output.public().public(),
        };
        let checkpoint = crate::PublicCheckpoint::genesis(&protocol, output.clone()).unwrap();
        let partition_prefix = "authenticated_disaster_restore".to_owned();
        let checkpoint_digest = sha256::Sha256::hash(&checkpoint.encode());
        let bundle = crate::DkgRecoveryBundle {
            format_version: crate::recovery::RECOVERY_FORMAT_VERSION,
            protocol_config_digest: protocol.digest().unwrap(),
            namespace_digest: sha256::Sha256::hash(b"test_dkg"),
            validator: self_pk.clone(),
            partition_prefix: partition_prefix.clone(),
            checkpoint: checkpoint.clone(),
            checkpoint_digest,
            created_at_ms: 1,
            epoch_state: crate::RecoveryEpochState {
                epoch: Epoch::zero(),
                round: 0,
                rng_seed: Summary::random(commonware_utils::test_rng()),
                output: Some(output),
                share: shares.get_value(&self_pk).cloned(),
            },
            reconciliation: None,
            epochs: Vec::new(),
        };
        let associated_data = crate::RecoveryAssociatedData {
            domain: crate::recovery::BUNDLE_AD_DOMAIN.to_owned(),
            domain_version: crate::recovery::RECOVERY_ENVELOPE_VERSION,
            protocol_config_digest: checkpoint.protocol_config_digest,
            namespace_digest: sha256::Sha256::hash(b"test_dkg"),
            validator: self_pk,
            partition_prefix: partition_prefix.clone(),
        };
        let protectors = crate::RecoveryProtectors::new(TEST_STORAGE_KEY);
        let encrypted = protectors
            .bundle
            .encrypt(&bundle, &associated_data, &mut commonware_utils::TestRng::new(22))
            .unwrap();
        let valid = crate::RecoveryCandidate {
            bundle: encrypted.clone(),
            metadata: crate::RecoveryMetadata {
                checkpoint_epoch: checkpoint.epoch,
                created_at_ms: bundle.created_at_ms,
                checkpoint_digest,
            },
        };
        let mut wrong_metadata = valid.clone();
        wrong_metadata.metadata.checkpoint_epoch = Epoch::new(1);
        let mut corrupt = valid.clone();
        corrupt.bundle.nonce[0] ^= 1;
        let publications = Arc::new(AtomicUsize::new(0));
        let operations = Arc::new(Mutex::new(Vec::new()));
        let mut sink = RecordingRecoverySink::new(publications.clone());
        sink.candidates = vec![wrong_metadata, corrupt, valid];
        sink.operations = operations.clone();
        let (actor, _) = Actor::<_, _, TestBlock>::new(
            context.child("actor"),
            Config {
                manager: NoopManager::<Ed25519PublicKey>::default(),
                signer,
                mailbox_size: NZUsize!(8),
                execution: Execution::Shared,
                partition_prefix,
                peer_config,
                max_supported_mode: crate::MAX_SUPPORTED_MODE,
                namespace: b"test_dkg".to_vec(),
                storage_protector: StorageProtector::new(TEST_STORAGE_KEY),
                epoch_length: NZU64!(200),
            },
        );
        let prepared = actor
            .prepare_authenticated(
                AuthenticatedBootstrap {
                    config: protocol,
                    checkpoint,
                    logs: Vec::new(),
                    initial_share: bundle.epoch_state.share,
                },
                RecoveryConfig::enabled(
                    true,
                    crate::RecoveryProtectors::new(TEST_STORAGE_KEY).bundle,
                    Box::new(sink),
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("disaster restore failed: {error}"));
        assert_eq!(prepared.mode(), StartupMode::DisasterRestore);
        assert_eq!(publications.load(Ordering::SeqCst), 1);
        assert_eq!(
            operations.lock().unwrap().as_slice(),
            &[crate::RecoveryPublication::DisasterRestore]
        );
    });
}

#[test_traced]
fn recovery_candidate_validation_replays_player_and_finalized_dealer_state() {
    deterministic::Runner::seeded(25).start(|mut context| async move {
        let (peer_config, participants) = peer_config(4, vec![4]);
        let signer = participants.values().next().unwrap().clone();
        let self_pk = signer.public_key();
        let (output, shares) = deal::<MinSig, _, N3f1>(
            commonware_utils::test_rng(),
            Mode::NonZeroCounter,
            peer_config.participants.clone(),
        )
        .unwrap();
        let protocol = crate::DkgProtocolConfig {
            state_format_version: crate::STATE_FORMAT_VERSION,
            namespace: b"test_dkg".to_vec(),
            epoch_length: NZU64!(200),
            participants: peer_config.participants.clone(),
            num_participants_per_round: vec![4],
            mode: Mode::NonZeroCounter,
            mode_version: 0,
            fault_model: crate::public::N3F1_FAULT_MODEL,
            trusted_initial_identity: *output.public().public(),
        };
        let checkpoint = crate::PublicCheckpoint::genesis(&protocol, output.clone()).unwrap();
        let bootstrap = AuthenticatedBootstrap {
            config: protocol.clone(),
            checkpoint: checkpoint.clone(),
            logs: Vec::new(),
            initial_share: shares.get_value(&self_pk).cloned(),
        };
        let info = protocol.round_info(&checkpoint).unwrap();
        let epoch = checkpoint.epoch;
        let rng_seed = Summary::random(&mut context);
        let partition_prefix = "validated_recovery_candidate";
        let mut storage = Storage::<_, MinSig, Ed25519PublicKey>::init(
            context.child("storage"),
            partition_prefix,
            StorageProtector::new(TEST_STORAGE_KEY),
            b"test_dkg".to_vec(),
            self_pk.clone(),
            NZU32!(4),
            crate::MAX_SUPPORTED_MODE,
        )
        .await
        .unwrap();
        storage
            .set_epoch(
                epoch,
                EpochState {
                    round: checkpoint.successful_round,
                    rng_seed,
                    output: Some(output),
                    share: bootstrap.initial_share.clone(),
                },
            )
            .await
            .unwrap();

        let external_signer = participants
            .values()
            .find(|candidate| candidate.public_key() != self_pk)
            .unwrap()
            .clone();
        let external_pk = external_signer.public_key();
        let (_, public_message, private_messages) = Dealer::<MinSig, _>::start::<N3f1>(
            commonware_utils::test_rng(),
            info.clone(),
            external_signer,
            shares.get_value(&external_pk).cloned(),
        )
        .unwrap();
        let private_message = private_messages
            .into_iter()
            .find(|(player, _)| player == &self_pk)
            .unwrap()
            .1;
        let mut player = Player::new(info.clone(), signer.clone()).unwrap();
        let Verdict::Valid(ack) = player.dealer_message::<N3f1>(
            external_pk.clone(),
            public_message.clone(),
            private_message.clone(),
        ) else {
            panic!("valid external dealing should be acknowledged");
        };
        storage
            .append_dealing(
                epoch,
                external_pk,
                public_message,
                private_message,
                ack.encode(),
            )
            .await
            .unwrap();

        let mut local = storage
            .create_dealer::<_, N3f1>(
                epoch,
                signer.clone(),
                info.clone(),
                bootstrap.initial_share.clone(),
                rng_seed,
            )
            .await
            .unwrap()
            .unwrap();
        let outgoing = local
            .shares_to_distribute()
            .map(|(player, public, private)| (player, public.clone(), private))
            .collect::<Vec<_>>();
        for (player_pk, public, private) in outgoing {
            let player_signer = participants.get(&player_pk).unwrap().clone();
            let mut player = Player::new(info.clone(), player_signer).unwrap();
            let Verdict::Valid(ack) =
                player.dealer_message::<N3f1>(self_pk.clone(), public, private)
            else {
                panic!("valid local dealing should be acknowledged");
            };
            assert!(local.handle(&mut storage, epoch, player_pk, ack).await);
        }
        assert!(local.finalize::<_, N3f1>(&mut storage, epoch).await);
        drop(local);
        let replayed = storage
            .create_dealer::<_, N3f1>(
                epoch,
                signer.clone(),
                info,
                bootstrap.initial_share.clone(),
                rng_seed,
            )
            .await
            .unwrap()
            .expect("finalized local dealer should replay");
        assert!(replayed.finalized().is_some());

        let mut bundle = storage.recovery_bundle(checkpoint.clone(), 25).unwrap();
        let import_partition = "validated_recovery_candidate_import";
        bundle.partition_prefix = import_partition.to_owned();
        let associated_data = crate::RecoveryAssociatedData {
            domain: crate::recovery::BUNDLE_AD_DOMAIN.to_owned(),
            domain_version: crate::recovery::RECOVERY_ENVELOPE_VERSION,
            protocol_config_digest: checkpoint.protocol_config_digest,
            namespace_digest: sha256::Sha256::hash(b"test_dkg"),
            validator: self_pk.clone(),
            partition_prefix: import_partition.to_owned(),
        };
        let encrypt = |candidate: &crate::DkgRecoveryBundle<MinSig, Ed25519PublicKey>, seed| {
            crate::RecoveryProtectors::new(TEST_STORAGE_KEY)
                .bundle
                .encrypt(
                    candidate,
                    &associated_data,
                    &mut commonware_utils::TestRng::new(seed),
                )
                .unwrap()
        };

        let mut invalid_ack = bundle.clone();
        let mut acknowledgement = invalid_ack.epochs[0].dealings[0]
            .acknowledgement
            .to_vec();
        acknowledgement.push(0);
        invalid_ack.epochs[0].dealings[0].acknowledgement = acknowledgement.into();
        let mut invalid_log = bundle.clone();
        let Some(crate::RecoveryDealer::Finalized { signed_log, .. }) =
            invalid_log.epochs[0].local_dealer.as_mut()
        else {
            panic!("finalized dealer should be persisted");
        };
        let mut trailing_log = signed_log.to_vec();
        trailing_log.push(0);
        *signed_log = trailing_log.into();
        let metadata = crate::RecoveryMetadata {
            checkpoint_epoch: checkpoint.epoch,
            created_at_ms: bundle.created_at_ms,
            checkpoint_digest: bundle.checkpoint_digest,
        };
        let publications = Arc::new(AtomicUsize::new(0));
        let mut sink = RecordingRecoverySink::new(publications.clone());
        sink.candidates = vec![
            crate::RecoveryCandidate {
                bundle: encrypt(&invalid_ack, 25),
                metadata,
            },
            crate::RecoveryCandidate {
                bundle: encrypt(&invalid_log, 26),
                metadata,
            },
            crate::RecoveryCandidate {
                bundle: encrypt(&bundle, 27),
                metadata,
            },
        ];
        let (actor, _) = Actor::<_, _, TestBlock>::new(
            context.child("actor"),
            Config {
                manager: NoopManager::<Ed25519PublicKey>::default(),
                signer,
                mailbox_size: NZUsize!(8),
                execution: Execution::Shared,
                partition_prefix: import_partition.to_owned(),
                peer_config,
                max_supported_mode: crate::MAX_SUPPORTED_MODE,
                namespace: b"test_dkg".to_vec(),
                storage_protector: StorageProtector::new(TEST_STORAGE_KEY),
                epoch_length: NZU64!(200),
            },
        );
        let prepared = actor
            .prepare_authenticated(
                bootstrap,
                RecoveryConfig::enabled(
                    true,
                    crate::RecoveryProtectors::new(TEST_STORAGE_KEY).bundle,
                    Box::new(sink),
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("rich recovery candidate failed: {error}"));
        assert_eq!(prepared.mode(), StartupMode::DisasterRestore);
        assert_eq!(publications.load(Ordering::SeqCst), 1);
    });
}

#[test_traced]
fn authenticated_preparation_rejects_empty_restore_and_invalid_receipts() {
    deterministic::Runner::seeded(23).start(|context| async move {
        let (peer_config, participants) = peer_config(4, vec![4]);
        let signer = participants.values().next().unwrap().clone();
        let (output, shares) = deal::<MinSig, _, N3f1>(
            commonware_utils::test_rng(),
            Mode::NonZeroCounter,
            peer_config.participants.clone(),
        )
        .unwrap();
        let protocol = crate::DkgProtocolConfig {
            state_format_version: crate::STATE_FORMAT_VERSION,
            namespace: b"test_dkg".to_vec(),
            epoch_length: NZU64!(200),
            participants: peer_config.participants.clone(),
            num_participants_per_round: vec![4],
            mode: Mode::NonZeroCounter,
            mode_version: 0,
            fault_model: crate::public::N3F1_FAULT_MODEL,
            trusted_initial_identity: *output.public().public(),
        };
        let checkpoint = crate::PublicCheckpoint::genesis(&protocol, output).unwrap();
        let share = shares.get_value(&signer.public_key()).cloned();
        let bootstrap = || AuthenticatedBootstrap {
            config: protocol.clone(),
            checkpoint: checkpoint.clone(),
            logs: Vec::new(),
            initial_share: share.clone(),
        };
        let config = |partition_prefix: String| Config {
            manager: NoopManager::<Ed25519PublicKey>::default(),
            signer: signer.clone(),
            mailbox_size: NZUsize!(8),
            execution: Execution::Shared,
            partition_prefix,
            peer_config: peer_config.clone(),
            max_supported_mode: crate::MAX_SUPPORTED_MODE,
            namespace: b"test_dkg".to_vec(),
            storage_protector: StorageProtector::new(TEST_STORAGE_KEY),
            epoch_length: NZU64!(200),
        };

        let (actor, _) = Actor::<_, _, TestBlock>::new(
            context.child("empty_restore"),
            config("empty_restore".to_owned()),
        );
        let error = actor
            .prepare_authenticated(
                bootstrap(),
                RecoveryConfig::enabled(
                    true,
                    crate::RecoveryProtectors::new(TEST_STORAGE_KEY).bundle,
                    Box::new(RecordingRecoverySink::new(Arc::new(AtomicUsize::new(0)))),
                ),
            )
            .await
            .err()
            .expect("empty recovery candidate set must fail");
        assert!(matches!(error, StartupError::NoValidRecoveryCandidate));

        for (index, fault) in [
            ReceiptFault::Generation,
            ReceiptFault::Epoch,
            ReceiptFault::CreatedAt,
            ReceiptFault::Checkpoint,
            ReceiptFault::Bundle,
        ]
        .into_iter()
        .enumerate()
        {
            let (actor, _) = Actor::<_, _, TestBlock>::new(
                context.child("invalid_receipt"),
                config(format!("invalid_receipt_{index}")),
            );
            let mut sink = RecordingRecoverySink::new(Arc::new(AtomicUsize::new(0)));
            sink.receipt_fault = Some(fault);
            let error = actor
                .prepare_authenticated(
                    bootstrap(),
                    RecoveryConfig::enabled(
                        false,
                        crate::RecoveryProtectors::new(TEST_STORAGE_KEY).bundle,
                        Box::new(sink),
                    ),
                )
                .await
                .err()
                .expect("invalid durable receipt must fail");
            assert!(matches!(error, StartupError::Recovery(crate::RecoveryError::Receipt(_))));
        }
    });
}

fn assert_recovered_storage_controls_dkg_mode_on_restart(execution: Execution, suffix: &str) {
    let executor = deterministic::Runner::seeded(8);
    executor.start(|mut context| async move {
        const RECOVERED_EPOCH: u64 = 5;
        const RECOVERED_ROUND: u64 = 5;
        let (peer_config, participants) = peer_config(6, vec![4]);
        let first_player = peer_config
            .dealers(RECOVERED_ROUND)
            .iter()
            .next()
            .cloned()
            .expect("recovered dealer exists");
        let signer = participants
            .get(&first_player)
            .cloned()
            .expect("signer should exist");
        let (output, shares) = deal::<MinSig, _, N3f1>(
            &mut context,
            Default::default(),
            peer_config.dealers(RECOVERED_ROUND),
        )
        .expect("deal should succeed");
        let share = shares.get_value(&first_player).cloned();
        let partition_prefix = format!("recovered_restart_{suffix}_{first_player}");

        let mut storage = Storage::<_, MinSig, Ed25519PublicKey>::init(
            context.child("seed_storage"),
            &partition_prefix,
            StorageProtector::new(TEST_STORAGE_KEY),
            b"test_dkg".to_vec(),
            first_player.clone(),
            NZU32!(peer_config.max_participants_per_round()),
            crate::MAX_SUPPORTED_MODE,
        )
        .await
        .expect("storage init should succeed");
        storage
            .set_epoch(
                Epoch::new(RECOVERED_EPOCH),
                EpochState {
                    round: RECOVERED_ROUND,
                    rng_seed: Summary::random(&mut context),
                    output: Some(output),
                    share,
                },
            )
            .await
            .expect("set epoch should succeed");
        drop(storage);

        let (actor, _mailbox) = Actor::<_, _, TestBlock>::new(
            context.child("actor"),
            Config {
                manager: NoopManager::<Ed25519PublicKey>::default(),
                signer,
                mailbox_size: NZUsize!(8),
                execution,
                partition_prefix,
                peer_config: peer_config.clone(),
                max_supported_mode: crate::MAX_SUPPORTED_MODE,
                namespace: b"test_dkg".to_vec(),
                storage_protector: StorageProtector::new(TEST_STORAGE_KEY),
                epoch_length: NZU64!(200),
            },
        );
        let (sender, receiver) = inert_channel(&peer_config.participants);
        let (orchestrator_sender, mut orchestrator_receiver) =
            mailbox::new(context.child("orchestrator_mailbox"), NZUsize!(4));
        let handle = actor.start(
            None,
            None,
            crate::orchestrator::Mailbox::new(orchestrator_sender),
            (sender, receiver),
            ContinueOnUpdate::boxed(),
        );

        let Some(Message::Enter(transition)) = orchestrator_receiver.recv().await else {
            panic!("actor should emit an epoch transition");
        };
        assert_eq!(transition.epoch, Epoch::new(RECOVERED_EPOCH));
        assert!(transition.poly.is_some());
        assert_eq!(transition.dealers, peer_config.dealers(RECOVERED_ROUND));

        handle.abort();
        let _ = handle.await;
    });
}

#[test_traced]
fn default_execution_recovered_storage_controls_dkg_mode_on_restart() {
    assert_recovered_storage_controls_dkg_mode_on_restart(Execution::default(), "shared");
}

#[test_traced]
fn dedicated_execution_recovered_storage_controls_dkg_mode_on_restart() {
    assert_recovered_storage_controls_dkg_mode_on_restart(Execution::Dedicated, "dedicated");
}

#[test_traced]
fn legacy_missing_player_dealing_exits_actor() {
    let executor = deterministic::Runner::seeded(9);
    executor.start(|mut context| async move {
        let namespace = b"test_dkg".to_vec();
        let epoch = Epoch::zero();
        let (peer_config, participants) = peer_config(4, vec![4]);
        let self_pk = peer_config
            .participants
            .iter()
            .next()
            .cloned()
            .expect("participant exists");
        let signer = participants
            .get(&self_pk)
            .cloned()
            .expect("signer should exist");
        let dealer_pk = peer_config
            .participants
            .iter()
            .find(|candidate| **candidate != self_pk)
            .cloned()
            .expect("dealer exists");
        let log = finalized_dkg_log(
            &namespace,
            epoch,
            peer_config.participants.clone(),
            peer_config.dealers(0),
            &participants,
            &dealer_pk,
        );
        let partition_prefix = format!("legacy_missing_player_dealing_{self_pk}");

        let mut storage = Storage::<_, MinSig, Ed25519PublicKey>::init(
            context.child("seed_storage"),
            &partition_prefix,
            StorageProtector::new(TEST_STORAGE_KEY),
            namespace.clone(),
            self_pk.clone(),
            NZU32!(peer_config.max_participants_per_round()),
            crate::MAX_SUPPORTED_MODE,
        )
        .await
        .expect("storage init should succeed");
        storage
            .set_epoch(
                epoch,
                EpochState {
                    round: 0,
                    rng_seed: Summary::random(&mut context),
                    output: None,
                    share: None,
                },
            )
            .await
            .expect("set epoch should succeed");
        storage
            .append_log(epoch, dealer_pk, log)
            .await
            .expect("append log should succeed");
        drop(storage);

        let (actor, _mailbox) = Actor::<_, _, TestBlock>::new(
            context.child("actor"),
            Config {
                manager: NoopManager::<Ed25519PublicKey>::default(),
                signer,
                mailbox_size: NZUsize!(8),
                execution: Execution::default(),
                partition_prefix,
                peer_config: peer_config.clone(),
                max_supported_mode: crate::MAX_SUPPORTED_MODE,
                namespace,
                storage_protector: StorageProtector::new(TEST_STORAGE_KEY),
                epoch_length: NZU64!(200),
            },
        );
        let (sender, receiver) = inert_channel(&peer_config.participants);
        let (orchestrator_sender, mut orchestrator_receiver) =
            mailbox::new(context.child("orchestrator_mailbox"), NZUsize!(4));
        let handle = actor.start(
            None,
            None,
            crate::orchestrator::Mailbox::new(orchestrator_sender),
            (sender, receiver),
            ContinueOnUpdate::boxed(),
        );

        let Some(Message::Enter(transition)) = orchestrator_receiver.recv().await else {
            panic!("actor should emit an epoch transition before detecting bad player state");
        };
        assert_eq!(transition.epoch, epoch);

        commonware_macros::select! {
            _ = handle => {},
            _ = context.sleep(std::time::Duration::from_secs(1)) => {
                panic!("legacy actor should fail closed instead of continuing shareless");
            },
        }
    });
}
