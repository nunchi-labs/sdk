use commonware_consensus::types::Epoch;
use commonware_formatting::hex;
use commonware_utils::NZU64;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    num::{NonZero, NonZeroU32, NonZeroUsize},
};

mod block;
mod consensus;

pub mod application;
pub mod engine;

pub use block::{Block, Finalized, Notarized};
pub use consensus::{
    Activity, Context, Finalization, Identity, Notarization, PublicKey, Scheme, Seed, Seedable,
    Signature,
};

/// The unique namespace prefix used in all signing operations to prevent signature replay attacks.
pub const NAMESPACE: &[u8] = b"_ALTO";

/// The epoch number used in [commonware_consensus::simplex].
///
/// Because the template does not implement reconfiguration (validator set changes and resharing), we hardcode the epoch to 0.
///
/// For an example of how to implement reconfiguration and resharing, see [commonware-reshare](https://github.com/commonwarexyz/monorepo/tree/main/examples/reshare).
pub const EPOCH: Epoch = Epoch::zero();

/// The epoch length used in [commonware_consensus::simplex].
///
/// Because the template does not implement reconfiguration (validator set changes and resharing), we hardcode the epoch length to u64::MAX (to
/// stay in the first epoch forever).
///
/// For an example of how to implement reconfiguration and resharing, see [commonware-reshare](https://github.com/commonwarexyz/monorepo/tree/main/examples/reshare).
pub const EPOCH_LENGTH: NonZero<u64> = NZU64!(u64::MAX);

#[repr(u8)]
pub enum Kind {
    Seed = 0,
    Notarization = 1,
    Finalization = 2,
}

impl Kind {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Seed),
            1 => Some(Self::Notarization),
            2 => Some(Self::Finalization),
            _ => None,
        }
    }

    pub fn to_hex(&self) -> String {
        match self {
            Self::Seed => hex(&[0]),
            Self::Notarization => hex(&[1]),
            Self::Finalization => hex(&[2]),
        }
    }
}

pub const DEFAULT_BLOCKING_THREADS: usize = 512;
pub const DEFAULT_STORAGE_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = commonware_utils::NZU32!(16_384);
pub const DEFAULT_NETWORK_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = commonware_utils::NZU32!(4_096);

fn default_blocking_threads() -> usize {
    DEFAULT_BLOCKING_THREADS
}

fn default_storage_buffer_pool_max_per_class() -> Option<NonZeroU32> {
    Some(DEFAULT_STORAGE_BUFFER_POOL_MAX_PER_CLASS)
}

fn default_network_buffer_pool_max_per_class() -> Option<NonZeroU32> {
    Some(DEFAULT_NETWORK_BUFFER_POOL_MAX_PER_CLASS)
}

/// Configuration for the [engine::Engine].
#[derive(Deserialize, Serialize)]
pub struct Config {
    pub private_key: String,
    pub share: String,
    pub polynomial: String,

    pub port: u16,
    pub metrics_port: u16,
    pub directory: String,
    pub worker_threads: usize,
    #[serde(default = "default_blocking_threads")]
    pub blocking_threads: usize,
    #[serde(default = "default_storage_buffer_pool_max_per_class")]
    pub storage_buffer_pool_max_per_class: Option<NonZeroU32>,
    #[serde(default = "default_network_buffer_pool_max_per_class")]
    pub network_buffer_pool_max_per_class: Option<NonZeroU32>,
    #[serde(default)]
    pub storage_buffer_pool_parallelism: Option<NonZeroUsize>,
    #[serde(default)]
    pub network_buffer_pool_parallelism: Option<NonZeroUsize>,
    pub log_level: String,

    pub local: bool,
    pub allowed_peers: Vec<String>,
    pub bootstrappers: Vec<String>,

    pub message_backlog: usize,
    pub mailbox_size: usize,
    pub deque_size: usize,

    pub signature_threads: usize,
}

/// A list of peers provided when a validator is run locally.
///
/// When run remotely, [`commonware_deployer::aws::Hosts`](https://docs.rs/commonware-deployer/latest/commonware_deployer/aws/struct.Hosts.html) is used instead.
#[derive(Deserialize, Serialize)]
pub struct Peers {
    pub addresses: HashMap<String, SocketAddr>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{
        marshal, simplex::scheme::bls12381_threshold::vrf as bls12381_threshold, types::ViewDelta,
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinSig, certificate::mocks::Fixture, ed25519::PublicKey,
        Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        simulated::{self, Link, Network, Oracle, Receiver, Sender},
        Manager,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        deterministic::{self, Runner},
        Clock, Metrics, Runner as _, Spawner, Supervisor as _,
    };
    use commonware_utils::{ordered::Set, NZUsize, NZU32};
    use engine::{Config, Engine};
    use governor::Quota;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::{collections::HashMap, num::NonZeroU32, time::Duration};
    use tracing::info;

    /// Limit the freezer table size to 1MB because the deterministic runtime stores
    /// everything in RAM.
    const FREEZER_TABLE_INITIAL_SIZE: u32 = 2u32.pow(14); // 1MB

    /// (Effectively) unlimited quota for tests.
    const TEST_QUOTA: Quota = Quota::per_second(NZU32!(u32::MAX));

    const PENDING_CHANNEL: u64 = 0;
    const RECOVERED_CHANNEL: u64 = 1;
    const RESOLVER_CHANNEL: u64 = 2;
    const BROADCAST_CHANNEL: u64 = 3;
    const BACKFILL_CHANNEL: u64 = 4;

    /// Registers all validators using the oracle.
    async fn register_validators(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        validators: &[PublicKey],
    ) -> HashMap<PublicKey, ValidatorChannels> {
        oracle
            .manager()
            .track(0, Set::from_iter_dedup(validators.iter().cloned()));
        let mut registrations = HashMap::new();
        for validator in validators.iter() {
            let oracle = oracle.control(validator.clone());
            let pending = oracle.register(PENDING_CHANNEL, TEST_QUOTA).await.unwrap();
            let recovered = oracle
                .register(RECOVERED_CHANNEL, TEST_QUOTA)
                .await
                .unwrap();
            let resolver = oracle.register(RESOLVER_CHANNEL, TEST_QUOTA).await.unwrap();
            let broadcast = oracle
                .register(BROADCAST_CHANNEL, TEST_QUOTA)
                .await
                .unwrap();
            let backfill = oracle.register(BACKFILL_CHANNEL, TEST_QUOTA).await.unwrap();
            registrations.insert(
                validator.clone(),
                ValidatorChannels {
                    pending,
                    recovered,
                    resolver,
                    broadcast,
                    backfill,
                },
            );
        }
        registrations
    }

    type Channel = (
        Sender<PublicKey, deterministic::Context>,
        Receiver<PublicKey>,
    );

    struct ValidatorChannels {
        pending: Channel,
        recovered: Channel,
        resolver: Channel,
        broadcast: Channel,
        backfill: Channel,
    }

    async fn link_validators(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        validators: &[PublicKey],
        link: Link,
        restrict_to: Option<fn(usize, usize, usize) -> bool>,
    ) {
        for (i1, v1) in validators.iter().enumerate() {
            for (i2, v2) in validators.iter().enumerate() {
                if v2 == v1 {
                    continue;
                }

                if let Some(f) = restrict_to {
                    if !f(validators.len(), i1, i2) {
                        continue;
                    }
                }

                oracle
                    .add_link(v1.clone(), v2.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }
    }

    fn validator_metric_sample(line: &str) -> Option<(&str, Option<&str>, &str)> {
        let line = line.trim();
        if line.starts_with('#') {
            return None;
        }
        let mut parts = line.split_whitespace();
        let metric = parts.next()?;
        let value = parts.next()?;
        let (name, labels) = metric
            .split_once('{')
            .map_or((metric, None), |(name, labels)| {
                (name, Some(labels.trim_end_matches('}')))
            });
        if !name.starts_with("validator_") {
            return None;
        }
        Some((name, labels, value))
    }

    #[derive(Clone)]
    struct ValidatorConfig {
        leader_timeout: Duration,
        certification_timeout: Duration,
    }

    impl Default for ValidatorConfig {
        fn default() -> Self {
            Self {
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
            }
        }
    }

    async fn start_validator(
        context: &deterministic::Context,
        oracle: &Oracle<PublicKey, deterministic::Context>,
        signer: &commonware_cryptography::ed25519::PrivateKey,
        scheme: &bls12381_threshold::Scheme<PublicKey, MinSig>,
        participants: Set<PublicKey>,
        channels: ValidatorChannels,
    ) {
        start_validator_with(
            context,
            oracle,
            signer,
            scheme,
            participants,
            channels,
            ValidatorConfig::default(),
        )
        .await;
    }

    async fn start_validator_with(
        context: &deterministic::Context,
        oracle: &Oracle<PublicKey, deterministic::Context>,
        signer: &commonware_cryptography::ed25519::PrivateKey,
        scheme: &bls12381_threshold::Scheme<PublicKey, MinSig>,
        participants: Set<PublicKey>,
        channels: ValidatorChannels,
        cfg: ValidatorConfig,
    ) {
        let public_key = signer.public_key();
        let uid = format!("validator_{public_key}");
        let config: Config<_, _, _> = engine::Config {
            blocker: oracle.control(public_key.clone()),
            provider: oracle.manager(),
            partition_prefix: uid.clone(),
            blocks_freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
            finalized_freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
            me: signer.public_key(),
            polynomial: scheme.polynomial().clone(),
            share: scheme.share().cloned().unwrap(),
            participants,
            mailbox_size: 1024,
            deque_size: 10,
            leader_timeout: cfg.leader_timeout,
            certification_timeout: cfg.certification_timeout,
            nullify_retry: Duration::from_secs(10),
            fetch_timeout: Duration::from_secs(1),
            activity_timeout: ViewDelta::new(10),
            skip_timeout: ViewDelta::new(5),
            max_fetch_count: 10,
            max_fetch_size: 1024 * 512,
            fetch_concurrent: 10,
            fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(10).unwrap()),
            strategy: Sequential,
        };
        let validator_context = context.child("validator").with_attribute("id", &uid);
        let marshal_resolver_cfg = marshal::resolver::p2p::Config {
            public_key: public_key.clone(),
            peer_provider: oracle.manager(),
            blocker: oracle.control(public_key.clone()),
            mailbox_size: NZUsize!(1024),
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let marshal_resolver = marshal::resolver::p2p::init(
            validator_context.child("backfill"),
            marshal_resolver_cfg,
            channels.backfill,
        );
        let engine = Engine::new(validator_context.child("engine"), config).await;
        engine.start(
            channels.pending,
            channels.recovered,
            channels.resolver,
            channels.broadcast,
            marshal_resolver,
        );
    }

    async fn poll_until_height(context: &deterministic::Context, required: u64) {
        loop {
            let metrics = context.encode();
            let mut success = false;
            for line in metrics.lines() {
                let Some((metric, _, value)) = validator_metric_sample(line) else {
                    continue;
                };
                if metric.ends_with("_peers_blocked") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }
                if metric.ends_with("_marshal_processed_height") {
                    let value = value.parse::<u64>().unwrap();
                    if value >= required {
                        success = true;
                        break;
                    }
                }
            }
            if success {
                break;
            }
            context.sleep(Duration::from_secs(1)).await;
        }
    }

    fn all_online(n: u32, seed: u64, link: Link, required: u64) -> String {
        let cfg = deterministic::Config::default().with_seed(seed);
        let executor = Runner::from(cfg);
        executor.start(|mut context| async move {
            let (network, mut oracle) = Network::new(
                context.child("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let Fixture {
                schemes,
                private_keys,
                participants,
                ..
            } = bls12381_threshold::fixture::<MinSig, _>(&mut context, NAMESPACE, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;
            let participants_set = Set::from_iter_dedup(participants.clone());

            link_validators(&mut oracle, &participants, link, None).await;

            for (signer, scheme) in private_keys.iter().zip(schemes.iter()) {
                let registration = registrations.remove(&signer.public_key()).unwrap();
                start_validator(
                    &context,
                    &oracle,
                    signer,
                    scheme,
                    participants_set.clone(),
                    registration,
                )
                .await;
            }

            poll_until_height(&context, required).await;
            context.auditor().state()
        })
    }

    #[test_traced]
    fn test_good_links() {
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };
        for seed in 0..5 {
            let state = all_online(5, seed, link.clone(), 25);
            assert_eq!(state, all_online(5, seed, link.clone(), 25));
        }
    }

    #[test_traced]
    fn test_bad_links() {
        let link = Link {
            latency: Duration::from_millis(200),
            jitter: Duration::from_millis(150),
            success_rate: 0.75,
        };
        for seed in 0..5 {
            let state = all_online(5, seed, link.clone(), 25);
            assert_eq!(state, all_online(5, seed, link.clone(), 25));
        }
    }

    #[test_traced]
    fn test_1k() {
        let link = Link {
            latency: Duration::from_millis(80),
            jitter: Duration::from_millis(10),
            success_rate: 0.98,
        };
        all_online(10, 0, link.clone(), 1000);
    }

    #[test_traced]
    fn test_backfill() {
        let n = 5;
        let initial_container_required = 10;
        let final_container_required = 20;
        let executor = Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let (network, mut oracle) = Network::new(
                context.child("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let Fixture {
                schemes,
                private_keys,
                participants,
                ..
            } = bls12381_threshold::fixture::<MinSig, _>(&mut context, NAMESPACE, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;
            let participants_set = Set::from_iter_dedup(participants.clone());

            // Link all validators (except 0)
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &participants,
                link.clone(),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            for (idx, (signer, scheme)) in private_keys.iter().zip(schemes.iter()).enumerate() {
                if idx == 0 {
                    continue;
                }
                let registration = registrations.remove(&signer.public_key()).unwrap();
                start_validator(
                    &context,
                    &oracle,
                    signer,
                    scheme,
                    participants_set.clone(),
                    registration,
                )
                .await;
            }

            poll_until_height(&context, initial_container_required).await;

            // Link first peer
            link_validators(
                &mut oracle,
                &participants,
                link,
                Some(|_, i, j| [i, j].contains(&0usize) && ![i, j].contains(&1usize)),
            )
            .await;

            let registration = registrations.remove(&private_keys[0].public_key()).unwrap();
            start_validator(
                &context,
                &oracle,
                &private_keys[0],
                &schemes[0],
                participants_set,
                registration,
            )
            .await;

            poll_until_height(&context, final_container_required).await;
        });
    }

    #[test_traced]
    fn test_unclean_shutdown() {
        // Create context
        let n = 5;
        let required_container = 100;

        // Derive threshold
        let mut rng = StdRng::seed_from_u64(0);
        let fixture = bls12381_threshold::fixture::<MinSig, _>(&mut rng, NAMESPACE, n);

        // Random restarts every x seconds
        let mut runs = 0;
        let mut prev_checkpoint = None;
        loop {
            // Setup run
            let Fixture {
                schemes,
                private_keys,
                participants,
                ..
            } = fixture.clone();
            let f = |mut context: deterministic::Context| async move {
                // Create simulated network
                let (network, mut oracle) = Network::new(
                    context.child("network"),
                    simulated::Config {
                        max_size: 1024 * 1024,
                        disconnect_on_block: true,
                        tracked_peer_sets: NZUsize!(1),
                    },
                );

                // Start network
                network.start();

                // Register participants
                let mut registrations = register_validators(&mut oracle, &participants).await;
                let participants_set = Set::from_iter_dedup(participants.clone());

                // Link all validators
                let link = Link {
                    latency: Duration::from_millis(10),
                    jitter: Duration::from_millis(1),
                    success_rate: 1.0,
                };
                link_validators(&mut oracle, &participants, link, None).await;

                // This test restarts validators every 250..1_000ms of simulated time.
                // Keep recovery timeouts below that window so a recovered view can
                // either certify or timeout/nullify before the next forced shutdown.
                let cfg = ValidatorConfig {
                    leader_timeout: Duration::from_millis(250),
                    certification_timeout: Duration::from_millis(500),
                };
                for (signer, scheme) in private_keys.iter().zip(schemes.iter()) {
                    let registration = registrations.remove(&signer.public_key()).unwrap();
                    start_validator_with(
                        &context,
                        &oracle,
                        signer,
                        scheme,
                        participants_set.clone(),
                        registration,
                        cfg.clone(),
                    )
                    .await;
                }

                let poller = context.child("metrics").spawn(move |context| async move {
                    loop {
                        let metrics = context.encode();

                        // Iterate over all lines
                        let mut success = false;
                        for line in metrics.lines() {
                            let Some((metric, _, value)) = validator_metric_sample(line) else {
                                continue;
                            };

                            // If ends with peers_blocked, ensure it is zero
                            if metric.ends_with("_peers_blocked") {
                                let value = value.parse::<u64>().unwrap();
                                assert_eq!(value, 0);
                            }

                            // If ends with contiguous_height, ensure it is at least required_container
                            if metric.ends_with("_marshal_processed_height") {
                                let value = value.parse::<u64>().unwrap();
                                if value >= required_container {
                                    success = true;
                                    break;
                                }
                            }
                        }
                        if success {
                            break;
                        }

                        // Still waiting for all validators to complete
                        context.sleep(Duration::from_millis(10)).await;
                    }
                });

                // Exit at random points until finished
                let wait =
                    context.gen_range(Duration::from_millis(250)..Duration::from_millis(1_000));

                // Wait for one to finish
                select! {
                    _ = poller => {
                        // Finished
                        true
                    },
                    _ = context.sleep(wait) => {
                        // Randomly exit
                        false
                    }
                }
            };

            // Handle run
            let (complete, checkpoint) = if let Some(prev_checkpoint) = prev_checkpoint {
                Runner::from(prev_checkpoint)
            } else {
                Runner::timed(Duration::from_secs(30))
            }
            .start_and_recover(f);

            // Check if we should exit
            if complete {
                break;
            }

            // Prepare for next run
            prev_checkpoint = Some(checkpoint);
            runs += 1;
        }
        assert!(runs > 1);
        info!(runs, "unclean shutdown recovery worked");
    }
}

#[cfg(test)]
mod type_tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_consensus::{
        simplex::{
            scheme::bls12381_threshold::vrf as bls12381_threshold,
            types::{Finalization, Finalize, Notarization, Notarize, Proposal},
        },
        types::{Height, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinSig, certificate::mocks::Fixture, ed25519, sha256,
        Digest, Digestible, Hasher, Sha256, Signer,
    };
    use commonware_parallel::Sequential;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_notarized() {
        let mut rng = StdRng::seed_from_u64(0);
        let n = 4;
        let Fixture { schemes, .. } =
            bls12381_threshold::fixture::<MinSig, _>(&mut rng, NAMESPACE, n);

        let context = Context {
            round: Round::new(EPOCH, View::new(9)),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (View::new(8), sha256::Digest::EMPTY),
        };
        let digest = Sha256::hash(b"hello world");
        let block = Block::new(context, digest, Height::new(10), 100);
        let proposal = Proposal::new(
            Round::new(EPOCH, View::new(9)),
            View::new(8),
            block.digest(),
        );

        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap();
        let notarized = Notarized::new(notarization, block.clone());

        let encoded = notarized.encode();
        let decoded = Notarized::decode(encoded).expect("failed to decode notarized");
        assert_eq!(notarized, decoded);
        assert!(notarized.verify(&schemes[0], &Sequential));
    }

    #[test]
    fn test_finalized() {
        let mut rng = StdRng::seed_from_u64(0);
        let n = 4;
        let Fixture { schemes, .. } =
            bls12381_threshold::fixture::<MinSig, _>(&mut rng, NAMESPACE, n);

        let context = Context {
            round: Round::new(EPOCH, View::new(9)),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (View::new(8), sha256::Digest::EMPTY),
        };
        let digest = Sha256::hash(b"hello world");
        let block = Block::new(context, digest, Height::new(10), 100);
        let proposal = Proposal::new(
            Round::new(EPOCH, View::new(9)),
            View::new(8),
            block.digest(),
        );

        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let finalization =
            Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap();
        let finalized = Finalized::new(finalization, block.clone());

        let encoded = finalized.encode();
        let decoded = Finalized::decode(encoded).expect("failed to decode finalized");
        assert_eq!(finalized, decoded);
        assert!(finalized.verify(&schemes[0], &Sequential));
    }
}
