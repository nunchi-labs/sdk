use commonware_consensus::marshal;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{deal, Output},
        primitives::{group, variant::MinSig},
    },
    ed25519, Signer,
};
use commonware_p2p::{
    simulated::{self, Link, Network, Oracle, Receiver, Sender},
    Manager,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    deterministic::{self, Runner},
    Clock, Metrics, Runner as _, Supervisor,
};
use commonware_utils::{
    ordered::{Map, Set},
    N3f1, NZUsize, NZU32,
};
use governor::Quota;
use nunchi_authority::AuthorityLedger;
use nunchi_coins::{Address, Ledger};
use nunchi_coins_chain::{
    engine::{Config, Engine},
    execution::NodeHandle,
    PublicKey, Submitter,
};
use nunchi_common::QmdbReader;
use nunchi_dkg::{ContinueOnUpdate, PeerConfig};
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

const FREEZER_TABLE_INITIAL_SIZE: u32 = 2u32.pow(14); // 1MB
const TEST_QUOTA: Quota = Quota::per_second(NZU32!(u32::MAX));
const MAX_BLOCK_TRANSACTIONS: usize = 256;

const PENDING_CHANNEL: u64 = nunchi_coins_chain::channels::PENDING;
const RECOVERED_CHANNEL: u64 = nunchi_coins_chain::channels::RECOVERED;
const RESOLVER_CHANNEL: u64 = nunchi_coins_chain::channels::RESOLVER;
const BROADCAST_CHANNEL: u64 = nunchi_coins_chain::channels::BROADCAST;
const DKG_CHANNEL: u64 = nunchi_coins_chain::channels::DKG;
const BACKFILL_CHANNEL: u64 = nunchi_coins_chain::channels::BACKFILL;

type Channel = (
    Sender<PublicKey, deterministic::Context>,
    Receiver<PublicKey>,
);
type ReadLedger = Ledger<QmdbReader<deterministic::Context>>;
type ReadAuthorityLedger = AuthorityLedger<QmdbReader<deterministic::Context>>;

#[derive(Clone)]
pub(crate) struct ThresholdFixture {
    output: Output<MinSig, PublicKey>,
    shares: Map<PublicKey, group::Share>,
    private_keys: Vec<ed25519::PrivateKey>,
    participants: Vec<PublicKey>,
}

impl ThresholdFixture {
    pub(crate) fn new(rng: impl rand_core::CryptoRngCore, validators: u32) -> Self {
        let private_keys = (0..validators)
            .map(|seed| ed25519::PrivateKey::from_seed(seed as u64))
            .collect::<Vec<_>>();
        let participants = private_keys
            .iter()
            .map(|signer| signer.public_key())
            .collect::<Vec<_>>();
        let participants_set = Set::from_iter_dedup(participants.clone());
        let (output, shares) = deal::<MinSig, _, N3f1>(rng, Default::default(), participants_set)
            .expect("trusted initial deal should succeed");
        Self {
            output,
            shares,
            private_keys,
            participants,
        }
    }
}

pub(crate) fn reliable_link() -> Link {
    Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    }
}

#[allow(dead_code)]
pub(crate) fn lossy_link() -> Link {
    Link {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(150),
        success_rate: 0.75,
    }
}

#[derive(Clone)]
pub(crate) struct ValidatorConfig {
    pub(crate) leader_timeout: Duration,
    pub(crate) certification_timeout: Duration,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
        }
    }
}

struct ValidatorChannels {
    pending: Channel,
    recovered: Channel,
    resolver: Channel,
    broadcast: Channel,
    dkg: Channel,
    backfill: Channel,
}

pub(crate) struct TestNetworkBuilder {
    validators: u32,
    fixture: Option<ThresholdFixture>,
    initial_link: Option<Link>,
    validator_config: ValidatorConfig,
}

impl TestNetworkBuilder {
    pub(crate) fn new(validators: u32) -> Self {
        Self {
            validators,
            fixture: None,
            initial_link: Some(reliable_link()),
            validator_config: ValidatorConfig::default(),
        }
    }

    pub(crate) fn with_fixture(mut self, fixture: ThresholdFixture) -> Self {
        self.validators = fixture
            .participants
            .len()
            .try_into()
            .expect("validator count exceeds u32");
        self.fixture = Some(fixture);
        self
    }

    pub(crate) fn with_initial_link(mut self, link: Link) -> Self {
        self.initial_link = Some(link);
        self
    }

    pub(crate) fn with_validator_config(mut self, validator_config: ValidatorConfig) -> Self {
        self.validator_config = validator_config;
        self
    }

    pub(crate) fn without_initial_links(mut self) -> Self {
        self.initial_link = None;
        self
    }

    pub(crate) async fn build<'a>(
        self,
        context: &'a mut deterministic::Context,
    ) -> TestNetwork<'a> {
        let (network, mut oracle) = Network::new(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
        );
        network.start();

        let fixture = self
            .fixture
            .unwrap_or_else(|| ThresholdFixture::new(&mut *context, self.validators));
        let ThresholdFixture {
            output,
            shares,
            private_keys,
            participants,
        } = fixture;
        let registrations = register_validators(&mut oracle, &participants).await;
        let participants_set = Set::from_iter_dedup(participants.clone());
        let peer_config = PeerConfig {
            num_participants_per_round: vec![participants.len() as u32],
            participants: participants_set,
        };

        let mut network = TestNetwork {
            context,
            oracle,
            output,
            shares,
            private_keys,
            participants,
            peer_config,
            registrations,
            validator_config: self.validator_config,
            nodes: HashMap::new(),
        };

        if let Some(link) = self.initial_link {
            network.link_all(link).await;
        }

        network
    }
}

pub(crate) struct TestNetwork<'a> {
    context: &'a deterministic::Context,
    oracle: Oracle<PublicKey, deterministic::Context>,
    output: Output<MinSig, PublicKey>,
    shares: Map<PublicKey, group::Share>,
    private_keys: Vec<ed25519::PrivateKey>,
    participants: Vec<PublicKey>,
    peer_config: PeerConfig<PublicKey>,
    registrations: HashMap<PublicKey, ValidatorChannels>,
    validator_config: ValidatorConfig,
    /// Handles published by each started validator, aggregated by the harness for the client to use.
    nodes: HashMap<PublicKey, NodeHandle<deterministic::Context>>,
}

impl TestNetwork<'_> {
    pub(crate) fn context(&self) -> &deterministic::Context {
        self.context
    }

    pub(crate) fn participants(&self) -> &[PublicKey] {
        &self.participants
    }

    pub(crate) async fn start_all(&mut self) {
        for index in 0..self.private_keys.len() {
            self.start_validator(index).await;
        }
    }

    pub(crate) async fn start_validator(&mut self, index: usize) {
        let signer = &self.private_keys[index];
        let public_key = signer.public_key();
        let channels = self
            .registrations
            .remove(&public_key)
            .expect("validator was already started");
        let share = self
            .shares
            .get_value(&public_key)
            .cloned()
            .expect("started validator must have an initial share");

        let handle = start_validator(
            self.context,
            &self.oracle,
            ValidatorIdentity {
                signer,
                output: self.output.clone(),
                share,
                peer_config: self.peer_config.clone(),
            },
            channels,
            self.validator_config.clone(),
        )
        .await;
        self.nodes.insert(public_key, handle);
    }

    pub(crate) async fn link_all(&mut self, link: Link) {
        self.link_where(link, |_, _| true).await;
    }

    pub(crate) async fn link_where(&mut self, link: Link, allow: impl Fn(usize, usize) -> bool) {
        for (from_index, from) in self.participants.iter().enumerate() {
            for (to_index, to) in self.participants.iter().enumerate() {
                if from == to || !allow(from_index, to_index) {
                    continue;
                }

                self.oracle
                    .add_link(from.clone(), to.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }
    }

    pub(crate) async fn run_until_height(&self, required: u64) {
        self.run_until_height_with_interval(required, Duration::from_secs(1))
            .await;
    }

    pub(crate) async fn run_until_height_with_interval(&self, required: u64, interval: Duration) {
        let expected = self.started_validator_ids();
        assert!(
            !expected.is_empty(),
            "run_until_height requires at least one started validator"
        );

        loop {
            let metrics = self.context.encode();
            let mut reached = HashSet::new();
            for line in metrics.lines() {
                let Some((metric, labels, value)) = validator_metric_sample(line) else {
                    continue;
                };

                if metric.ends_with("_peers_blocked") {
                    assert_eq!(value.parse::<u64>().unwrap(), 0);
                }

                if metric.ends_with("_marshal_processed_height")
                    && value.parse::<u64>().unwrap() >= required
                {
                    if let Some(id) = metric_label(labels, "id") {
                        if expected.contains(id) {
                            reached.insert(id);
                        }
                    }
                }
            }
            if reached.len() == expected.len() {
                break;
            }
            self.context.sleep(interval).await;
        }
    }

    fn started_validator_ids(&self) -> HashSet<String> {
        self.private_keys
            .iter()
            .filter_map(|signer| {
                let public_key = signer.public_key();
                (!self.registrations.contains_key(&public_key))
                    .then(|| format!("validator_{public_key}"))
            })
            .collect()
    }

    /// The transaction submitter for validator `index`; a client's ingress to that node.
    pub(crate) fn submitter(&self, index: usize) -> Submitter {
        self.nodes
            .get(&self.participants[index])
            .expect("validator not started")
            .submitter
            .clone()
    }

    /// Snapshot, in registration order, every started validator's committed coin ledger.
    pub(crate) async fn ledgers(&self) -> Vec<ReadLedger> {
        let mut ledgers = Vec::new();
        for participant in &self.participants {
            let Some(node) = self.nodes.get(participant) else {
                continue;
            };
            let db = node.stateful.subscribe_databases().await;
            ledgers.push(Ledger::new(QmdbReader::new(db)));
        }
        ledgers
    }

    pub(crate) async fn authority_ledgers(&self) -> Vec<ReadAuthorityLedger> {
        let mut ledgers = Vec::new();
        for participant in &self.participants {
            let Some(node) = self.nodes.get(participant) else {
                continue;
            };
            let db = node.stateful.subscribe_databases().await;
            ledgers.push(AuthorityLedger::new(QmdbReader::new(db)));
        }
        ledgers
    }

    /// Poll until every node's ledger shows the expected nonce for each listed account.
    ///
    /// An account's nonce advances once per applied transaction, so this is a precise "all the
    /// client's transactions have been finalized and applied, on every node" gate.
    pub(crate) async fn run_until_nonces(&self, expected: &[(Address, u64)]) {
        loop {
            if self.all_nonces_reached(expected).await {
                break;
            }
            self.context.sleep(Duration::from_secs(1)).await;
        }
    }

    async fn all_nonces_reached(&self, expected: &[(Address, u64)]) -> bool {
        let ledgers = self.ledgers().await;
        if ledgers.len() != self.participants.len() {
            return false;
        }
        for ledger in ledgers {
            for (account, target) in expected {
                let nonce = ledger.nonce(account).await.expect("nonce read failed");
                if nonce != *target {
                    return false;
                }
            }
        }
        true
    }
}

pub(crate) fn deterministic_state(
    validators: u32,
    seed: u64,
    link: Link,
    required_height: u64,
) -> String {
    let cfg = deterministic::Config::default().with_seed(seed);
    let executor = Runner::from(cfg);
    executor.start(|mut context| async move {
        let mut network = TestNetworkBuilder::new(validators)
            .with_initial_link(link)
            .build(&mut context)
            .await;
        network.start_all().await;
        network.run_until_height(required_height).await;
        context.auditor().state()
    })
}

#[allow(clippy::too_many_arguments)]
struct ValidatorIdentity<'a> {
    signer: &'a ed25519::PrivateKey,
    output: Output<MinSig, PublicKey>,
    share: group::Share,
    peer_config: PeerConfig<PublicKey>,
}

async fn start_validator(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKey, deterministic::Context>,
    identity: ValidatorIdentity<'_>,
    channels: ValidatorChannels,
    cfg: ValidatorConfig,
) -> NodeHandle<deterministic::Context> {
    let ValidatorIdentity {
        signer,
        output,
        share,
        peer_config,
    } = identity;
    let public_key = signer.public_key();
    let uid = format!("validator_{public_key}");
    let config: Config<_, _, _> = Config {
        blocker: oracle.control(public_key.clone()),
        manager: oracle.manager(),
        partition_prefix: uid.clone(),
        blocks_freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
        finalized_freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
        signer: signer.clone(),
        output,
        share: Some(share),
        peer_config,
        leader_timeout: cfg.leader_timeout,
        certification_timeout: cfg.certification_timeout,
        strategy: Sequential,
        max_block_transactions: MAX_BLOCK_TRANSACTIONS,
        genesis: None,
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

    let (engine, handle) = Engine::new(validator_context.child("engine"), config).await;
    engine.start(
        channels.pending,
        channels.recovered,
        channels.resolver,
        channels.broadcast,
        channels.dkg,
        marshal_resolver,
        ContinueOnUpdate::boxed(),
    );
    handle
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
    name.starts_with("validator_")
        .then_some((name, labels, value))
}

fn metric_label<'a>(labels: Option<&'a str>, name: &str) -> Option<&'a str> {
    labels?.split(',').find_map(|label| {
        let (label_name, value) = label.split_once('=')?;
        (label_name == name).then(|| value.trim_matches('"'))
    })
}

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
        let dkg = oracle.register(DKG_CHANNEL, TEST_QUOTA).await.unwrap();
        let backfill = oracle.register(BACKFILL_CHANNEL, TEST_QUOTA).await.unwrap();
        registrations.insert(
            validator.clone(),
            ValidatorChannels {
                pending,
                recovered,
                resolver,
                broadcast,
                dkg,
                backfill,
            },
        );
    }
    registrations
}
