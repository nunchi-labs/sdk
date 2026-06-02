use commonware_consensus::{
    marshal, simplex::scheme::bls12381_threshold::vrf as bls12381_threshold, types::ViewDelta,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::mocks::Fixture, ed25519, Signer,
};
use commonware_p2p::{
    simulated::{self, Link, Network, Oracle, Receiver, Sender},
    Manager,
};
use commonware_parallel::Sequential;
use commonware_runtime::{deterministic, Clock, Supervisor};
use commonware_utils::{ordered::Set, NZUsize, NZU32};
use governor::Quota;
use nunchi_coins_chain::{
    engine::{Config, Engine},
    execution::{NodeHandle, SharedLedger},
    txpool::Submitter,
    PublicKey, NAMESPACE,
};
use std::{collections::HashMap, num::NonZeroU32, time::Duration};

const FREEZER_TABLE_INITIAL_SIZE: u32 = 2u32.pow(14); // 1MB
const TEST_QUOTA: Quota = Quota::per_second(NZU32!(u32::MAX));
const MAX_BLOCK_TRANSACTIONS: usize = 256;

const PENDING_CHANNEL: u64 = 0;
const RECOVERED_CHANNEL: u64 = 1;
const RESOLVER_CHANNEL: u64 = 2;
const BROADCAST_CHANNEL: u64 = 3;
const BACKFILL_CHANNEL: u64 = 4;

type Channel = (
    Sender<PublicKey, deterministic::Context>,
    Receiver<PublicKey>,
);

type ThresholdScheme = bls12381_threshold::Scheme<PublicKey, MinSig>;

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

struct ValidatorChannels {
    pending: Channel,
    recovered: Channel,
    resolver: Channel,
    broadcast: Channel,
    backfill: Channel,
}

pub(crate) struct TestNetworkBuilder {
    validators: u32,
    initial_link: Option<Link>,
    validator_config: ValidatorConfig,
}

impl TestNetworkBuilder {
    pub(crate) fn new(validators: u32) -> Self {
        Self {
            validators,
            initial_link: Some(reliable_link()),
            validator_config: ValidatorConfig::default(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn with_initial_link(mut self, link: Link) -> Self {
        self.initial_link = Some(link);
        self
    }

    #[allow(dead_code)]
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

        let Fixture {
            schemes,
            private_keys,
            participants,
            ..
        } = bls12381_threshold::fixture::<MinSig, _>(context, NAMESPACE, self.validators);
        let registrations = register_validators(&mut oracle, &participants).await;
        let participants_set = Set::from_iter_dedup(participants.clone());

        let mut network = TestNetwork {
            context,
            oracle,
            schemes,
            private_keys,
            participants,
            participants_set,
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
    schemes: Vec<ThresholdScheme>,
    private_keys: Vec<ed25519::PrivateKey>,
    participants: Vec<PublicKey>,
    participants_set: Set<PublicKey>,
    registrations: HashMap<PublicKey, ValidatorChannels>,
    validator_config: ValidatorConfig,
    /// Handles published by each started validator, aggregated by the harness for the client to use.
    nodes: HashMap<PublicKey, NodeHandle<deterministic::Context>>,
}

impl TestNetwork<'_> {
    pub(crate) async fn start_all(&mut self) {
        for index in 0..self.private_keys.len() {
            self.start_validator(index).await;
        }
    }

    pub(crate) async fn start_validator(&mut self, index: usize) {
        let signer = &self.private_keys[index];
        let scheme = &self.schemes[index];
        let public_key = signer.public_key();
        let channels = self
            .registrations
            .remove(&public_key)
            .expect("validator was already started");

        let handle = start_validator(
            self.context,
            &self.oracle,
            signer,
            scheme,
            self.participants_set.clone(),
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

    /// The transaction submitter for validator `index` — a client's ingress to that node.
    pub(crate) fn submitter(&self, index: usize) -> Submitter {
        self.nodes
            .get(&self.participants[index])
            .expect("validator not started")
            .submitter
            .clone()
    }

    /// Snapshot, in registration order, every started validator's shared coin ledger.
    pub(crate) fn ledger_handles(&self) -> Vec<SharedLedger<deterministic::Context>> {
        self.participants
            .iter()
            .filter_map(|participant| self.nodes.get(participant).map(|node| node.ledger.clone()))
            .collect()
    }

    /// Poll until every node's ledger shows the expected nonce for each listed account.
    ///
    /// An account's nonce advances once per applied transaction, so this is a precise "all the
    /// client's transactions have been finalized and applied, on every node" gate.
    pub(crate) async fn run_until_nonces(&self, expected: &[(PublicKey, u64)]) {
        loop {
            if self.all_nonces_reached(expected).await {
                break;
            }
            self.context.sleep(Duration::from_secs(1)).await;
        }
    }

    async fn all_nonces_reached(&self, expected: &[(PublicKey, u64)]) -> bool {
        let handles = self.ledger_handles();
        if handles.len() != self.participants.len() {
            return false;
        }
        for shared in handles {
            let state = shared.lock().await;
            for (account, target) in expected {
                let nonce = state
                    .ledger
                    .nonce(account)
                    .await
                    .expect("nonce read failed");
                if nonce != *target {
                    return false;
                }
            }
        }
        true
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_validator(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKey, deterministic::Context>,
    signer: &ed25519::PrivateKey,
    scheme: &ThresholdScheme,
    participants: Set<PublicKey>,
    channels: ValidatorChannels,
    cfg: ValidatorConfig,
) -> NodeHandle<deterministic::Context> {
    let public_key = signer.public_key();
    let uid = format!("validator_{public_key}");
    let config: Config<_, _, _> = Config {
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
        max_block_transactions: MAX_BLOCK_TRANSACTIONS,
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
        marshal_resolver,
    );
    handle
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
