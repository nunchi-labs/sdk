use crate::{
    engine::{Config as EngineConfig, Engine},
    PublicKey, NAMESPACE,
};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_consensus::{
    marshal, simplex::scheme::bls12381_threshold::vrf as bls12381_threshold, types::ViewDelta,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group,
        sharing::{ModeVersion, Sharing},
        variant::MinSig,
    },
    certificate::mocks::Fixture,
    ed25519, Signer,
};
use commonware_formatting::{from_hex, hex};
use commonware_p2p::{
    authenticated::discovery::{self, Network},
    Ingress, Manager,
};
use commonware_parallel::Sequential;
use commonware_runtime::{tokio, Quota, Runner as _, Supervisor};
use commonware_utils::{ordered::Set, NZUsize, NZU32};
use governor::Quota as GovernorQuota;
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::{NonZeroU32, TryFromIntError},
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::info;

const FREEZER_TABLE_INITIAL_SIZE: u32 = 2u32.pow(14);
const DEFAULT_MAX_BLOCK_TRANSACTIONS: usize = 256;
const DEFAULT_MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
const DEFAULT_MAILBOX_SIZE: usize = 1024;
const DEFAULT_DEQUE_SIZE: usize = 10;
const DEFAULT_FETCH_CONCURRENT: usize = 10;
const DEFAULT_MAX_FETCH_COUNT: usize = 10;
const DEFAULT_MAX_FETCH_SIZE: usize = 1024 * 512;

const PENDING_CHANNEL: u64 = 0;
const RECOVERED_CHANNEL: u64 = 1;
const RESOLVER_CHANNEL: u64 = 2;
const BROADCAST_CHANNEL: u64 = 3;
const BACKFILL_CHANNEL: u64 = 4;

#[derive(Clone, Debug)]
pub struct LocalTestnetConfig {
    pub validators: u32,
    pub base_port: u16,
    pub base_data_dir: PathBuf,
    pub seed: u64,
}

impl LocalTestnetConfig {
    pub fn new(validators: u32, base_port: u16, base_data_dir: impl Into<PathBuf>) -> Self {
        Self {
            validators,
            base_port,
            base_data_dir: base_data_dir.into(),
            seed: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalTestnetManifest {
    pub chain: String,
    pub executable_path: PathBuf,
    pub nodes: Vec<ManifestNode>,
}

impl LocalTestnetManifest {
    pub const FILE_NAME: &'static str = "narae.toml";

    pub fn read(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(Error::Io)?;
        toml::from_str(&raw).map_err(Error::TomlDeserialize)
    }

    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let raw = toml::to_string_pretty(self).map_err(Error::TomlSerialize)?;
        fs::write(path, raw).map_err(Error::Io)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestNode {
    pub name: String,
    pub config_path: PathBuf,
    pub port: u16,
    pub data_dir: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub private_key: String,
    pub polynomial: String,
    pub share: String,
    pub participants: Vec<String>,
    pub listen_address: SocketAddr,
    pub dialable_address: SocketAddr,
    pub bootstrappers: Vec<BootstrapperConfig>,
    pub storage_dir: PathBuf,
    pub consensus: ConsensusConfig,
    pub networking: NetworkConfig,
    pub max_block_transactions: usize,
}

impl NodeConfig {
    pub fn read(path: impl AsRef<Path>) -> Result<Self, Error> {
        let raw = fs::read_to_string(path).map_err(Error::Io)?;
        toml::from_str(&raw).map_err(Error::TomlDeserialize)
    }

    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let raw = toml::to_string_pretty(self).map_err(Error::TomlSerialize)?;
        fs::write(path, raw).map_err(Error::Io)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapperConfig {
    pub public_key: String,
    pub address: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub leader_timeout_ms: u64,
    pub certification_timeout_ms: u64,
    pub nullify_retry_ms: u64,
    pub fetch_timeout_ms: u64,
    pub activity_timeout_views: u64,
    pub skip_timeout_views: u64,
    pub max_fetch_count: usize,
    pub max_fetch_size: usize,
    pub fetch_concurrent: usize,
    pub fetch_rate_per_peer: u32,
    pub mailbox_size: usize,
    pub deque_size: usize,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            leader_timeout_ms: 1_000,
            certification_timeout_ms: 2_000,
            nullify_retry_ms: 10_000,
            fetch_timeout_ms: 1_000,
            activity_timeout_views: 10,
            skip_timeout_views: 5,
            max_fetch_count: DEFAULT_MAX_FETCH_COUNT,
            max_fetch_size: DEFAULT_MAX_FETCH_SIZE,
            fetch_concurrent: DEFAULT_FETCH_CONCURRENT,
            fetch_rate_per_peer: 10,
            mailbox_size: DEFAULT_MAILBOX_SIZE,
            deque_size: DEFAULT_DEQUE_SIZE,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub max_message_size: u32,
    pub channel_backlog: usize,
    pub channel_rate_per_second: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            channel_backlog: DEFAULT_MAILBOX_SIZE,
            channel_rate_per_second: u32::MAX,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("validator count must be non-zero")]
    EmptyValidatorSet,
    #[error("validator count is too large for this platform: {0}")]
    ValidatorCountTooLarge(#[from] TryFromIntError),
    #[error("port range starting at {base_port} cannot fit {validators} validators")]
    PortRange { base_port: u16, validators: u32 },
    #[error("missing threshold share for validator {0}")]
    MissingShare(usize),
    #[error("failed to decode hex field {field}: {message}")]
    HexDecode {
        field: &'static str,
        message: String,
    },
    #[error("failed to decode field {field}: {source}")]
    CodecDecode {
        field: &'static str,
        source: commonware_codec::Error,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to serialize toml: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("failed to parse toml: {0}")]
    TomlDeserialize(#[from] toml::de::Error),
}

pub fn generate_local_testnet(config: LocalTestnetConfig) -> Result<LocalTestnetManifest, Error> {
    if config.validators == 0 {
        return Err(Error::EmptyValidatorSet);
    }

    fs::create_dir_all(&config.base_data_dir)?;
    let node_count = usize::try_from(config.validators)?;
    let last_port_offset = u16::try_from(config.validators - 1).map_err(|_| Error::PortRange {
        base_port: config.base_port,
        validators: config.validators,
    })?;
    config
        .base_port
        .checked_add(last_port_offset)
        .ok_or(Error::PortRange {
            base_port: config.base_port,
            validators: config.validators,
        })?;

    let mut rng = StdRng::seed_from_u64(config.seed);
    let Fixture {
        schemes,
        private_keys,
        participants,
        ..
    } = bls12381_threshold::fixture::<MinSig, _>(&mut rng, NAMESPACE, config.validators);

    let mut nodes = Vec::with_capacity(node_count);
    for index in 0..node_count {
        let name = format!("validator-{index}");
        let port = config.base_port + u16::try_from(index)?;
        let storage_dir = config.base_data_dir.join(&name);
        fs::create_dir_all(&storage_dir)?;
        let config_path = config.base_data_dir.join(format!("{name}.toml"));
        let listen_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let bootstrappers = participants
            .iter()
            .enumerate()
            .filter(|(candidate, _)| *candidate != index)
            .map(|(candidate, public_key)| BootstrapperConfig {
                public_key: encode(public_key),
                address: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    config.base_port + u16::try_from(candidate).expect("candidate fits u16"),
                ),
            })
            .collect();
        let node_config = NodeConfig {
            name: name.clone(),
            private_key: encode(&private_keys[index]),
            polynomial: encode(schemes[index].polynomial()),
            share: encode(schemes[index].share().ok_or(Error::MissingShare(index))?),
            participants: participants.iter().map(encode).collect(),
            listen_address,
            dialable_address: listen_address,
            bootstrappers,
            storage_dir: storage_dir.clone(),
            consensus: ConsensusConfig::default(),
            networking: NetworkConfig::default(),
            max_block_transactions: DEFAULT_MAX_BLOCK_TRANSACTIONS,
        };
        node_config.write(&config_path)?;
        nodes.push(ManifestNode {
            name,
            config_path,
            port,
            data_dir: storage_dir,
        });
    }

    Ok(LocalTestnetManifest {
        chain: "coins-chain".to_string(),
        executable_path: PathBuf::from("coins-chain-node"),
        nodes,
    })
}

pub fn run_node(config_path: impl AsRef<Path>) -> Result<(), Error> {
    let config = NodeConfig::read(config_path)?;
    let runtime =
        tokio::Runner::new(tokio::Config::new().with_storage_directory(config.storage_dir.clone()));
    runtime.start(|context| async move {
        start_node(context, config).await?;
        futures::future::pending::<()>().await;
        #[allow(unreachable_code)]
        Ok(())
    })
}

async fn start_node(context: tokio::Context, config: NodeConfig) -> Result<(), Error> {
    let private_key = decode_unit::<ed25519::PrivateKey>(&config.private_key, "private_key")?;
    let public_key = private_key.public_key();
    let participants = decode_participants(&config.participants)?;
    let participant_set = Set::from_iter_dedup(participants.clone());
    let polynomial = decode_polynomial(&config.polynomial, participants.len())?;
    let share = decode_unit::<group::Share>(&config.share, "share")?;
    let bootstrappers = config
        .bootstrappers
        .iter()
        .map(|bootstrapper| {
            Ok((
                decode_unit::<PublicKey>(&bootstrapper.public_key, "bootstrapper.public_key")?,
                Ingress::from(bootstrapper.address),
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    info!(
        node = %config.name,
        public_key = %public_key,
        listen = %config.listen_address,
        "starting coins-chain validator"
    );

    let p2p_config = discovery::Config::local(
        private_key.clone(),
        NAMESPACE,
        config.listen_address,
        config.dialable_address,
        bootstrappers,
        config.networking.max_message_size,
    );
    let (mut network, mut oracle) = Network::new(context.child("network"), p2p_config);
    oracle.track(0, participant_set.clone());

    let channel_rate = Quota::per_second(
        NonZeroU32::new(config.networking.channel_rate_per_second).unwrap_or(NZU32!(u32::MAX)),
    );
    let pending = network.register(
        PENDING_CHANNEL,
        channel_rate,
        config.networking.channel_backlog,
    );
    let recovered = network.register(
        RECOVERED_CHANNEL,
        channel_rate,
        config.networking.channel_backlog,
    );
    let resolver = network.register(
        RESOLVER_CHANNEL,
        channel_rate,
        config.networking.channel_backlog,
    );
    let broadcast = network.register(
        BROADCAST_CHANNEL,
        channel_rate,
        config.networking.channel_backlog,
    );
    let backfill = network.register(
        BACKFILL_CHANNEL,
        channel_rate,
        config.networking.channel_backlog,
    );
    network.start();

    let consensus = &config.consensus;
    let engine_config: EngineConfig<_, _, _> = EngineConfig {
        blocker: oracle.clone(),
        provider: oracle.clone(),
        partition_prefix: config.name.clone(),
        blocks_freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
        finalized_freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
        me: public_key.clone(),
        polynomial,
        share,
        participants: participant_set,
        mailbox_size: consensus.mailbox_size,
        deque_size: consensus.deque_size,
        leader_timeout: Duration::from_millis(consensus.leader_timeout_ms),
        certification_timeout: Duration::from_millis(consensus.certification_timeout_ms),
        nullify_retry: Duration::from_millis(consensus.nullify_retry_ms),
        fetch_timeout: Duration::from_millis(consensus.fetch_timeout_ms),
        activity_timeout: ViewDelta::new(consensus.activity_timeout_views),
        skip_timeout: ViewDelta::new(consensus.skip_timeout_views),
        max_fetch_count: consensus.max_fetch_count,
        max_fetch_size: consensus.max_fetch_size,
        fetch_concurrent: consensus.fetch_concurrent,
        fetch_rate_per_peer: GovernorQuota::per_second(
            NonZeroU32::new(consensus.fetch_rate_per_peer).unwrap_or(NZU32!(u32::MAX)),
        ),
        strategy: Sequential,
        max_block_transactions: config.max_block_transactions,
    };

    let resolver_config = marshal::resolver::p2p::Config {
        public_key,
        peer_provider: oracle.clone(),
        blocker: oracle,
        mailbox_size: NZUsize!(consensus.mailbox_size),
        initial: Duration::from_secs(1),
        timeout: Duration::from_secs(2),
        fetch_retry_timeout: Duration::from_millis(100),
        priority_requests: false,
        priority_responses: false,
    };
    let marshal_resolver =
        marshal::resolver::p2p::init(context.child("backfill"), resolver_config, backfill);

    let (engine, _) = Engine::new(context.child("engine"), engine_config).await;
    engine.start(pending, recovered, resolver, broadcast, marshal_resolver);
    info!(node = %config.name, "coins-chain validator started");
    Ok(())
}

fn decode_participants(participants: &[String]) -> Result<Vec<PublicKey>, Error> {
    participants
        .iter()
        .map(|participant| decode_unit(participant, "participants"))
        .collect()
}

fn decode_polynomial(value: &str, participant_count: usize) -> Result<Sharing<MinSig>, Error> {
    let bytes = decode_hex(value, "polynomial")?;
    let max_participants =
        NonZeroU32::new(u32::try_from(participant_count)?).ok_or(Error::EmptyValidatorSet)?;
    Sharing::<MinSig>::decode_cfg(bytes.as_ref(), &(max_participants, ModeVersion::v0())).map_err(
        |source| Error::CodecDecode {
            field: "polynomial",
            source,
        },
    )
}

fn decode_unit<T>(value: &str, field: &'static str) -> Result<T, Error>
where
    T: DecodeExt<()>,
{
    let bytes = decode_hex(value, field)?;
    T::decode(bytes.as_ref()).map_err(|source| Error::CodecDecode { field, source })
}

fn decode_hex(value: &str, field: &'static str) -> Result<Vec<u8>, Error> {
    from_hex(value).ok_or_else(|| Error::HexDecode {
        field,
        message: "invalid hex".to_string(),
    })
}

fn encode(value: &impl Encode) -> String {
    hex(&value.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_testnet_has_unique_ports_dirs_and_complete_peer_sets() {
        let dir = std::env::temp_dir().join(format!("coins-chain-testnet-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let manifest = generate_local_testnet(LocalTestnetConfig {
            validators: 4,
            base_port: 40_000,
            base_data_dir: dir.clone(),
            seed: 7,
        })
        .expect("generate testnet");

        assert_eq!(manifest.nodes.len(), 4);
        let ports = manifest
            .nodes
            .iter()
            .map(|node| node.port)
            .collect::<HashSet<_>>();
        assert_eq!(ports.len(), 4);
        let dirs = manifest
            .nodes
            .iter()
            .map(|node| node.data_dir.clone())
            .collect::<HashSet<_>>();
        assert_eq!(dirs.len(), 4);

        for node in &manifest.nodes {
            let config = NodeConfig::read(&node.config_path).expect("read node config");
            assert_eq!(config.participants.len(), 4);
            assert_eq!(config.bootstrappers.len(), 3);
            assert!(!config
                .bootstrappers
                .iter()
                .any(|bootstrapper| bootstrapper.address.port() == node.port));
        }

        let _ = fs::remove_dir_all(dir);
    }
}
