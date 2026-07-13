//! Standalone two-chain bridge demo support.

use crate::{
    channels,
    engine::{Config as EngineConfig, Engine},
    rpc, PublicKey, Scheme, NAMESPACE,
};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_consensus::marshal;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{deal, Output},
        primitives::{group, variant::MinSig},
    },
    ed25519, Signer,
};
use commonware_formatting::{from_hex, hex};
use commonware_p2p::{
    authenticated::discovery::{self, Network},
    Ingress, Manager,
};
use commonware_parallel::Sequential;
use commonware_runtime::{tokio, Handle, Runner as _, Supervisor as _};
use commonware_utils::{
    ordered::{Map, Set},
    union, N3f1, NZUsize, NZU32,
};
use governor::Quota;
use nunchi_bridge::BridgeActor;
use nunchi_dkg::{ContinueOnUpdate, EpochProvider, PeerConfig, Provider, MAX_SUPPORTED_MODE};
use nunchi_mempool::PoolConfig;
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
const DEFAULT_MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
const DEFAULT_CHANNEL_BACKLOG: usize = 1024;

#[derive(Clone, Debug)]
pub struct LocalBridgePairConfig {
    pub validators: u32,
    pub base_port_a: u16,
    pub base_rpc_port_a: u16,
    pub base_port_b: u16,
    pub base_rpc_port_b: u16,
    pub base_data_dir: PathBuf,
    pub seed_a: u64,
    pub seed_b: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalBridgePairManifest {
    pub chains: [String; 2],
    pub chain_a_executable_path: PathBuf,
    pub chain_b_executable_path: PathBuf,
    pub relayer_executable_path: PathBuf,
    pub nodes: Vec<ManifestNode>,
    pub relayer: RelayerManifest,
}

impl LocalBridgePairManifest {
    pub const FILE_NAME: &'static str = "bridge-demo.toml";

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
pub struct ManifestNode {
    pub name: String,
    pub chain: String,
    pub executable_path: PathBuf,
    pub config_path: PathBuf,
    pub port: u16,
    pub rpc_port: u16,
    pub data_dir: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayerManifest {
    pub left_rpc: String,
    pub right_rpc: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub chain: String,
    pub namespace: String,
    pub foreign_namespace: String,
    pub private_key: String,
    pub output: String,
    pub foreign_output: String,
    pub share: String,
    pub peer_config: PeerConfig<PublicKey>,
    pub listen_address: SocketAddr,
    pub dialable_address: SocketAddr,
    pub rpc_address: SocketAddr,
    pub bootstrappers: Vec<BootstrapperConfig>,
    pub storage_dir: PathBuf,
    pub consensus: ConsensusConfig,
    pub networking: NetworkConfig,
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
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            leader_timeout_ms: 1_000,
            certification_timeout_ms: 2_000,
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
            channel_backlog: DEFAULT_CHANNEL_BACKLOG,
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
    #[error("trusted setup failed: {0}")]
    Deal(commonware_cryptography::bls12381::dkg::feldman_desmedt::Error),
    #[error("missing threshold share for validator {0}")]
    MissingShare(usize),
    #[error("failed to decode hex field {field}")]
    HexDecode { field: &'static str },
    #[error("failed to decode field {field}: {source}")]
    CodecDecode {
        field: &'static str,
        source: commonware_codec::Error,
    },
    #[error("threshold output does not support epoch-independent verification")]
    MissingForeignVerifier,
    #[error("config for chain {actual} cannot be run by {expected} binary")]
    WrongChainBinary {
        expected: &'static str,
        actual: String,
    },
    #[error("failed to build RPC module: {0}")]
    RpcBuild(#[from] nunchi_rpc::RpcBuildError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to serialize toml: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("failed to parse toml: {0}")]
    TomlDeserialize(#[from] toml::de::Error),
    #[error("engine stopped unexpectedly: {0}")]
    Engine(commonware_runtime::Error),
}

struct Material {
    private_keys: Vec<ed25519::PrivateKey>,
    participants: Vec<PublicKey>,
    output: Output<MinSig, PublicKey>,
    shares: Map<PublicKey, group::Share>,
    peer_config: PeerConfig<PublicKey>,
}

pub fn generate_bridge_pair(
    config: LocalBridgePairConfig,
) -> Result<LocalBridgePairManifest, Error> {
    if config.validators == 0 {
        return Err(Error::EmptyValidatorSet);
    }
    fs::create_dir_all(&config.base_data_dir)?;
    check_port_range(config.base_port_a, config.validators)?;
    check_port_range(config.base_rpc_port_a, config.validators)?;
    check_port_range(config.base_port_b, config.validators)?;
    check_port_range(config.base_rpc_port_b, config.validators)?;

    let chain_a = ChainSpec {
        name: "chain-a",
        namespace: format!("{}-A", String::from_utf8_lossy(NAMESPACE)),
        base_port: config.base_port_a,
        base_rpc_port: config.base_rpc_port_a,
        seed: config.seed_a,
    };
    let chain_b = ChainSpec {
        name: "chain-b",
        namespace: format!("{}-B", String::from_utf8_lossy(NAMESPACE)),
        base_port: config.base_port_b,
        base_rpc_port: config.base_rpc_port_b,
        seed: config.seed_b,
    };

    let material_a = material(config.validators, chain_a.seed)?;
    let material_b = material(config.validators, chain_b.seed)?;
    let mut nodes = Vec::new();
    write_chain(
        &config,
        &chain_a,
        &chain_b,
        &material_a,
        &material_b.output,
        &mut nodes,
    )?;
    write_chain(
        &config,
        &chain_b,
        &chain_a,
        &material_b,
        &material_a.output,
        &mut nodes,
    )?;

    let relayer = RelayerManifest {
        left_rpc: format!("http://127.0.0.1:{}", config.base_rpc_port_a),
        right_rpc: format!("http://127.0.0.1:{}", config.base_rpc_port_b),
    };
    Ok(LocalBridgePairManifest {
        chains: [chain_a.name.to_string(), chain_b.name.to_string()],
        chain_a_executable_path: PathBuf::from("bridge-chain-a-node"),
        chain_b_executable_path: PathBuf::from("bridge-chain-b-node"),
        relayer_executable_path: PathBuf::from("bridge-relayer"),
        nodes,
        relayer,
    })
}

fn material(validators: u32, seed: u64) -> Result<Material, Error> {
    let private_keys = (0..validators)
        .map(|index| ed25519::PrivateKey::from_seed(seed.wrapping_add(index as u64)))
        .collect::<Vec<_>>();
    let participants = private_keys
        .iter()
        .map(|signer| signer.public_key())
        .collect::<Vec<_>>();
    let participants_set = Set::from_iter_dedup(participants.clone());
    let mut rng = StdRng::seed_from_u64(seed);
    let (output, shares) =
        deal::<MinSig, _, N3f1>(&mut rng, Default::default(), participants_set.clone())
            .map_err(Error::Deal)?;
    let peer_config = PeerConfig {
        num_participants_per_round: vec![validators],
        participants: participants_set,
    };
    Ok(Material {
        private_keys,
        participants,
        output,
        shares,
        peer_config,
    })
}

struct ChainSpec<'a> {
    name: &'a str,
    namespace: String,
    base_port: u16,
    base_rpc_port: u16,
    seed: u64,
}

fn write_chain(
    config: &LocalBridgePairConfig,
    local: &ChainSpec<'_>,
    foreign: &ChainSpec<'_>,
    material: &Material,
    foreign_output: &Output<MinSig, PublicKey>,
    nodes: &mut Vec<ManifestNode>,
) -> Result<(), Error> {
    let node_count = usize::try_from(config.validators)?;
    let chain_dir = config.base_data_dir.join(local.name);
    fs::create_dir_all(&chain_dir)?;
    for index in 0..node_count {
        let name = format!("{}-validator-{index}", local.name);
        let port = local.base_port + u16::try_from(index)?;
        let rpc_port = local.base_rpc_port + u16::try_from(index)?;
        let storage_dir = chain_dir.join(format!("validator-{index}"));
        fs::create_dir_all(&storage_dir)?;
        let config_path = chain_dir.join(format!("validator-{index}.toml"));
        let listen_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let bootstrappers = material
            .participants
            .iter()
            .enumerate()
            .filter(|(candidate, _)| *candidate != index)
            .map(|(candidate, public_key)| {
                Ok(BootstrapperConfig {
                    public_key: encode(public_key),
                    address: SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        local.base_port + u16::try_from(candidate)?,
                    ),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let share = material
            .shares
            .get_value(&material.participants[index])
            .ok_or(Error::MissingShare(index))?;
        let node_config = NodeConfig {
            name: name.clone(),
            chain: local.name.to_string(),
            namespace: local.namespace.clone(),
            foreign_namespace: foreign.namespace.clone(),
            private_key: encode(&material.private_keys[index]),
            output: encode(&material.output),
            foreign_output: encode(foreign_output),
            share: encode(share),
            peer_config: material.peer_config.clone(),
            listen_address,
            dialable_address: listen_address,
            rpc_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpc_port),
            bootstrappers,
            storage_dir: storage_dir.clone(),
            consensus: ConsensusConfig::default(),
            networking: NetworkConfig::default(),
        };
        node_config.write(&config_path)?;
        nodes.push(ManifestNode {
            name,
            chain: local.name.to_string(),
            executable_path: PathBuf::from(match local.name {
                "chain-a" => "bridge-chain-a-node",
                "chain-b" => "bridge-chain-b-node",
                _ => "bridge-chain-node",
            }),
            config_path,
            port,
            rpc_port,
            data_dir: storage_dir,
        });
    }
    Ok(())
}

fn check_port_range(base_port: u16, validators: u32) -> Result<(), Error> {
    let out_of_range = || Error::PortRange {
        base_port,
        validators,
    };
    let last_offset = u16::try_from(validators - 1).map_err(|_| out_of_range())?;
    base_port
        .checked_add(last_offset)
        .ok_or_else(out_of_range)?;
    Ok(())
}

pub fn run_node(config_path: impl AsRef<Path>) -> Result<(), Error> {
    let config = NodeConfig::read(config_path)?;
    run_config(config)
}

pub fn run_chain_a_node(config_path: impl AsRef<Path>) -> Result<(), Error> {
    let config = NodeConfig::read(config_path)?;
    run_node_for_chain(config, "chain-a")
}

pub fn run_chain_b_node(config_path: impl AsRef<Path>) -> Result<(), Error> {
    let config = NodeConfig::read(config_path)?;
    run_node_for_chain(config, "chain-b")
}

fn run_node_for_chain(config: NodeConfig, expected: &'static str) -> Result<(), Error> {
    if config.chain != expected {
        return Err(Error::WrongChainBinary {
            expected,
            actual: config.chain,
        });
    }
    run_config(config)
}

fn run_config(config: NodeConfig) -> Result<(), Error> {
    let runtime =
        tokio::Runner::new(tokio::Config::new().with_storage_directory(config.storage_dir.clone()));
    runtime.start(|context| async move {
        let (_rpc_server, engine_handle) = start_node(context, config).await?;
        wait_for_shutdown(engine_handle).await
    })
}

async fn wait_for_shutdown(engine_handle: Handle<()>) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use ::tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt()).map_err(Error::Io)?;
        let mut sigterm = signal(SignalKind::terminate()).map_err(Error::Io)?;
        ::tokio::select! {
            _ = sigint.recv() => {
                info!("received SIGINT, shutting down");
                Ok(())
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM, shutting down");
                Ok(())
            }
            result = engine_handle => {
                result.map_err(Error::Engine)
            }
        }
    }
    #[cfg(not(unix))]
    {
        ::tokio::select! {
            result = ::tokio::signal::ctrl_c() => {
                result.map_err(Error::Io)?;
                info!("received Ctrl-C, shutting down");
                Ok(())
            }
            result = engine_handle => {
                result.map_err(Error::Engine)
            }
        }
    }
}

async fn start_node(
    context: tokio::Context,
    config: NodeConfig,
) -> Result<(nunchi_rpc::ServerHandle, Handle<()>), Error> {
    let private_key = decode_unit::<ed25519::PrivateKey>(&config.private_key, "private_key")?;
    let public_key = private_key.public_key();
    let max_participants = NonZeroU32::new(config.peer_config.max_participants_per_round())
        .ok_or(Error::EmptyValidatorSet)?;
    let output = decode_output(&config.output, max_participants)?;
    let share = decode_unit::<group::Share>(&config.share, "share")?;
    let foreign_output = decode_output(&config.foreign_output, max_participants)?;
    let foreign_consensus_namespace = union(config.foreign_namespace.as_bytes(), b"_CONSENSUS");
    let foreign_verifier =
        <Provider<Scheme, ed25519::PrivateKey> as EpochProvider>::certificate_verifier(
            &foreign_consensus_namespace,
            &foreign_output,
        )
        .ok_or(Error::MissingForeignVerifier)?;
    let (bridge_actor, bridge_mailbox) =
        BridgeActor::new(foreign_verifier, config.networking.channel_backlog);
    let bridge_handle = bridge_actor.start(context.child("bridge"));
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
        chain = %config.chain,
        public_key = %public_key,
        listen = %config.listen_address,
        rpc = %config.rpc_address,
        "starting bridge-chain validator"
    );

    let p2p_config = discovery::Config::local(
        private_key.clone(),
        config.namespace.as_bytes(),
        config.listen_address,
        config.dialable_address,
        bootstrappers,
        config.networking.max_message_size,
    );
    let (mut network, mut oracle) = Network::new(context.child("network"), p2p_config);
    oracle.track(0, config.peer_config.participants.clone());

    let channel_rate = Quota::per_second(
        NonZeroU32::new(config.networking.channel_rate_per_second).unwrap_or(NZU32!(u32::MAX)),
    );
    let mut register =
        |channel| network.register(channel, channel_rate, config.networking.channel_backlog);
    let pending = register(channels::PENDING);
    let recovered = register(channels::RECOVERED);
    let resolver = register(channels::RESOLVER);
    let broadcast = register(channels::BROADCAST);
    let dkg = register(channels::DKG);
    let backfill = register(channels::BACKFILL);
    network.start();

    let engine_config: EngineConfig<_, _, _> = EngineConfig {
        blocker: oracle.clone(),
        manager: oracle.clone(),
        namespace: config.namespace.as_bytes().to_vec(),
        partition_prefix: config.name.clone(),
        blocks_freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
        finalized_freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
        signer: private_key,
        output,
        share: Some(share),
        peer_config: config.peer_config.clone(),
        leader_timeout: Duration::from_millis(config.consensus.leader_timeout_ms),
        certification_timeout: Duration::from_millis(config.consensus.certification_timeout_ms),
        strategy: Sequential,
        pool_config: PoolConfig::default(),
        bridge: bridge_mailbox,
        bridge_handle,
    };

    let resolver_config = marshal::resolver::p2p::Config {
        public_key,
        peer_provider: oracle.clone(),
        blocker: oracle,
        mailbox_size: NZUsize!(1024),
        initial: Duration::from_secs(1),
        timeout: Duration::from_secs(2),
        fetch_retry_timeout: Duration::from_millis(100),
        priority_requests: false,
        priority_responses: false,
    };
    let marshal_resolver =
        marshal::resolver::p2p::init(context.child("backfill"), resolver_config, backfill);

    let (engine, node_handle) = Engine::new(context.child("engine"), engine_config).await;
    let engine_handle = engine.start(
        pending,
        recovered,
        resolver,
        broadcast,
        dkg,
        marshal_resolver,
        ContinueOnUpdate::boxed(),
    );

    let rpc_module = rpc::module(node_handle)?;
    let rpc_server = nunchi_rpc::ServerBuilder::default()
        .build(config.rpc_address)
        .await?
        .start(rpc_module);

    info!(node = %config.name, "bridge-chain validator started");
    Ok((rpc_server, engine_handle))
}

fn decode_output(
    value: &str,
    max_participants: NonZeroU32,
) -> Result<Output<MinSig, PublicKey>, Error> {
    let bytes = decode_hex(value, "output")?;
    Output::decode_cfg(bytes.as_ref(), &(max_participants, MAX_SUPPORTED_MODE)).map_err(|source| {
        Error::CodecDecode {
            field: "output",
            source,
        }
    })
}

fn decode_unit<T>(value: &str, field: &'static str) -> Result<T, Error>
where
    T: DecodeExt<()>,
{
    let bytes = decode_hex(value, field)?;
    T::decode(bytes.as_ref()).map_err(|source| Error::CodecDecode { field, source })
}

fn decode_hex(value: &str, field: &'static str) -> Result<Vec<u8>, Error> {
    from_hex(value).ok_or(Error::HexDecode { field })
}

fn encode(value: &impl Encode) -> String {
    hex(&value.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_pair_has_distinct_validator_sets_and_foreign_outputs() {
        let dir = std::env::temp_dir().join(format!("bridge-chain-pair-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let manifest = generate_bridge_pair(LocalBridgePairConfig {
            validators: 4,
            base_port_a: 40_000,
            base_rpc_port_a: 41_000,
            base_port_b: 42_000,
            base_rpc_port_b: 43_000,
            base_data_dir: dir.clone(),
            seed_a: 7,
            seed_b: 99,
        })
        .expect("generate bridge pair");

        assert_eq!(manifest.nodes.len(), 8);
        assert_eq!(
            manifest.chains,
            ["chain-a".to_string(), "chain-b".to_string()]
        );
        assert_eq!(
            manifest.chain_a_executable_path,
            PathBuf::from("bridge-chain-a-node")
        );
        assert_eq!(
            manifest.chain_b_executable_path,
            PathBuf::from("bridge-chain-b-node")
        );

        let ports = manifest
            .nodes
            .iter()
            .map(|node| node.port)
            .collect::<HashSet<_>>();
        assert_eq!(ports.len(), 8);
        let rpc_ports = manifest
            .nodes
            .iter()
            .map(|node| node.rpc_port)
            .collect::<HashSet<_>>();
        assert_eq!(rpc_ports.len(), 8);

        let chain_a = NodeConfig::read(&manifest.nodes[0].config_path).expect("read chain a");
        let chain_b = NodeConfig::read(&manifest.nodes[4].config_path).expect("read chain b");
        assert_eq!(
            manifest.nodes[0].executable_path,
            PathBuf::from("bridge-chain-a-node")
        );
        assert_eq!(
            manifest.nodes[4].executable_path,
            PathBuf::from("bridge-chain-b-node")
        );
        assert_eq!(chain_a.chain, "chain-a");
        assert_eq!(chain_b.chain, "chain-b");
        assert_ne!(
            chain_a.peer_config.participants,
            chain_b.peer_config.participants
        );
        assert_eq!(chain_a.foreign_output, chain_b.output);
        assert_eq!(chain_b.foreign_output, chain_a.output);
        assert_ne!(chain_a.namespace, chain_b.namespace);
        assert_eq!(chain_a.foreign_namespace, chain_b.namespace);
        assert_eq!(chain_b.foreign_namespace, chain_a.namespace);

        for node in &manifest.nodes {
            let config = NodeConfig::read(&node.config_path).expect("read node config");
            assert_eq!(config.peer_config.participants.len(), 4);
            assert_eq!(config.bootstrappers.len(), 3);
            assert!(!config
                .bootstrappers
                .iter()
                .any(|bootstrapper| bootstrapper.address.port() == node.port));

            let max_participants =
                NonZeroU32::new(config.peer_config.max_participants_per_round()).unwrap();
            decode_output(&config.output, max_participants).expect("decode output");
            decode_output(&config.foreign_output, max_participants).expect("decode foreign output");
            decode_unit::<group::Share>(&config.share, "share").expect("decode share");
            decode_unit::<ed25519::PrivateKey>(&config.private_key, "private_key")
                .expect("decode private key");
        }

        let manifest_path = dir.join(LocalBridgePairManifest::FILE_NAME);
        manifest.write(&manifest_path).expect("write manifest");
        let read = LocalBridgePairManifest::read(&manifest_path).expect("read manifest");
        assert_eq!(read.nodes.len(), manifest.nodes.len());

        let _ = fs::remove_dir_all(dir);
    }
}
