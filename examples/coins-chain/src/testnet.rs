//! Standalone local-testnet support: config generation and a real-network node runner.
//!
//! [`generate_local_testnet`] performs a trusted setup (key generation plus an initial threshold
//! deal) and writes one TOML config per validator alongside a manifest that process runners such
//! as `narae` consume. [`run_node`] boots a single validator from one of those configs on the
//! tokio runtime with authenticated peer discovery, and serves the aggregated JSON-RPC module.

use crate::{
    channels,
    engine::{Config as EngineConfig, Engine},
    genesis::ChainGenesis,
    rpc, PublicKey, NAMESPACE,
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
use commonware_runtime::{tokio, Runner as _, Supervisor as _};
use commonware_utils::{ordered::Set, N3f1, NZUsize, NZU32};
use governor::Quota;
use nunchi_dkg::{ContinueOnUpdate, PeerConfig, MAX_SUPPORTED_MODE};
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
const DEFAULT_MAX_BLOCK_TRANSACTIONS: usize = 256;
const DEFAULT_MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
const DEFAULT_CHANNEL_BACKLOG: usize = 1024;

#[derive(Clone, Debug)]
pub struct LocalTestnetConfig {
    pub validators: u32,
    pub base_port: u16,
    pub base_rpc_port: u16,
    pub base_data_dir: PathBuf,
    pub seed: u64,
}

/// The manifest written next to the generated node configs; process runners read this to know
/// what to launch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalTestnetManifest {
    pub chain: String,
    pub executable_path: PathBuf,
    pub nodes: Vec<ManifestNode>,
}

impl LocalTestnetManifest {
    pub const FILE_NAME: &'static str = "narae.toml";

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
    pub config_path: PathBuf,
    pub port: u16,
    pub rpc_port: u16,
    pub data_dir: PathBuf,
}

/// One validator's standalone configuration.
///
/// Key material is hex-encoded commonware-codec bytes. The threshold `output` and `share` come
/// from the trusted initial deal; subsequent epochs reshare on-chain via the DKG actor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub private_key: String,
    pub output: String,
    pub share: String,
    pub peer_config: PeerConfig<PublicKey>,
    pub listen_address: SocketAddr,
    pub dialable_address: SocketAddr,
    pub rpc_address: SocketAddr,
    pub bootstrappers: Vec<BootstrapperConfig>,
    pub storage_dir: PathBuf,
    pub genesis_path: Option<PathBuf>,
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
    /// Received-message rate limit per p2p channel. `0` disables the limit.
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
    #[error("failed to build RPC module: {0}")]
    RpcBuild(#[from] nunchi_rpc::RpcBuildError),
    #[error("genesis error: {0}")]
    Genesis(#[from] crate::genesis::GenesisError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to serialize toml: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("failed to parse toml: {0}")]
    TomlDeserialize(#[from] toml::de::Error),
}

/// Generate node keys, run the trusted initial deal, and write per-node configs plus the
/// runner manifest into `config.base_data_dir`.
pub fn generate_local_testnet(config: LocalTestnetConfig) -> Result<LocalTestnetManifest, Error> {
    if config.validators == 0 {
        return Err(Error::EmptyValidatorSet);
    }

    fs::create_dir_all(&config.base_data_dir)?;
    let node_count = usize::try_from(config.validators)?;
    check_port_range(config.base_port, config.validators)?;
    check_port_range(config.base_rpc_port, config.validators)?;

    let private_keys = (0..config.validators)
        .map(|index| ed25519::PrivateKey::from_seed(config.seed.wrapping_add(index as u64)))
        .collect::<Vec<_>>();
    let participants = private_keys
        .iter()
        .map(|signer| signer.public_key())
        .collect::<Vec<_>>();
    let participants_set = Set::from_iter_dedup(participants.clone());

    let mut rng = StdRng::seed_from_u64(config.seed);
    let (output, shares) =
        deal::<MinSig, _, N3f1>(&mut rng, Default::default(), participants_set.clone())
            .map_err(Error::Deal)?;
    let peer_config = PeerConfig {
        num_participants_per_round: vec![config.validators],
        participants: participants_set,
    };

    let mut nodes = Vec::with_capacity(node_count);
    for index in 0..node_count {
        let name = format!("validator-{index}");
        let port = config.base_port + u16::try_from(index)?;
        let rpc_port = config.base_rpc_port + u16::try_from(index)?;
        let storage_dir = config.base_data_dir.join(&name);
        fs::create_dir_all(&storage_dir)?;
        let config_path = config.base_data_dir.join(format!("{name}.toml"));
        let listen_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let bootstrappers = participants
            .iter()
            .enumerate()
            .filter(|(candidate, _)| *candidate != index)
            .map(|(candidate, public_key)| {
                Ok(BootstrapperConfig {
                    public_key: encode(public_key),
                    address: SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        config.base_port + u16::try_from(candidate)?,
                    ),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let share = shares
            .get_value(&participants[index])
            .ok_or(Error::MissingShare(index))?;
        let node_config = NodeConfig {
            name: name.clone(),
            private_key: encode(&private_keys[index]),
            output: encode(&output),
            share: encode(share),
            peer_config: peer_config.clone(),
            listen_address,
            dialable_address: listen_address,
            rpc_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpc_port),
            bootstrappers,
            storage_dir: storage_dir.clone(),
            genesis_path: None,
            consensus: ConsensusConfig::default(),
            networking: NetworkConfig::default(),
            max_block_transactions: DEFAULT_MAX_BLOCK_TRANSACTIONS,
        };
        node_config.write(&config_path)?;
        nodes.push(ManifestNode {
            name,
            config_path,
            port,
            rpc_port,
            data_dir: storage_dir,
        });
    }

    Ok(LocalTestnetManifest {
        chain: "coins-chain".to_string(),
        executable_path: PathBuf::from("coins-chain-node"),
        nodes,
    })
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

/// Run a single validator from a generated config until the process is killed.
pub fn run_node(config_path: impl AsRef<Path>) -> Result<(), Error> {
    let config = NodeConfig::read(config_path)?;
    let runtime =
        tokio::Runner::new(tokio::Config::new().with_storage_directory(config.storage_dir.clone()));
    runtime.start(|context| async move {
        let _rpc_server = start_node(context, config).await?;
        futures::future::pending::<()>().await;
        #[allow(unreachable_code)]
        Ok(())
    })
}

async fn start_node(
    context: tokio::Context,
    config: NodeConfig,
) -> Result<nunchi_rpc::ServerHandle, Error> {
    let private_key = decode_unit::<ed25519::PrivateKey>(&config.private_key, "private_key")?;
    let public_key = private_key.public_key();
    let max_participants = NonZeroU32::new(config.peer_config.max_participants_per_round())
        .ok_or(Error::EmptyValidatorSet)?;
    let output = decode_output(&config.output, max_participants)?;
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
        rpc = %config.rpc_address,
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
        max_block_transactions: config.max_block_transactions,
        pool_config: PoolConfig::default(),
        genesis: read_genesis(config.genesis_path.as_ref())?,
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

    let (engine, handle) = Engine::new(context.child("engine"), engine_config).await;
    engine.start(
        pending,
        recovered,
        resolver,
        broadcast,
        dkg,
        marshal_resolver,
        ContinueOnUpdate::boxed(),
    );

    let rpc_module = rpc::module(
        handle.query(),
        handle.submitter.clone(),
        handle.applied_height.clone(),
    )?;
    let rpc_server = nunchi_rpc::ServerBuilder::default()
        .build(config.rpc_address)
        .await?
        .start(rpc_module);

    info!(node = %config.name, "coins-chain validator started");
    Ok(rpc_server)
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

fn read_genesis(path: Option<&PathBuf>) -> Result<Option<ChainGenesis>, Error> {
    path.map(ChainGenesis::read)
        .transpose()
        .map_err(Error::Genesis)
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
    fn generated_testnet_has_unique_ports_dirs_and_complete_peer_sets() {
        let dir = std::env::temp_dir().join(format!("coins-chain-testnet-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let manifest = generate_local_testnet(LocalTestnetConfig {
            validators: 4,
            base_port: 40_000,
            base_rpc_port: 41_000,
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
            assert_eq!(config.peer_config.participants.len(), 4);
            assert_eq!(config.bootstrappers.len(), 3);
            assert!(!config
                .bootstrappers
                .iter()
                .any(|bootstrapper| bootstrapper.address.port() == node.port));

            // The threshold material must round-trip from the written config.
            let max_participants =
                NonZeroU32::new(config.peer_config.max_participants_per_round()).unwrap();
            decode_output(&config.output, max_participants).expect("decode output");
            decode_unit::<group::Share>(&config.share, "share").expect("decode share");
            decode_unit::<ed25519::PrivateKey>(&config.private_key, "private_key")
                .expect("decode private key");
        }

        let _ = fs::remove_dir_all(dir);
    }
}
