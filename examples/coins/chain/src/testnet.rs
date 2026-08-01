//! Standalone local-testnet support: config generation and a real-network node runner.
//!
//! [`generate_local_testnet`] performs a trusted setup (key generation plus an initial threshold
//! deal) and writes one TOML config per validator alongside a manifest that process runners such
//! as `narae` consume. [`run_node`] boots a single validator from one of those configs on the
//! tokio runtime with authenticated peer discovery, and serves the aggregated JSON-RPC module.

use crate::indexer::Client as _;
use crate::{
    channels,
    engine::{Config as EngineConfig, Engine, RecoveryExportConfig},
    genesis::{ChainGenesis, GenesisError},
    indexer, rpc, PublicKey, BLOCKS_PER_EPOCH, NAMESPACE,
};
use commonware_codec::{Decode, DecodeExt, Encode, EncodeSize};
use commonware_consensus::marshal;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{deal, Output},
        primitives::{group, variant::MinSig},
    },
    ed25519, Signer,
};
use commonware_formatting::{from_hex, hex};
use commonware_glue::stateful::PruneConfig;
use commonware_p2p::{
    authenticated::discovery::{self, Network},
    Ingress, Manager,
};
use commonware_runtime::{
    tokio, Clock as _, Handle, Runner as _, Spawner as _, Strategizer as _, Supervisor as _,
};
use commonware_utils::{ordered::Set, Hostname, N3f1, NZUsize, NZU32};
use governor::Quota;
use nunchi_dkg::{
    ContinueOnUpdate, PeerConfig, RecoveryProtectors, Storage as DkgStorage, StorageKey,
    StorageProtector, UpdateCallBack, MAX_SUPPORTED_MODE,
};
use nunchi_mempool::PoolConfig;
use nunchi_chain::engine::{
    default_state_prune_config, validate_state_prune_config, PruneConfigError,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display},
    fs,
    net::{IpAddr, SocketAddr},
    num::{NonZeroU32, NonZeroU64, NonZeroUsize, TryFromIntError},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};
use tracing::{info, warn, Level};

const DEFAULT_MAX_BLOCK_TRANSACTIONS: usize = 4_096;
const DEFAULT_MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
const DEFAULT_CHANNEL_BACKLOG: usize = 1024;

#[derive(Clone, Debug)]
pub struct LocalTestnetConfig {
    pub validators: u32,
    pub base_port: u16,
    pub base_rpc_port: u16,
    pub base_metrics_port: u16,
    pub base_data_dir: PathBuf,
    pub bind_ip: IpAddr,
    pub public_ips: Option<Vec<IpAddr>>,
    pub storage_dir: Option<PathBuf>,
    pub genesis_path: Option<PathBuf>,
    pub indexer_url: Option<String>,
    pub seed: u64,
}

/// The manifest written next to the generated node configs; process runners read this to know
/// what to launch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalTestnetManifest {
    pub chain: String,
    pub executable_path: PathBuf,
    #[serde(default)]
    pub indexer: IndexerManifest,
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
    pub metrics_port: u16,
    pub data_dir: PathBuf,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IndexerManifest {
    pub identity: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub output: String,
    pub participants: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DkgRecoveryExportConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub directory: PathBuf,
}

/// One validator's standalone configuration.
///
/// Key material is hex-encoded commonware-codec bytes. The threshold `output` and `share` come
/// from the trusted initial deal; subsequent epochs reshare on-chain via the DKG actor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub private_key: String,
    pub dkg_storage_key: String,
    pub output: String,
    pub share: String,
    pub peer_config: PeerConfig<PublicKey>,
    pub listen_address: SocketAddr,
    /// Address advertised to peers. IP literals use socket syntax (with brackets around IPv6),
    /// while DNS names use `hostname:port` without a URL scheme or path. DNS is resolved again
    /// whenever a disconnected peer retries this node, so operators should use a stable hostname
    /// and an appropriate TTL.
    #[serde(with = "ingress_serde")]
    pub dialable_address: Ingress,
    pub rpc_address: SocketAddr,
    pub metrics_address: SocketAddr,
    pub bootstrappers: Vec<BootstrapperConfig>,
    pub storage_dir: PathBuf,
    #[serde(default)]
    pub dkg_recovery_export: DkgRecoveryExportConfig,
    pub genesis_path: Option<PathBuf>,
    #[serde(default)]
    pub indexer_url: Option<String>,
    /// Number of finalized blocks in each consensus epoch.
    #[serde(default = "default_epoch_length")]
    pub epoch_length: NonZeroU64,
    /// Minimum timestamp delta between a block and its parent.
    #[serde(default = "default_min_block_interval_ms")]
    pub min_block_interval_ms: NonZeroU64,
    /// Maximum self-contained finalized payloads retained while the indexer is unavailable.
    #[serde(default = "default_indexer_spool_max_entries")]
    pub indexer_spool_max_entries: u64,
    /// Maximum logical encoded payload bytes retained by the indexer spool.
    #[serde(default = "default_indexer_spool_max_bytes")]
    pub indexer_spool_max_bytes: u64,
    /// Maximum encoded size accepted for one finalized payload.
    #[serde(default = "default_indexer_spool_max_payload_bytes")]
    pub indexer_spool_max_payload_bytes: u64,
    /// Maximum payload age before visible terminal expiry.
    #[serde(default = "default_indexer_spool_max_age_seconds")]
    pub indexer_spool_max_age_seconds: u64,
    pub consensus: ConsensusConfig,
    pub networking: NetworkConfig,
    /// Enable one-time peer QMDB state sync for a fresh joining node.
    #[serde(default)]
    pub state_sync: bool,
    /// Maximum number of marshal acknowledgements that may remain pending.
    pub max_pending_acks: NonZeroUsize,
    /// Finalized-height cadence for marshal and QMDB pruning maintenance.
    pub maintenance_interval: NonZeroUsize,
    /// Blocks retained by marshal beyond the mandatory acknowledgement window.
    pub retained_marshal_blocks: usize,
    /// Operation-history blocks retained by QMDB beyond the mandatory acknowledgement window.
    pub retained_qmdb_blocks: usize,
    pub max_block_transactions: usize,
}

impl NodeConfig {
    pub fn read(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(Error::Io)?;
        let config: Self = toml::from_str(&raw).map_err(Error::TomlDeserialize)?;
        let prune_config = config.prune_config()?;
        crate::history::RetentionPolicy::new(prune_config)?;
        config.validate_recovery_paths(path)?;
        Ok(config)
    }

    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let raw = toml::to_string_pretty(self).map_err(Error::TomlSerialize)?;
        fs::write(path, raw).map_err(Error::Io)
    }

    pub fn prune_config(&self) -> Result<PruneConfig, PruneConfigError> {
        validate_state_prune_config(PruneConfig {
            max_pending_acks: self.max_pending_acks,
            maintenance_interval: self.maintenance_interval,
            retained_marshal_blocks: self.retained_marshal_blocks,
            retained_qmdb_blocks: self.retained_qmdb_blocks,
        })
    }

    fn validate_recovery_paths(&self, config_path: &Path) -> Result<(), Error> {
        if !self.dkg_recovery_export.enabled {
            return Ok(());
        }
        if self.dkg_recovery_export.directory.as_os_str().is_empty() {
            return Err(Error::InvalidRecoveryDirectory);
        }
        let recovery = self.dkg_recovery_export.directory.canonicalize()?;
        let storage = canonicalize_storage_path(&self.storage_dir)?;
        if !recovery.is_dir()
            || recovery.starts_with(&storage)
            || storage.starts_with(&recovery)
        {
            return Err(Error::InvalidRecoveryDirectory);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let config_mode = fs::metadata(config_path)?.permissions().mode();
            let directory_mode = fs::metadata(&recovery)?.permissions().mode();
            if config_mode & 0o077 != 0 || directory_mode & 0o077 != 0 {
                return Err(Error::UnsafeRecoveryPermissions);
            }
        }
        let probe = recovery.join(format!(".nunchi-write-probe-{}", std::process::id()));
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&probe)?;
        drop(file);
        fs::remove_file(probe)?;
        Ok(())
    }
}

fn canonicalize_storage_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    let mut missing = Vec::new();
    let mut existing = path;
    loop {
        match existing.canonicalize() {
            Ok(mut canonical) => {
                for component in missing.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let component = existing.file_name().ok_or(error)?;
                missing.push(component.to_os_string());
                existing = existing.parent().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "storage directory has no existing ancestor",
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn default_epoch_length() -> NonZeroU64 {
    BLOCKS_PER_EPOCH
}

fn default_min_block_interval_ms() -> NonZeroU64 {
    nunchi_chain::DEFAULT_MIN_BLOCK_INTERVAL_MS
}

fn default_indexer_spool_max_entries() -> u64 {
    indexer::SpoolLimits::default().max_entries
}

fn default_indexer_spool_max_bytes() -> u64 {
    indexer::SpoolLimits::default().max_bytes
}

fn default_indexer_spool_max_payload_bytes() -> u64 {
    indexer::SpoolLimits::default().max_payload_bytes
}

fn default_indexer_spool_max_age_seconds() -> u64 {
    indexer::SpoolLimits::default().max_age.as_secs()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapperConfig {
    pub public_key: PublicKey,
    /// Address used to dial the bootstrapper. IP literals use socket syntax (with brackets around
    /// IPv6), while DNS names use `hostname:port` without a URL scheme or path. DNS is resolved on
    /// each reconnect attempt rather than continuously while a connection is healthy.
    pub address: Ingress,
}

#[derive(Debug, thiserror::Error)]
pub enum BootstrapperConfigError {
    #[error("bootstrapper is missing the '@' separator")]
    MissingSeparator,
    #[error("bootstrapper contains multiple '@' separators")]
    MultipleSeparators,
    #[error("bootstrapper is missing a public key")]
    MissingPublicKey,
    #[error("bootstrapper public key must be exactly 64 lowercase hexadecimal characters")]
    InvalidPublicKeyHex,
    #[error("invalid bootstrapper public key: {0}")]
    InvalidPublicKey(#[source] commonware_codec::Error),
    #[error("bootstrapper is missing an address")]
    MissingAddress,
    #[error("invalid bootstrapper address: {0}")]
    InvalidAddress(String),
}

impl FromStr for BootstrapperConfig {
    type Err = BootstrapperConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (public_key, address) = value
            .split_once('@')
            .ok_or(BootstrapperConfigError::MissingSeparator)?;
        if address.contains('@') {
            return Err(BootstrapperConfigError::MultipleSeparators);
        }
        if public_key.is_empty() {
            return Err(BootstrapperConfigError::MissingPublicKey);
        }
        if address.is_empty() {
            return Err(BootstrapperConfigError::MissingAddress);
        }

        Ok(Self {
            public_key: parse_bootstrapper_public_key(public_key)?,
            address: parse_ingress(address)
                .map_err(|error| BootstrapperConfigError::InvalidAddress(error.to_string()))?,
        })
    }
}

impl Display for BootstrapperConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}@{}",
            self.public_key,
            format_ingress(&self.address)
        )
    }
}

impl Serialize for BootstrapperConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BootstrapperConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

fn parse_bootstrapper_public_key(
    value: &str,
) -> Result<PublicKey, BootstrapperConfigError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BootstrapperConfigError::InvalidPublicKeyHex);
    }
    let bytes = from_hex(value).ok_or(BootstrapperConfigError::InvalidPublicKeyHex)?;
    PublicKey::decode(bytes.as_slice()).map_err(BootstrapperConfigError::InvalidPublicKey)
}

#[derive(Debug, thiserror::Error)]
enum PeerAddressError {
    #[error("peer address must not contain a URL scheme or path")]
    SchemeOrPath,
    #[error("peer address is missing a port")]
    MissingPort,
    #[error("peer address is missing a host")]
    MissingHost,
    #[error("IPv6 peer addresses must use bracketed socket syntax")]
    UnbracketedIpv6,
    #[error("invalid peer address port: {0}")]
    InvalidPort(String),
    #[error("invalid peer address hostname: {0}")]
    InvalidHostname(String),
}

fn parse_ingress(value: &str) -> Result<Ingress, PeerAddressError> {
    if let Ok(address) = SocketAddr::from_str(value) {
        return Ok(Ingress::Socket(address));
    }
    if value.contains("://") {
        return Err(PeerAddressError::SchemeOrPath);
    }

    let (host, port) = value
        .rsplit_once(':')
        .ok_or(PeerAddressError::MissingPort)?;
    if host.is_empty() {
        return Err(PeerAddressError::MissingHost);
    }
    if port.is_empty() {
        return Err(PeerAddressError::MissingPort);
    }
    if host.contains(':') {
        return Err(PeerAddressError::UnbracketedIpv6);
    }
    let port = port
        .parse::<u16>()
        .map_err(|error| PeerAddressError::InvalidPort(error.to_string()))?;
    let host = Hostname::new(host.to_ascii_lowercase())
        .map_err(|error| PeerAddressError::InvalidHostname(error.to_string()))?;
    Ok(Ingress::Dns { host, port })
}

fn format_ingress(ingress: &Ingress) -> String {
    match ingress {
        Ingress::Socket(address) => address.to_string(),
        Ingress::Dns { host, port } => format!("{host}:{port}"),
    }
}

mod ingress_serde {
    use super::*;
    use serde::{de::Error as _, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ingress, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_ingress(&value).map_err(D::Error::custom)
    }

    pub fn serialize<S>(ingress: &Ingress, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format_ingress(ingress))
    }
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
    #[error("expected {validators} public hosts, got {hosts}")]
    PublicHostCount { validators: u32, hosts: usize },
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
    Genesis(#[from] GenesisError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to serialize toml: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("failed to parse toml: {0}")]
    TomlDeserialize(#[from] toml::de::Error),
    #[error("invalid prune configuration: {0}")]
    PruneConfig(#[from] PruneConfigError),
    #[error("invalid finalized-history retention policy: {0}")]
    RetentionPolicy(#[from] crate::history::RetentionPolicyError),
    #[error("DKG recovery export directory must be an existing independent directory")]
    InvalidRecoveryDirectory,
    #[error("DKG recovery config and directory must not be group/world readable")]
    UnsafeRecoveryPermissions,
    #[error("engine startup failed: {0}")]
    EngineStartup(#[from] crate::engine::StartupError),
    #[error("engine stopped unexpectedly: {0}")]
    Engine(#[from] crate::engine::EngineError),
    #[error("engine task failed: {0}")]
    EngineTask(commonware_runtime::Error),
    #[error("runtime shutdown failed: {0}")]
    Shutdown(commonware_runtime::Error),
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
    check_port_range(config.base_metrics_port, config.validators)?;
    if let Some(public_ips) = &config.public_ips {
        if public_ips.len() != node_count {
            return Err(Error::PublicHostCount {
                validators: config.validators,
                hosts: public_ips.len(),
            });
        }
    }

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
        let metrics_port = config.base_metrics_port + u16::try_from(index)?;
        let storage_dir = config
            .storage_dir
            .clone()
            .unwrap_or_else(|| config.base_data_dir.join(&name));
        if config.storage_dir.is_none() {
            fs::create_dir_all(&storage_dir)?;
        }
        let config_path = config.base_data_dir.join(format!("{name}.toml"));
        let listen_address = SocketAddr::new(config.bind_ip, port);
        let dialable_address = Ingress::Socket(SocketAddr::new(
            config
                .public_ips
                .as_ref()
                .map(|hosts| hosts[index])
                .unwrap_or(config.bind_ip),
            port,
        ));
        let bootstrappers = participants
            .iter()
            .enumerate()
            .filter(|(candidate, _)| *candidate != index)
            .map(|(candidate, public_key)| {
                Ok(BootstrapperConfig {
                    public_key: public_key.clone(),
                    address: Ingress::Socket(SocketAddr::new(
                        config
                            .public_ips
                            .as_ref()
                            .map(|hosts| hosts[candidate])
                            .unwrap_or(config.bind_ip),
                        config.base_port + u16::try_from(candidate)?,
                    )),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let share = shares
            .get_value(&participants[index])
            .ok_or(Error::MissingShare(index))?;
        let node_config = NodeConfig {
            name: name.clone(),
            private_key: encode(&private_keys[index]),
            dkg_storage_key: encode_storage_key(&storage_key(config.seed, index)),
            output: encode(&output),
            share: encode(share),
            peer_config: peer_config.clone(),
            listen_address,
            dialable_address,
            rpc_address: SocketAddr::new(config.bind_ip, rpc_port),
            metrics_address: SocketAddr::new(config.bind_ip, metrics_port),
            bootstrappers,
            storage_dir: storage_dir.clone(),
            dkg_recovery_export: DkgRecoveryExportConfig::default(),
            genesis_path: config.genesis_path.clone(),
            indexer_url: config.indexer_url.clone(),
            epoch_length: default_epoch_length(),
            min_block_interval_ms: default_min_block_interval_ms(),
            indexer_spool_max_entries: default_indexer_spool_max_entries(),
            indexer_spool_max_bytes: default_indexer_spool_max_bytes(),
            indexer_spool_max_payload_bytes: default_indexer_spool_max_payload_bytes(),
            indexer_spool_max_age_seconds: default_indexer_spool_max_age_seconds(),
            consensus: ConsensusConfig::default(),
            networking: NetworkConfig::default(),
            state_sync: false,
            max_pending_acks: default_state_prune_config().max_pending_acks,
            maintenance_interval: default_state_prune_config().maintenance_interval,
            retained_marshal_blocks: default_state_prune_config().retained_marshal_blocks,
            retained_qmdb_blocks: default_state_prune_config().retained_qmdb_blocks,
            max_block_transactions: DEFAULT_MAX_BLOCK_TRANSACTIONS,
        };
        node_config.write(&config_path)?;
        nodes.push(ManifestNode {
            name,
            config_path,
            port,
            rpc_port,
            metrics_port,
            data_dir: storage_dir,
        });
    }

    Ok(LocalTestnetManifest {
        chain: "coins-chain".to_string(),
        executable_path: PathBuf::from("coins-chain-node"),
        indexer: IndexerManifest {
            identity: encode(output.public().public()),
            output: encode(&output),
            participants: config.validators,
        },
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

/// Run a single validator from a generated config until it receives a shutdown signal or the
/// engine stops.
///
/// On Unix the node exits cleanly on SIGINT or SIGTERM. On other platforms it responds to
/// Ctrl-C. If the engine stops before a signal is received the function returns
/// [`Error::Engine`].
pub fn run_node(config_path: impl AsRef<Path>) -> Result<(), Error> {
    let config = NodeConfig::read(config_path)?;
    let runtime =
        tokio::Runner::new(tokio::Config::new().with_storage_directory(config.storage_dir.clone()));
    runtime.start(|context| async move {
        tokio::telemetry::init(
            context.child("telemetry"),
            tokio::telemetry::Logs {
                level: log_level_from_env(),
                json: false,
            },
            Some(config.metrics_address),
            None,
        );
        let (rpc_server, engine_handle) = start_node(&context, config).await?;
        wait_for_shutdown(context, rpc_server, engine_handle).await
    })
}

fn log_level_from_env() -> Level {
    std::env::var("RUST_LOG")
        .ok()
        .and_then(|value| Level::from_str(&value).ok())
        .unwrap_or(Level::INFO)
}

/// Block until a shutdown signal is received or the engine handle resolves.
async fn wait_for_shutdown(
    context: tokio::Context,
    rpc_server: nunchi_rpc::ServerHandle,
    engine_handle: Handle<Result<(), crate::engine::EngineError>>,
) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use ::tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt()).map_err(Error::Io)?;
        let mut sigterm = signal(SignalKind::terminate()).map_err(Error::Io)?;
        ::tokio::select! {
            _ = sigint.recv() => {
                info!("received SIGINT, shutting down");
                shutdown(context, rpc_server).await
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM, shutting down");
                shutdown(context, rpc_server).await
            }
            result = engine_handle => {
                result.map_err(Error::EngineTask)??;
                Ok(())
            }
        }
    }
    #[cfg(not(unix))]
    {
        ::tokio::select! {
            result = ::tokio::signal::ctrl_c() => {
                result.map_err(Error::Io)?;
                info!("received Ctrl-C, shutting down");
                shutdown(context, rpc_server).await
            }
            result = engine_handle => {
                result.map_err(Error::EngineTask)??;
                Ok(())
            }
        }
    }
}

async fn shutdown(
    context: tokio::Context,
    rpc_server: nunchi_rpc::ServerHandle,
) -> Result<(), Error> {
    let _ = rpc_server.stop();
    context
        .child("shutdown")
        .stop(0, None)
        .await
        .map_err(Error::Shutdown)
}

async fn start_node(
    context: &tokio::Context,
    config: NodeConfig,
) -> Result<
    (
        nunchi_rpc::ServerHandle,
        Handle<Result<(), crate::engine::EngineError>>,
    ),
    Error,
> {
    let prune_config = config.prune_config()?;
    crate::history::RetentionPolicy::new(prune_config)?;
    let private_key = decode_unit::<ed25519::PrivateKey>(&config.private_key, "private_key")?;
    let mut dkg_storage_key = decode_storage_key(&config.dkg_storage_key)?;
    let dkg_storage_protector = StorageProtector::new(dkg_storage_key);
    let recovery_protectors = config
        .dkg_recovery_export
        .enabled
        .then(|| RecoveryProtectors::new(dkg_storage_key));
    dkg_storage_key.fill(0);
    let public_key = private_key.public_key();
    let max_participants = NonZeroU32::new(config.peer_config.max_participants_per_round())
        .ok_or(Error::EmptyValidatorSet)?;
    let output = decode_output(&config.output, max_participants)?;
    let share = decode_unit::<group::Share>(&config.share, "share")?;
    let bootstrappers = config
        .bootstrappers
        .iter()
        .map(|bootstrapper| {
            (
                bootstrapper.public_key.clone(),
                bootstrapper.address.clone(),
            )
        })
        .collect();

    info!(
        node = %config.name,
        public_key = %public_key,
        listen = %config.listen_address,
        dialable = ?config.dialable_address,
        rpc = %config.rpc_address,
        metrics = %config.metrics_address,
        "starting coins-chain validator"
    );

    let p2p_config = discovery::Config::local(
        private_key.clone(),
        NAMESPACE,
        config.listen_address,
        config.dialable_address.clone(),
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
    let mempool = register(channels::MEMPOOL);
    let clob = register(channels::CLOB);
    let probe = register(channels::PROBE);
    let state_sync = register(channels::STATE_SYNC);
    network.start();

    let indexer_client = config.indexer_url.as_deref().map(|url| {
        let metrics = indexer::IndexerMetrics::register(&context.child("indexer"));
        (
            indexer::HttpClient::new(url).with_metrics(metrics.clone()),
            metrics,
        )
    });
    if let Some((client, metrics)) = indexer_client.clone() {
        spawn_current_dkg_output_uploader(
            context,
            config.name.clone(),
            dkg_storage_protector.clone(),
            public_key.clone(),
            max_participants,
            client,
            metrics,
        );
    }
    let engine_config: EngineConfig<_, _, _> = EngineConfig {
        blocker: oracle.clone(),
        manager: oracle.clone(),
        partition_prefix: config.name.clone(),
        signer: private_key,
        storage_dir: config.storage_dir.clone(),
        dkg_storage_protector,
        recovery_export: recovery_protectors.map(|protectors| RecoveryExportConfig {
            directory: config.dkg_recovery_export.directory.clone(),
            bundle_protector: protectors.bundle,
            manifest_protector: protectors.manifest,
        }),
        output,
        share: Some(share),
        peer_config: config.peer_config.clone(),
        epoch_length: config.epoch_length,
        min_block_interval_ms: config.min_block_interval_ms,
        leader_timeout: Duration::from_millis(config.consensus.leader_timeout_ms),
        certification_timeout: Duration::from_millis(config.consensus.certification_timeout_ms),
        strategy: context
            .strategy(std::thread::available_parallelism().unwrap_or(std::num::NonZeroUsize::MIN)),
        state_sync: config.state_sync,
        prune_config,
        max_block_transactions: config.max_block_transactions,
        pool_config: PoolConfig::default(),
        genesis: read_genesis(config.genesis_path.as_ref())?,
        indexer: indexer_client.map(|(client, _metrics)| client),
        indexer_spool_limits: indexer::SpoolLimits {
            max_entries: config.indexer_spool_max_entries,
            max_bytes: config.indexer_spool_max_bytes,
            max_payload_bytes: config.indexer_spool_max_payload_bytes,
            max_age: Duration::from_secs(config.indexer_spool_max_age_seconds),
        },
    };
    let dkg_callback: Box<dyn UpdateCallBack<MinSig, PublicKey>> = ContinueOnUpdate::boxed();

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

    let (engine, node_handle) = Engine::new(
        context.child("engine"),
        engine_config,
        probe,
        state_sync,
    )
    .await?;
    let engine_handle = engine.start(
        pending,
        recovered,
        resolver,
        broadcast,
        dkg,
        mempool,
        clob,
        marshal_resolver,
        dkg_callback,
    );

    let rpc_module = rpc::module(
        node_handle.query(),
        node_handle.submitter.clone(),
        node_handle.applied_height.clone(),
    )?;
    let rpc_server = nunchi_rpc::ServerBuilder::default()
        .build(config.rpc_address)
        .await?
        .start(rpc_module);

    info!(node = %config.name, "coins-chain validator started");
    Ok((rpc_server, engine_handle))
}

async fn upload_current_dkg_output(
    context: &tokio::Context,
    node_name: &str,
    storage_protector: StorageProtector,
    public_key: PublicKey,
    max_participants: NonZeroU32,
    client: indexer::HttpClient,
    metrics: indexer::IndexerMetrics,
) {
    let started = Instant::now();
    let storage = match DkgStorage::<_, MinSig, PublicKey>::init(
        context.child("dkg_output_seed"),
        node_name,
        storage_protector,
        NAMESPACE.to_vec(),
        public_key,
        max_participants,
        MAX_SUPPORTED_MODE,
    )
    .await
    {
        Ok(storage) => storage,
        Err(error) => {
            warn!(%error, "failed to open DKG storage for indexer upload");
            metrics.dkg_upload_completed(indexer::DkgUploadStatus::Failure, started.elapsed());
            return;
        }
    };
    let Some((epoch, state)) = storage.epoch() else {
        metrics.dkg_upload_completed(indexer::DkgUploadStatus::NoEpoch, started.elapsed());
        return;
    };
    metrics.dkg_upload_last_attempt_epoch(epoch.get());
    let Some(output) = state.output else {
        metrics.dkg_upload_completed(indexer::DkgUploadStatus::NoOutput, started.elapsed());
        return;
    };
    metrics.dkg_upload_output_bytes(output.encode_size() as u64);
    match client.dkg_output_upload(epoch, output).await {
        Ok(()) => {
            metrics.dkg_upload_last_success_epoch(epoch.get());
            metrics.dkg_upload_completed(indexer::DkgUploadStatus::Success, started.elapsed());
            info!(%epoch, "uploaded current DKG output to indexer");
        }
        Err(error) => {
            metrics.dkg_upload_completed(indexer::DkgUploadStatus::Failure, started.elapsed());
            warn!(%epoch, %error, "failed to upload current DKG output to indexer");
        }
    }
}

fn spawn_current_dkg_output_uploader(
    context: &tokio::Context,
    node_name: String,
    storage_protector: StorageProtector,
    public_key: PublicKey,
    max_participants: NonZeroU32,
    client: indexer::HttpClient,
    metrics: indexer::IndexerMetrics,
) {
    context
        .child("dkg_output_uploader")
        .spawn(move |context| async move {
            loop {
                upload_current_dkg_output(
                    &context,
                    &node_name,
                    storage_protector.clone(),
                    public_key.clone(),
                    max_participants,
                    client.clone(),
                    metrics.clone(),
                )
                .await;
                context.sleep(Duration::from_secs(60)).await;
            }
        });
}

pub(crate) fn decode_output(
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

pub(crate) fn decode_unit<T>(value: &str, field: &'static str) -> Result<T, Error>
where
    T: DecodeExt<()>,
{
    let bytes = decode_hex(value, field)?;
    T::decode(bytes.as_ref()).map_err(|source| Error::CodecDecode { field, source })
}

fn decode_hex(value: &str, field: &'static str) -> Result<Vec<u8>, Error> {
    from_hex(value).ok_or(Error::HexDecode { field })
}

pub(crate) fn decode_storage_key(value: &str) -> Result<StorageKey, Error> {
    let bytes = decode_hex(value, "dkg_storage_key")?;
    bytes.try_into().map_err(|_| Error::CodecDecode {
        field: "dkg_storage_key",
        source: commonware_codec::Error::InvalidLength(32),
    })
}

fn encode(value: &impl Encode) -> String {
    hex(&value.encode())
}

fn encode_storage_key(key: &StorageKey) -> String {
    hex(key)
}

fn storage_key(seed: u64, index: usize) -> StorageKey {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xd6b0_44a5_6d1b_5a11 ^ index as u64);
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    key
}
