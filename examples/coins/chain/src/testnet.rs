//! Standalone local-testnet support: config generation and a real-network node runner.
//!
//! [`generate_local_testnet`] performs a trusted setup (key generation plus an initial threshold
//! deal) and writes one TOML config per node alongside a manifest that process runners such as
//! `narae` consume. [`run_node`] boots a validator or secondary from one of those configs on the
//! tokio runtime with authenticated peer discovery, and serves the aggregated JSON-RPC module.

use crate::indexer::Client as _;
use crate::{
    channels,
    engine::{Config as EngineConfig, Engine},
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
    ContinueOnUpdate, PeerConfig, Storage as DkgStorage, StorageKey, StorageProtector,
    UpdateCallBack, MAX_SUPPORTED_MODE,
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
    pub secondaries: u32,
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

/// One node's standalone configuration.
///
/// Key material is hex-encoded commonware-codec bytes. The threshold `output` and optional
/// validator `share` come from the trusted initial deal; subsequent epochs reshare on-chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub private_key: String,
    pub dkg_storage_key: String,
    pub output: String,
    pub share: Option<String>,
    pub peer_config: PeerConfig<PublicKey>,
    #[serde(default, with = "secondary_serde")]
    pub secondary_nodes: Set<PublicKey>,
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
        let raw = fs::read_to_string(path).map_err(Error::Io)?;
        let config: Self = toml::from_str(&raw).map_err(Error::TomlDeserialize)?;
        config.validate()?;
        Ok(config)
    }

    fn read_validated(path: impl AsRef<Path>) -> Result<ValidatedNodeConfig, Error> {
        let raw = fs::read_to_string(path).map_err(Error::Io)?;
        let config: Self = toml::from_str(&raw).map_err(Error::TomlDeserialize)?;
        config.into_validated()
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

    fn validate(&self) -> Result<(), Error> {
        self.clone().into_validated().map(|_| ())
    }

    fn into_validated(self) -> Result<ValidatedNodeConfig, Error> {
        let prune_config = self.prune_config()?;
        crate::history::RetentionPolicy::new(prune_config)?;
        let private_key = decode_unit::<ed25519::PrivateKey>(&self.private_key, "private_key")?;
        let dkg_storage_key = decode_storage_key(&self.dkg_storage_key)?;
        let public_key = private_key.public_key();

        if self.peer_config.participants.is_empty() {
            return Err(Error::EmptyValidatorSet);
        }
        let schedule = &self.peer_config.num_participants_per_round;
        if schedule.is_empty()
            || schedule
                .iter()
                .any(|count| *count == 0 || *count as usize > self.peer_config.participants.len())
        {
            return Err(Error::InvalidParticipantSchedule);
        }
        let max_participants = NonZeroU32::new(
            schedule.iter().copied().max().expect("schedule checked non-empty"),
        )
        .expect("schedule checked non-zero");
        let output = decode_output(&self.output, max_participants)?;
        let protocol_config = nunchi_dkg::DkgProtocolConfig::<MinSig, PublicKey> {
            state_format_version: nunchi_dkg::STATE_FORMAT_VERSION,
            namespace: NAMESPACE.to_vec(),
            epoch_length: self.epoch_length,
            participants: self.peer_config.participants.clone(),
            num_participants_per_round: schedule.clone(),
            mode: commonware_cryptography::bls12381::primitives::sharing::Mode::NonZeroCounter,
            mode_version: 0,
            fault_model: nunchi_dkg::public::N3F1_FAULT_MODEL,
            trusted_initial_identity: *output.public().public(),
        };
        protocol_config.validate().map_err(Error::DkgConfig)?;

        if output.players() != &self.peer_config.dealers(0) {
            return Err(Error::InitialPlayersMismatch);
        }
        let validator = self.peer_config.participants.position(&public_key).is_some();
        let secondary = self.secondary_nodes.position(&public_key).is_some();
        if validator && secondary {
            return Err(Error::AmbiguousLocalIdentity);
        }
        if self
            .peer_config
            .participants
            .iter()
            .any(|key| self.secondary_nodes.position(key).is_some())
        {
            return Err(Error::OverlappingNodeSets);
        }

        let role = match (validator, secondary, self.share.as_deref()) {
            (true, false, Some(encoded)) => {
                let share = decode_unit::<group::Share>(encoded, "share")
                    .map_err(|error| Error::InvalidShareEncoding(error.to_string()))?;
                nunchi_dkg::validate_share(&output, &public_key, &share)
                    .map_err(Error::InvalidShare)?;
                NodeRole::Validator { share }
            }
            (true, false, None) => return Err(Error::ValidatorMissingShare),
            (false, true, None) => NodeRole::Secondary,
            (false, true, Some(_)) => return Err(Error::SecondaryHasShare),
            (false, false, _) => return Err(Error::UnknownLocalIdentity),
            (true, true, _) => unreachable!("overlapping local identity rejected above"),
        };
        if matches!(role, NodeRole::Secondary) && self.indexer_url.is_some() {
            return Err(Error::SecondaryIndexer);
        }
        for bootstrapper in &self.bootstrappers {
            if self
                .peer_config
                .participants
                .position(&bootstrapper.public_key)
                .is_none()
                && self
                    .secondary_nodes
                    .position(&bootstrapper.public_key)
                    .is_none()
            {
                return Err(Error::UnknownBootstrapper(
                    bootstrapper.public_key.to_string(),
                ));
            }
        }
        let genesis = read_genesis(self.genesis_path.as_ref())?;

        Ok(ValidatedNodeConfig {
            config: self,
            private_key,
            dkg_storage_key,
            public_key,
            output,
            role,
            prune_config,
            genesis,
        })
    }
}

#[derive(Clone, Debug)]
enum NodeRole {
    Validator { share: group::Share },
    Secondary,
}

impl NodeRole {
    fn share(&self) -> Option<group::Share> {
        match self {
            Self::Validator { share } => Some(share.clone()),
            Self::Secondary => None,
        }
    }

    fn node_type(&self) -> rpc::NodeType {
        match self {
            Self::Validator { .. } => rpc::NodeType::Validator,
            Self::Secondary => rpc::NodeType::Secondary,
        }
    }
}

struct ValidatedNodeConfig {
    config: NodeConfig,
    private_key: ed25519::PrivateKey,
    dkg_storage_key: StorageKey,
    public_key: PublicKey,
    output: Output<MinSig, PublicKey>,
    role: NodeRole,
    prune_config: PruneConfig,
    genesis: Option<ChainGenesis>,
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

mod secondary_serde {
    use super::*;
    use serde::{de::SeqAccess, de::Visitor, Deserializer, Serializer};

    pub fn serialize<S>(value: &Set<PublicKey>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(value.iter().map(|key| hex(&key.encode())))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Set<PublicKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SetVisitor;

        impl<'de> Visitor<'de> for SetVisitor {
            type Value = Set<PublicKey>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of unique hex public keys")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut keys = Vec::new();
                while let Some(value) = sequence.next_element::<String>()? {
                    let bytes = from_hex(&value)
                        .ok_or_else(|| serde::de::Error::custom("invalid hex public key"))?;
                    let key = PublicKey::decode(bytes.as_slice())
                        .map_err(serde::de::Error::custom)?;
                    keys.push(key);
                }
                Set::try_from(keys).map_err(|_| serde::de::Error::custom("duplicate item"))
            }
        }

        deserializer.deserialize_seq(SetVisitor)
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
    #[error("expected {nodes} public hosts, got {hosts}")]
    PublicHostCount { nodes: u32, hosts: usize },
    #[error("validator count is too large for this platform: {0}")]
    ValidatorCountTooLarge(#[from] TryFromIntError),
    #[error("total node count overflowed")]
    NodeCountOverflow,
    #[error("port range starting at {base_port} cannot fit {nodes} nodes")]
    PortRange { base_port: u16, nodes: u32 },
    #[error("trusted setup failed: {0}")]
    Deal(commonware_cryptography::bls12381::dkg::feldman_desmedt::Error),
    #[error("missing threshold share for validator {0}")]
    MissingShare(usize),
    #[error("invalid DKG participant schedule")]
    InvalidParticipantSchedule,
    #[error("invalid DKG protocol configuration: {0}")]
    DkgConfig(nunchi_dkg::public::Error),
    #[error("initial output players do not match the round-zero validator schedule")]
    InitialPlayersMismatch,
    #[error("validator and secondary sets overlap")]
    OverlappingNodeSets,
    #[error("local identity is not allowlisted as a validator or secondary")]
    UnknownLocalIdentity,
    #[error("local identity is allowlisted in both node sets")]
    AmbiguousLocalIdentity,
    #[error("validator configuration is missing its threshold share")]
    ValidatorMissingShare,
    #[error("secondary configuration unexpectedly contains a threshold share")]
    SecondaryHasShare,
    #[error("invalid validator threshold share: {0}")]
    InvalidShare(nunchi_dkg::public::Error),
    #[error("failed to decode validator threshold share: {0}")]
    InvalidShareEncoding(String),
    #[error("secondary nodes cannot configure an indexer URL")]
    SecondaryIndexer,
    #[error("bootstrapper {0} is not in either node allowlist")]
    UnknownBootstrapper(String),
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
    let total_nodes = config
        .validators
        .checked_add(config.secondaries)
        .ok_or(Error::NodeCountOverflow)?;
    let node_count = usize::try_from(total_nodes)?;
    let validator_count = usize::try_from(config.validators)?;
    check_port_range(config.base_port, total_nodes)?;
    check_port_range(config.base_rpc_port, total_nodes)?;
    check_port_range(config.base_metrics_port, total_nodes)?;
    if let Some(public_ips) = &config.public_ips {
        if public_ips.len() != node_count {
            return Err(Error::PublicHostCount {
                nodes: total_nodes,
                hosts: public_ips.len(),
            });
        }
    }

    let private_keys = (0..total_nodes)
        .map(|index| ed25519::PrivateKey::from_seed(config.seed.wrapping_add(index as u64)))
        .collect::<Vec<_>>();
    let public_keys = private_keys
        .iter()
        .map(|signer| signer.public_key())
        .collect::<Vec<_>>();
    let participants_set = Set::from_iter_dedup(public_keys[..validator_count].iter().cloned());
    let secondary_nodes = Set::from_iter_dedup(public_keys[validator_count..].iter().cloned());

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
        let validator = index < validator_count;
        let role_index = if validator { index } else { index - validator_count };
        let name = if validator {
            format!("validator-{role_index}")
        } else {
            format!("secondary-{role_index}")
        };
        let port = config.base_port + u16::try_from(index)?;
        let rpc_port = config.base_rpc_port + u16::try_from(index)?;
        let metrics_port = config.base_metrics_port + u16::try_from(index)?;
        let storage_dir = config
            .storage_dir
            .as_ref()
            .unwrap_or(&config.base_data_dir)
            .join(&name);
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
        let bootstrappers = public_keys
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
        let share = validator
            .then(|| {
                shares
                    .get_value(&public_keys[index])
                    .map(encode)
                    .ok_or(Error::MissingShare(index))
            })
            .transpose()?;
        let node_config = NodeConfig {
            name: name.clone(),
            private_key: encode(&private_keys[index]),
            dkg_storage_key: encode_storage_key(&storage_key(config.seed, index)),
            output: encode(&output),
            share,
            peer_config: peer_config.clone(),
            secondary_nodes: secondary_nodes.clone(),
            listen_address,
            dialable_address,
            rpc_address: SocketAddr::new(config.bind_ip, rpc_port),
            metrics_address: SocketAddr::new(config.bind_ip, metrics_port),
            bootstrappers,
            storage_dir: storage_dir.clone(),
            genesis_path: config.genesis_path.clone(),
            indexer_url: if validator {
                config.indexer_url.clone()
            } else {
                None
            },
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

fn check_port_range(base_port: u16, nodes: u32) -> Result<(), Error> {
    let out_of_range = || Error::PortRange {
        base_port,
        nodes,
    };
    let last_offset = u16::try_from(nodes - 1).map_err(|_| out_of_range())?;
    base_port
        .checked_add(last_offset)
        .ok_or_else(out_of_range)?;
    Ok(())
}

/// Run a single node from a generated config until it receives a shutdown signal or the
/// engine stops.
///
/// On Unix the node exits cleanly on SIGINT or SIGTERM. On other platforms it responds to
/// Ctrl-C. If the engine stops before a signal is received the function returns
/// [`Error::Engine`].
pub fn run_node(config_path: impl AsRef<Path>) -> Result<(), Error> {
    let validated = NodeConfig::read_validated(config_path)?;
    let runtime = tokio::Runner::new(
        tokio::Config::new().with_storage_directory(validated.config.storage_dir.clone()),
    );
    runtime.start(|context| async move {
        tokio::telemetry::init(
            context.child("telemetry"),
            tokio::telemetry::Logs {
                level: log_level_from_env(),
                json: false,
            },
            Some(validated.config.metrics_address),
            None,
        );
        let (rpc_server, engine_handle) = start_node(&context, validated).await?;
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
    validated: ValidatedNodeConfig,
) -> Result<
    (
        nunchi_rpc::ServerHandle,
        Handle<Result<(), crate::engine::EngineError>>,
    ),
    Error,
> {
    let ValidatedNodeConfig {
        config,
        private_key,
        dkg_storage_key,
        public_key,
        output,
        role,
        prune_config,
        genesis,
    } = validated;
    let max_participants = NonZeroU32::new(config.peer_config.max_participants_per_round())
        .expect("validated participant schedule is non-empty");
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
        role = ?role,
        "starting coins-chain node"
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
    oracle.track(
        0,
        commonware_p2p::TrackedPeers::new(
            config.peer_config.participants.clone(),
            config.secondary_nodes.clone(),
        ),
    );

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
            dkg_storage_key,
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
        dkg_storage_key,
        output,
        share: role.share(),
        peer_config: config.peer_config.clone(),
        secondary_nodes: config.secondary_nodes.clone(),
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
        genesis,
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
        role.node_type(),
    )?;
    let rpc_server = nunchi_rpc::ServerBuilder::default()
        .build(config.rpc_address)
        .await?
        .start(rpc_module);

    info!(node = %config.name, role = ?role, "coins-chain node started");
    Ok((rpc_server, engine_handle))
}

async fn upload_current_dkg_output(
    context: &tokio::Context,
    node_name: &str,
    dkg_storage_key: StorageKey,
    public_key: PublicKey,
    max_participants: NonZeroU32,
    client: indexer::HttpClient,
    metrics: indexer::IndexerMetrics,
) {
    let started = Instant::now();
    let storage = match DkgStorage::<_, MinSig, PublicKey>::init(
        context.child("dkg_output_seed"),
        node_name,
        StorageProtector::new(dkg_storage_key),
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
    dkg_storage_key: StorageKey,
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
                    dkg_storage_key,
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
