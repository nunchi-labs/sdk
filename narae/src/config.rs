use nunchi_coins_chain::testnet::LocalTestnetManifest;
use std::path::{Path, PathBuf};

/// Runtime configuration for the narae TUI devnet runner.
///
/// Typically constructed from a `narae.toml` manifest via [`Config::read_manifest`].
#[derive(Clone, Debug)]
pub struct Config {
    /// Human-readable title displayed in the TUI header.
    pub title: String,
    /// Ordered list of node processes managed by the runner.
    pub nodes: Vec<NodeSpec>,
}

/// Specification for a single node process managed by narae.
#[derive(Clone, Debug)]
pub struct NodeSpec {
    /// Display name shown in the TUI sidebar.
    pub name: String,
    /// Executable path or name (passed to `Command::new`).
    pub command: String,
    /// Arguments passed to the command.
    pub args: Vec<String>,
    /// Working directory for the process. If `None`, the workspace root is used.
    pub cwd: Option<String>,
    /// Environment variables set for the process.
    pub env: Vec<EnvVar>,
}

/// An environment variable key-value pair for a node process.
#[derive(Clone, Debug)]
pub struct EnvVar {
    /// The environment variable name.
    pub key: String,
    /// The environment variable value.
    pub value: String,
}

/// Errors that can occur when loading a narae configuration.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The manifest file could not be loaded or parsed.
    #[error("failed to load manifest: {0}")]
    Manifest(#[from] nunchi_coins_chain::testnet::Error),
}

impl Config {
    /// Parse a `narae.toml` manifest from `path` and construct a [`Config`].
    ///
    /// The `path` should point to a valid `narae.toml` file. Relative executable
    /// and config paths declared inside the manifest are resolved against the
    /// directory containing the manifest file.
    pub fn read_manifest(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let manifest = LocalTestnetManifest::read(path)?;
        Ok(Self::from_manifest(manifest, path.parent()))
    }

    /// Build a [`Config`] from an already-parsed [`LocalTestnetManifest`].
    ///
    /// `manifest_dir` is used to resolve relative executable and config paths
    /// declared inside the manifest. Pass `None` to keep relative paths as-is.
    pub fn from_manifest(manifest: LocalTestnetManifest, manifest_dir: Option<&Path>) -> Self {
        let executable = resolve_manifest_path(manifest.executable_path, manifest_dir);
        let nodes = manifest
            .nodes
            .into_iter()
            .map(|node| NodeSpec {
                name: node.name,
                command: executable.display().to_string(),
                args: vec![
                    "--config".to_string(),
                    resolve_manifest_path(node.config_path, manifest_dir)
                        .display()
                        .to_string(),
                ],
                cwd: None,
                env: vec![EnvVar {
                    key: "RUST_LOG".to_string(),
                    // Let the operator turn the node log level knob from outside.
                    value: std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
                }],
            })
            .collect();
        Self {
            title: format!("{} local testnet", manifest.chain),
            nodes,
        }
    }
}

fn resolve_manifest_path(path: PathBuf, manifest_dir: Option<&Path>) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    manifest_dir.map_or(path.clone(), |dir| dir.join(path))
}
