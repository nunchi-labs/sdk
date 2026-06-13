use nunchi_coins_chain::testnet::LocalTestnetManifest;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Config {
    pub title: String,
    pub nodes: Vec<NodeSpec>,
}

#[derive(Clone, Debug)]
pub struct NodeSpec {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<EnvVar>,
}

#[derive(Clone, Debug)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to load manifest: {0}")]
    Manifest(#[from] nunchi_coins_chain::testnet::Error),
}

impl Config {
    pub fn read_manifest(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let manifest = LocalTestnetManifest::read(path)?;
        Ok(Self::from_manifest(manifest, path.parent()))
    }

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
