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
                    value: "info".to_string(),
                }],
            })
            .collect();
        Self {
            title: format!("{} local testnet", manifest.chain),
            nodes,
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.nodes.is_empty() {
            return Err(ValidationError::NoNodes);
        }
        for node in &self.nodes {
            if node.name.trim().is_empty() {
                return Err(ValidationError::EmptyNodeName);
            }
            if node.command.trim().is_empty() {
                return Err(ValidationError::EmptyCommand {
                    node: node.name.clone(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("config must contain at least one node")]
    NoNodes,
    #[error("node names cannot be empty")]
    EmptyNodeName,
    #[error("node {node:?} has an empty command")]
    EmptyCommand { node: String },
}

fn resolve_manifest_path(path: PathBuf, manifest_dir: Option<&Path>) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    manifest_dir.map_or(path.clone(), |dir| dir.join(path))
}
