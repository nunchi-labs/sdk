use clap::Args;
use nunchi_coins_chain::testnet::{
    generate_local_testnet, LocalTestnetConfig, LocalTestnetManifest,
};
use std::path::{Path, PathBuf};

const DEFAULT_BASE_METRICS_PORT: u16 = 9_090;

#[derive(Debug, Args)]
pub struct Generate {
    #[arg(long, default_value_t = 4)]
    pub validators: u32,
    #[arg(long, default_value = "testnet")]
    pub out: PathBuf,
    #[arg(long, default_value_t = 30_000)]
    pub base_port: u16,
    #[arg(long, default_value_t = 8_545)]
    pub base_rpc_port: u16,
    #[arg(long, default_value_t = DEFAULT_BASE_METRICS_PORT)]
    pub base_metrics_port: u16,
    #[arg(long, default_value_t = 0)]
    pub seed: u64,
}

impl Generate {
    pub fn local(
        validators: u32,
        out: PathBuf,
        base_port: u16,
        base_rpc_port: u16,
        base_metrics_port: u16,
        seed: u64,
    ) -> Self {
        Self {
            validators,
            out,
            base_port,
            base_rpc_port,
            base_metrics_port,
            seed,
        }
    }

    pub fn run(self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let manifest_path = manifest_path(&self.out);
        let mut manifest = generate_local_testnet(LocalTestnetConfig {
            validators: self.validators,
            base_port: self.base_port,
            base_rpc_port: self.base_rpc_port,
            base_metrics_port: self.base_metrics_port,
            base_data_dir: self.out,
            seed: self.seed,
        })?;
        manifest.executable_path = coins_chain_executable();
        manifest.write(&manifest_path)?;
        Ok(manifest_path)
    }
}

pub fn manifest_path(dir: &Path) -> PathBuf {
    dir.join(LocalTestnetManifest::FILE_NAME)
}

fn coins_chain_executable() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("coins-chain-node")))
        .unwrap_or_else(|| PathBuf::from("coins-chain-node"))
}
