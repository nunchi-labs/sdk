use clap::{Parser, Subcommand};
use narae::Config;
use nunchi_coins_chain::testnet::{
    generate_local_testnet, LocalTestnetConfig, LocalTestnetManifest,
};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
};

const DEFAULT_BASE_METRICS_PORT: u16 = 9_090;

#[derive(Debug, Parser)]
#[command(about = "Generate and run local testnets in a ratatui dashboard")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate local testnet node configs and a narae manifest.
    Generate {
        #[command(subcommand)]
        chain: ChainCommand,
    },
    /// Run nodes from a generated manifest directory.
    Run {
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
    /// Generate configs and immediately run the local testnet.
    Up {
        #[command(subcommand)]
        chain: ChainCommand,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Generate { chain } => {
            let manifest_path = generate(chain)?;
            println!("{}", manifest_path.display());
        }
        Command::Run { dir } => {
            let manifest_path = manifest_path(&dir);
            let config = Config::read_manifest(&manifest_path)?;
            ensure_executables(&config)?;
            narae::run(config, std::env::current_dir()?)?;
        }
        Command::Up { chain } => {
            let manifest_path = generate(chain)?;
            let config = Config::read_manifest(&manifest_path)?;
            ensure_executables(&config)?;
            narae::run(config, std::env::current_dir()?)?;
        }
    }
    Ok(())
}

/// Fail fast with a build hint instead of opening a dashboard full of spawn errors.
fn ensure_executables(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    for node in &config.nodes {
        let command = Path::new(&node.command);
        if command.is_absolute() && !command.exists() {
            return Err(format!(
                "node executable not found: {} (build it with `cargo build -p nunchi-coins-chain --bin coins-chain-node`)",
                command.display()
            )
            .into());
        }
    }
    Ok(())
}

#[derive(Debug, Subcommand)]
enum ChainCommand {
    /// Generate a coins-chain local validator set.
    CoinsChain {
        #[arg(long, default_value_t = 4)]
        validators: u32,
        #[arg(long, default_value = "testnet")]
        out: PathBuf,
        #[arg(long, default_value_t = 30_000)]
        base_port: u16,
        #[arg(long, default_value_t = 8_545)]
        base_rpc_port: u16,
        #[arg(long, default_value_t = DEFAULT_BASE_METRICS_PORT)]
        base_metrics_port: u16,
        #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
        bind_ip: IpAddr,
        #[arg(long)]
        public_host: Vec<IpAddr>,
        #[arg(long)]
        storage_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        seed: u64,
    },
}

fn generate(chain: ChainCommand) -> Result<PathBuf, Box<dyn std::error::Error>> {
    match chain {
        ChainCommand::CoinsChain {
            validators,
            out,
            base_port,
            base_rpc_port,
            base_metrics_port,
            bind_ip,
            public_host,
            storage_dir,
            seed,
        } => {
            let manifest_path = manifest_path(&out);
            let mut manifest = generate_local_testnet(LocalTestnetConfig {
                validators,
                base_port,
                base_rpc_port,
                base_metrics_port,
                base_data_dir: out,
                bind_ip,
                public_ips: (!public_host.is_empty()).then_some(public_host),
                storage_dir,
                seed,
            })?;
            manifest.executable_path = coins_chain_executable();
            manifest.write(&manifest_path)?;
            Ok(manifest_path)
        }
    }
}

fn manifest_path(dir: &Path) -> PathBuf {
    dir.join(LocalTestnetManifest::FILE_NAME)
}

fn coins_chain_executable() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("coins-chain-node")))
        .unwrap_or_else(|| PathBuf::from("coins-chain-node"))
}
