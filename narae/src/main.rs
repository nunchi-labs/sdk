use clap::{Parser, Subcommand};
use narae::Config;
use std::{
    env,
    ffi::OsStr,
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
            let manifest_path = generate_local(chain)?;
            println!("{}", manifest_path.display());
        }
        Command::Run { dir } => {
            let manifest_path = manifest_path(&dir);
            let config = Config::read_manifest(&manifest_path)?;
            ensure_executables(&config)?;
            narae::run(config, std::env::current_dir()?)?;
        }
        Command::Up { chain } => {
            let manifest_path = generate_local(chain)?;
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
        if !command_exists(command, env::var_os("PATH").as_deref()) {
            return Err(format!(
                "node executable not found: {} (build it with `cargo build -p nunchi-coins-chain --bin coins-chain-node`)",
                command.display()
            )
            .into());
        }
    }
    Ok(())
}

fn command_exists(command: &Path, path: Option<&OsStr>) -> bool {
    if command.components().count() != 1 {
        return command.is_file();
    }

    path.into_iter()
        .flat_map(env::split_paths)
        .any(|directory| directory.join(command).is_file())
}

#[cfg(test)]
mod tests {
    use super::command_exists;
    use std::{
        ffi::OsString,
        fs,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn command_exists_searches_path_for_bare_command() {
        let directory = std::env::temp_dir().join(format!(
            "narae-command-exists-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time before Unix epoch")
                .as_nanos()
        ));
        fs::create_dir(&directory).expect("create temporary directory");
        let command = directory.join("coins-chain-node");
        fs::write(&command, []).expect("create command");

        assert!(command_exists(
            Path::new("coins-chain-node"),
            Some(OsString::from(&directory).as_os_str())
        ));

        fs::remove_dir_all(directory).expect("remove temporary directory");
    }

    #[test]
    fn command_exists_rejects_missing_bare_command() {
        assert!(!command_exists(Path::new("coins-chain-node"), None));
    }
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
        #[arg(long, default_value_t = 0)]
        seed: u64,
    },
}

fn generate_local(chain: ChainCommand) -> Result<PathBuf, Box<dyn std::error::Error>> {
    match chain {
        ChainCommand::CoinsChain {
            validators,
            out,
            base_port,
            base_rpc_port,
            base_metrics_port,
            seed,
        } => nunchi_xtask::coins_chain::Generate::local(
            validators,
            out,
            base_port,
            base_rpc_port,
            base_metrics_port,
            seed,
        )
        .run(),
    }
}

fn manifest_path(dir: &Path) -> PathBuf {
    nunchi_xtask::coins_chain::manifest_path(dir)
}
