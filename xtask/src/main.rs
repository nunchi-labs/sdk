use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(about = "Run workspace automation tasks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate local testnet node configs.
    Generate {
        #[command(subcommand)]
        chain: ChainCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ChainCommand {
    /// Generate a coins-chain local validator set.
    CoinsChain(nunchi_xtask::coins_chain::Generate),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Generate { chain } => {
            let manifest_path = generate(chain)?;
            println!("{}", manifest_path.display());
        }
    }
    Ok(())
}

fn generate(chain: ChainCommand) -> Result<PathBuf, Box<dyn std::error::Error>> {
    match chain {
        ChainCommand::CoinsChain(generate) => generate.run(),
    }
}
