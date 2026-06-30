use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(about = "Run a standalone coins-chain validator node")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    nunchi_coins_chain::testnet::run_node(cli.config)?;
    Ok(())
}
