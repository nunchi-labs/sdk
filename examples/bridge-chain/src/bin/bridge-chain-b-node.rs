use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(about = "Run one chain-b bridge-chain validator")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    let cli = Cli::parse();
    nunchi_bridge_chain::testnet::run_chain_b_node(cli.config)?;
    Ok(())
}
