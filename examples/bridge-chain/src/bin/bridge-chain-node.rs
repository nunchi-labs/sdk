use clap::Parser;
use nunchi_bridge_chain::testnet::{
    generate_bridge_pair, LocalBridgePairConfig, LocalBridgePairManifest,
};
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(about = "Generate a two-devnet bridge-chain demo")]
struct Cli {
    #[arg(long, default_value_t = 4)]
    validators: u32,
    #[arg(long, default_value = "bridge-demo")]
    out: PathBuf,
    #[arg(long, default_value_t = 30_000)]
    base_port_a: u16,
    #[arg(long, default_value_t = 8_545)]
    base_rpc_port_a: u16,
    #[arg(long, default_value_t = 31_000)]
    base_port_b: u16,
    #[arg(long, default_value_t = 9_545)]
    base_rpc_port_b: u16,
    #[arg(long, default_value_t = 0)]
    seed_a: u64,
    #[arg(long, default_value_t = 10_000)]
    seed_b: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    let cli = Cli::parse();
    let manifest = generate_bridge_pair(LocalBridgePairConfig {
        validators: cli.validators,
        base_port_a: cli.base_port_a,
        base_rpc_port_a: cli.base_rpc_port_a,
        base_port_b: cli.base_port_b,
        base_rpc_port_b: cli.base_rpc_port_b,
        base_data_dir: cli.out.clone(),
        seed_a: cli.seed_a,
        seed_b: cli.seed_b,
    })?;
    let manifest_path = cli.out.join(LocalBridgePairManifest::FILE_NAME);
    manifest.write(&manifest_path)?;
    println!("{}", manifest_path.display());
    Ok(())
}
