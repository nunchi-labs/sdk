use clap::Parser;
use commonware_codec::DecodeExt;
use commonware_formatting::from_hex;
use nunchi_coins_chain::Identity;
use nunchi_coins_indexer::{Api, Indexer};
use std::{num::NonZeroU32, path::PathBuf, sync::Arc};
use tracing::info;

#[derive(Debug, Parser)]
#[command(about = "Run a coins-chain indexer server")]
struct Cli {
    #[arg(long, default_value_t = 8080)]
    port: u16,
    #[arg(long, help = "Hex-encoded BLS12-381 threshold public key")]
    identity: String,
    #[arg(long, help = "Number of consensus participants")]
    participants: NonZeroU32,
    #[arg(long, help = "Directory containing built frontend assets")]
    frontend_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let identity_bytes = from_hex(&cli.identity).ok_or("invalid identity hex")?;
    let identity = Identity::decode(identity_bytes.as_ref()).map_err(|_| "invalid identity")?;
    let indexer = Arc::new(Indexer::new(identity, cli.participants));
    let app = Api::new(indexer).router_with_frontend(cli.frontend_dir.clone());

    let addr = format!("0.0.0.0:{}", cli.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!(
        %addr,
        participants = %cli.participants,
        frontend_dir = ?cli.frontend_dir,
        "started coins-chain indexer"
    );
    axum::serve(listener, app).await?;
    Ok(())
}
