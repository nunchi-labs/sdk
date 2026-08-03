use clap::Parser;
use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::types::Epoch;
use commonware_formatting::from_hex;
use nunchi_coins_chain::{Identity, MAX_SUPPORTED_MODE};
use nunchi_coins_indexer::{load_dkg_output, Api, DkgOutput, Indexer};
use std::{num::NonZeroU32, path::PathBuf, sync::Arc};
use tracing::info;

#[derive(Debug, Parser)]
#[command(about = "Run a coins-chain indexer server")]
struct Cli {
    #[arg(long, default_value_t = 8080)]
    port: u16,
    #[arg(long, help = "Hex-encoded initial DKG output")]
    output: Option<String>,
    #[arg(long, default_value_t = 0, help = "Consensus epoch for --output")]
    output_epoch: u64,
    #[arg(long, help = "Hex-encoded BLS12-381 threshold public key")]
    identity: Option<String>,
    #[arg(long, help = "Number of consensus participants")]
    participants: NonZeroU32,
    #[arg(long, help = "Directory containing built frontend assets")]
    frontend_dir: Option<PathBuf>,
    #[arg(long, help = "Directory for persisted indexer verifier state")]
    dkg_output_state_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let persisted_output = match cli.dkg_output_state_dir.as_deref() {
        Some(path) => load_dkg_output(path, cli.participants)?,
        None => None,
    };
    let mut indexer = match persisted_output {
        Some((epoch, output)) => Indexer::new_from_output_at(epoch, output, cli.participants),
        None => match optional_arg(cli.output) {
            Some(output) => {
                let output_bytes = from_hex(&output).ok_or("invalid output hex")?;
                let output = DkgOutput::decode_cfg(
                    output_bytes.as_ref(),
                    &(cli.participants, MAX_SUPPORTED_MODE),
                )
                .map_err(|_| "invalid output")?;
                Indexer::new_from_output_at(Epoch::new(cli.output_epoch), output, cli.participants)
            }
            None => {
                let identity =
                    optional_arg(cli.identity).ok_or("identity or output is required")?;
                let identity_bytes = from_hex(&identity).ok_or("invalid identity hex")?;
                let identity =
                    Identity::decode(identity_bytes.as_ref()).map_err(|_| "invalid identity")?;
                Indexer::new(identity, cli.participants)
            }
        },
    };
    if let Some(path) = cli.dkg_output_state_dir.clone() {
        indexer = indexer.with_dkg_output_state_dir(path);
    }
    let indexer = Arc::new(indexer);
    let app = Api::new(indexer).router_with_frontend(cli.frontend_dir.clone());

    let addr = format!("0.0.0.0:{}", cli.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!(
        %addr,
        participants = %cli.participants,
        frontend_dir = ?cli.frontend_dir,
        dkg_output_state_dir = ?cli.dkg_output_state_dir,
        "started coins-chain indexer"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

fn optional_arg(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}
