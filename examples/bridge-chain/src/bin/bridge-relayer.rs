use clap::Parser;
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use nunchi_bridge_chain::rpc::{SubmitFinalizationParams, SubmitFinalizationResponse};
use std::time::Duration;
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(about = "Relay finalized bridge-chain certificates between two chains")]
struct Cli {
    #[arg(long)]
    left: String,
    #[arg(long)]
    right: String,
    #[arg(long, default_value_t = 500)]
    interval_ms: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    let cli = Cli::parse();
    let left = HttpClientBuilder::default().build(&cli.left)?;
    let right = HttpClientBuilder::default().build(&cli.right)?;
    let interval = Duration::from_millis(cli.interval_ms);
    run(left, right, interval).await
}

async fn run(
    left: HttpClient,
    right: HttpClient,
    interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_left = None::<String>;
    let mut last_right = None::<String>;
    loop {
        relay_one("left", "right", &left, &right, &mut last_left).await;
        relay_one("right", "left", &right, &left, &mut last_right).await;
        tokio::time::sleep(interval).await;
    }
}

async fn relay_one(
    from_name: &str,
    to_name: &str,
    from: &HttpClient,
    to: &HttpClient,
    last: &mut Option<String>,
) {
    let latest = match from
        .request::<Option<String>, _>("bridge.latestFinalization", rpc_params![])
        .await
    {
        Ok(latest) => latest,
        Err(error) => {
            warn!(from = from_name, error = %error, "failed to fetch latest finalization");
            return;
        }
    };
    let Some(finalization) = latest else {
        return;
    };
    if last.as_ref() == Some(&finalization) {
        return;
    }

    let params = SubmitFinalizationParams {
        finalization: finalization.clone(),
    };
    match to
        .request::<SubmitFinalizationResponse, _>("bridge.submitFinalization", rpc_params![params])
        .await
    {
        Ok(response) => {
            info!(
                from = from_name,
                to = to_name,
                result = %response.result,
                accepted_view = ?response.accepted_view,
                "relayed finalization"
            );
            *last = Some(finalization);
        }
        Err(error) => {
            warn!(
                from = from_name,
                to = to_name,
                error = %error,
                "failed to submit finalization"
            );
        }
    }
}
