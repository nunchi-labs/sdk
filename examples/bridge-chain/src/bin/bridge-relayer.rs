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
    let mut left_to_right = None;
    let mut right_to_left = None;
    loop {
        relay_one("left", "right", &left, &right, &mut left_to_right).await;
        relay_one("right", "left", &right, &left, &mut right_to_left).await;
        tokio::time::sleep(interval).await;
    }
}

/// Last source/destination pair that was accepted or already known.
///
/// A rejected submission is not recorded, and a destination restart (accepted
/// certificate disappears) does not match this cursor, so the same finalization
/// is submitted again.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RelayCursor {
    source: String,
    destination: Option<String>,
}

fn should_relay(cursor: Option<&RelayCursor>, source: &str, destination: Option<&str>) -> bool {
    if destination == Some(source) {
        return false;
    }
    match cursor {
        Some(cursor) => cursor.source != source || cursor.destination.as_deref() != destination,
        None => true,
    }
}

fn cursor_after_submit(
    source: &str,
    destination: Option<&str>,
    result: &str,
) -> Option<RelayCursor> {
    if result == "updated" || result == "stale" {
        Some(RelayCursor {
            source: source.to_string(),
            destination: destination.map(str::to_string),
        })
    } else {
        None
    }
}

async fn relay_one(
    from_name: &str,
    to_name: &str,
    from: &HttpClient,
    to: &HttpClient,
    cursor: &mut Option<RelayCursor>,
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
    let accepted = match to
        .request::<Option<String>, _>("bridge.latestAccepted", rpc_params![])
        .await
    {
        Ok(accepted) => accepted,
        Err(error) => {
            warn!(to = to_name, error = %error, "failed to fetch accepted finalization");
            return;
        }
    };
    if !should_relay(cursor.as_ref(), &finalization, accepted.as_deref()) {
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
                "submitted finalization"
            );
            if let Some(next) =
                cursor_after_submit(&finalization, accepted.as_deref(), &response.result)
            {
                *cursor = Some(next);
            } else {
                warn!(
                    from = from_name,
                    to = to_name,
                    result = %response.result,
                    "destination rejected finalization; will retry"
                );
            }
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

#[cfg(test)]
mod tests {
    use super::{cursor_after_submit, should_relay, RelayCursor};

    #[test]
    fn rejected_submission_is_retried_and_restart_resubmits() {
        let source = "aa";
        assert!(should_relay(None, source, None));

        assert_eq!(cursor_after_submit(source, None, "rejected"), None);
        assert!(should_relay(None, source, None));

        let remembered = cursor_after_submit(source, Some("bb"), "stale").unwrap();
        assert!(!should_relay(Some(&remembered), source, Some("bb")));
        assert!(should_relay(Some(&remembered), source, None));

        let updated = cursor_after_submit(source, None, "updated").unwrap();
        assert_eq!(
            updated,
            RelayCursor {
                source: source.to_string(),
                destination: None,
            }
        );
        assert!(!should_relay(Some(&updated), source, Some(source)));
    }
}
