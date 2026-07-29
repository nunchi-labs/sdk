//! MCP server that bridges AI assistants to a running Nunchi node's JSON-RPC surface.
//!
//! Start this binary pointing at any node URL; it speaks the Model Context Protocol over
//! stdio so that any MCP-compatible AI client (Claude Desktop, VS Code Copilot, …) can
//! query chain state and submit transactions without writing raw JSON-RPC calls.
//!
//! # Usage
//!
//! ```text
//! nunchi-mcp --rpc-url http://127.0.0.1:9090
//! ```

mod client;
mod server;

use std::path::PathBuf;

use clap::Parser;
use rmcp::transport::io::stdio;
use rmcp::ServiceExt as _;
use tracing_subscriber::{fmt, EnvFilter};

/// CLI arguments.
#[derive(Debug, Parser)]
#[command(
    name = "nunchi-mcp",
    about = "MCP server for the Nunchi SDK – exposes chain queries, transaction submission, \
             and repository source-code browsing as AI tools"
)]
struct Cli {
    /// HTTP(S) URL of the Nunchi node's JSON-RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:9090")]
    rpc_url: String,

    /// Path to the root of the Nunchi SDK repository.
    /// When set, the server exposes `repo_list_files`, `repo_read_file`, and
    /// `repo_search_code` tools that let AI clients browse source code.
    /// Must be provided explicitly; repo tools are disabled if omitted.
    #[arg(long)]
    repo_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Log to stderr so stdout stays clean for the MCP stdio transport.
    fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let repo_path = cli.repo_path.map(|p| match p.canonicalize() {
        Ok(canonical) => canonical,
        Err(e) => {
            tracing::warn!(
                path = %p.display(),
                error = %e,
                "could not canonicalize --repo-path; using as-is"
            );
            p
        }
    });
    if repo_path.is_none() {
        tracing::info!("--repo-path not set; repo_list_files, repo_read_file, and repo_search_code tools are disabled");
    }
    let rpc_client = client::RpcClient::new(cli.rpc_url);
    let mcp_server = server::NunchiServer::new(rpc_client, repo_path);

    let service = mcp_server.serve(stdio()).await?;

    service.waiting().await?;
    Ok(())
}
