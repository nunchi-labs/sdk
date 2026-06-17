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

use clap::Parser;
use rmcp::transport::io::stdio;
use rmcp::ServiceExt as _;
use tracing_subscriber::{fmt, EnvFilter};

/// CLI arguments.
#[derive(Debug, Parser)]
#[command(
    name = "nunchi-mcp",
    about = "MCP server for the Nunchi SDK – exposes chain queries and transaction submission as AI tools"
)]
struct Cli {
    /// HTTP(S) URL of the Nunchi node's JSON-RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:9090")]
    rpc_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Log to stderr so stdout stays clean for the MCP stdio transport.
    fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();
    let rpc_client = client::RpcClient::new(cli.rpc_url);
    let mcp_server = server::NunchiServer::new(rpc_client);

    let service = mcp_server.serve(stdio()).await?;

    service.waiting().await?;
    Ok(())
}
