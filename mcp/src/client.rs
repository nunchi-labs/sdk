//! Thin JSON-RPC client that talks to a running Nunchi node.
//!
//! We use a plain `reqwest` HTTP client rather than pulling in `jsonrpsee` as a
//! dependency, keeping the MCP crate's dependency footprint small.  All methods
//! are async and return `anyhow::Result` so callers can surface errors as MCP
//! tool errors.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A bare-minimum JSON-RPC 2.0 request envelope.
#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    params: Value,
    id: u64,
}

/// A bare-minimum JSON-RPC 2.0 response envelope.
#[derive(Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Deserialize, Debug)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

/// A lightweight async JSON-RPC client.
#[derive(Clone, Debug)]
pub struct RpcClient {
    url: String,
    http: reqwest::Client,
}

impl RpcClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Invoke `method` with named params (`params` is a JSON object or `null`).
    pub async fn call(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let body = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id: 1,
        };

        let resp: JsonRpcResponse = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.error {
            let detail = err.data.map(|d| format!(" – {d}")).unwrap_or_default();
            anyhow::bail!("JSON-RPC error {}: {}{}", err.code, err.message, detail);
        }

        resp.result
            .ok_or_else(|| anyhow::anyhow!("JSON-RPC response has neither result nor error"))
    }
}
