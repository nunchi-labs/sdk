//! Thin JSON-RPC client that talks to a running Nunchi node.
//!
//! We use a plain `reqwest` HTTP client rather than pulling in `jsonrpsee` as a
//! dependency, keeping the MCP crate's dependency footprint small.  All methods
//! are async and return `anyhow::Result` so callers can surface errors as MCP
//! tool errors.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

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
    id: u64,
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
    next_id: Arc<AtomicU64>,
}

impl RpcClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            http: reqwest::Client::new(),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Invoke `method` with named params (`params` is a JSON object or `null`).
    pub async fn call(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };

        let resp: JsonRpcResponse = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if resp.id != id {
            anyhow::bail!(
                "JSON-RPC response ID {} does not match request ID {id}",
                resp.id
            );
        }

        if let Some(err) = resp.error {
            let detail = err.data.map(|d| format!(" – {d}")).unwrap_or_default();
            anyhow::bail!("JSON-RPC error {}: {}{}", err.code, err.message, detail);
        }

        resp.result
            .ok_or_else(|| anyhow::anyhow!("JSON-RPC response has neither result nor error"))
    }
}

#[cfg(test)]
mod tests {
    use super::RpcClient;
    use std::sync::atomic::Ordering;

    #[test]
    fn request_ids_are_shared_between_clones() {
        let client = RpcClient::new("http://127.0.0.1:8545");
        let clone = client.clone();

        assert_eq!(client.next_id.fetch_add(1, Ordering::Relaxed), 1);
        assert_eq!(clone.next_id.fetch_add(1, Ordering::Relaxed), 2);
    }
}
