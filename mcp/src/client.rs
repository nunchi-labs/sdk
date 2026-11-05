//! Thin JSON-RPC client that talks to a running Nunchi node.
//!
//! We use a plain `reqwest` HTTP client rather than pulling in `jsonrpsee` as a
//! dependency, keeping the MCP crate's dependency footprint small.  All methods
//! are async and return `anyhow::Result` so callers can surface errors as MCP
//! tool errors.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
        Self::with_timeout(url, CONNECT_TIMEOUT, REQUEST_TIMEOUT)
    }

    pub fn with_timeout(
        url: impl Into<String>,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .build()
            .expect("valid MCP HTTP client configuration");
        Self {
            url: url.into(),
            http,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn call_times_out_when_the_peer_accepts_and_never_responds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buffer).await;
                std::future::pending::<()>().await;
            }
        });

        let client = RpcClient::with_timeout(
            format!("http://{address}"),
            Duration::from_millis(200),
            Duration::from_millis(200),
        );
        let started = std::time::Instant::now();
        let error = client
            .call("coins.nonce", serde_json::json!({}))
            .await
            .expect_err("hung peer should time out");
        assert!(started.elapsed() < Duration::from_secs(2), "{error}");
        let timed_out = error
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_timeout)
            || error.to_string().to_lowercase().contains("timed out");
        assert!(timed_out, "{error}");
    }
}
