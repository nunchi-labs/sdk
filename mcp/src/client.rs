//! Thin JSON-RPC client that talks to a running Nunchi node.
//!
//! We use a plain `reqwest` HTTP client rather than pulling in `jsonrpsee` as a
//! dependency, keeping the MCP crate's dependency footprint small.  All methods
//! are async and return `anyhow::Result` so callers can surface errors as MCP
//! tool errors.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
        Self::with_timeouts(url, CONNECT_TIMEOUT, REQUEST_TIMEOUT)
    }

    pub fn with_timeouts(
        url: impl Into<String>,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .build()
            .expect("valid JSON-RPC HTTP client configuration");
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

        let response = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|error| anyhow::anyhow!(error_chain(&error)))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| anyhow::anyhow!(error_chain(&error)))?;
        if !status.is_success() {
            if let Ok(parsed) = serde_json::from_slice::<JsonRpcResponse>(&bytes) {
                if let Some(err) = parsed.error {
                    return Err(rpc_error(err));
                }
            }
            anyhow::bail!("HTTP {status}: {}", body_snippet(&bytes));
        }

        let resp: JsonRpcResponse = serde_json::from_slice(&bytes)
            .map_err(|err| anyhow::anyhow!("invalid JSON-RPC response (HTTP {status}): {err}"))?;

        if let Some(err) = resp.error {
            return Err(rpc_error(err));
        }

        resp.result
            .ok_or_else(|| anyhow::anyhow!("JSON-RPC response has neither result nor error"))
    }
}

fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    for _ in 0..8 {
        let Some(cause) = source else {
            break;
        };
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

fn rpc_error(err: JsonRpcError) -> anyhow::Error {
    let detail = err.data.map(|d| format!(" – {d}")).unwrap_or_default();
    anyhow::anyhow!("JSON-RPC error {}: {}{}", err.code, err.message, detail)
}

fn body_snippet(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut snippet = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index == 512 {
            snippet.push_str("...");
            break;
        }
        snippet.push(ch);
    }
    snippet
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_response(status: &str, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_string();
        let body = body.to_string();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        });
        format!("http://{address}/")
    }

    #[tokio::test]
    async fn http_error_includes_status_and_body() {
        let url = spawn_response("404 Not Found", "missing method").await;
        let client = RpcClient::new(url);
        let error = client
            .call("chain.status", Value::Null)
            .await
            .expect_err("404 is an error");
        let message = error.to_string();
        assert!(message.contains("404"), "{message}");
        assert!(message.contains("missing method"), "{message}");
    }

    #[tokio::test]
    async fn http_error_with_jsonrpc_body_reports_the_rpc_error() {
        let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Module error","data":"the pool is full"}}"#;
        let url = spawn_response("500 Internal Server Error", body).await;
        let client = RpcClient::new(url);
        let error = client
            .call("coins.submit_transaction", Value::Null)
            .await
            .expect_err("rpc error");
        let message = error.to_string();
        assert!(message.contains("-32000"), "{message}");
        assert!(message.contains("the pool is full"), "{message}");
        assert!(!message.contains("invalid JSON-RPC"), "{message}");
    }

    #[tokio::test]
    async fn success_returns_result() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"applied_height":7}}"#;
        let url = spawn_response("200 OK", body).await;
        let client = RpcClient::new(url);
        let value = client.call("chain.status", Value::Null).await.unwrap();
        assert_eq!(value["applied_height"], 7);
    }

    #[tokio::test]
    async fn call_times_out_when_the_peer_never_responds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let client = RpcClient::with_timeouts(
            format!("http://{address}/"),
            Duration::from_millis(50),
            Duration::from_millis(200),
        );
        let error = client
            .call("chain.status", Value::Null)
            .await
            .expect_err("hung peer should time out");
        let message = error.to_string().to_ascii_lowercase();
        assert!(message.contains("operation timed out"), "{message}");
    }
}
