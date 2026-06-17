//! MCP server handler: exposes Nunchi JSON-RPC methods as AI tools.
//!
//! Each tool corresponds to one method on a running Nunchi node.  Inputs and
//! outputs are plain strings / hex blobs, matching the node's wire format, so
//! an AI assistant can use them without any additional encoding knowledge.

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    tool, tool_handler, tool_router, ServerHandler,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::client::RpcClient;

// ── parameter structs ─────────────────────────────────────────────────────────

/// Parameters for `coins_nonce`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct NonceParams {
    /// Hex-encoded account address (32 bytes, no 0x prefix required).
    pub account: String,
}

/// Parameters for `coins_token`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct TokenParams {
    /// Hex-encoded coin identifier (32 bytes, no 0x prefix required).
    pub coin: String,
}

/// Parameters for `coins_balance`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BalanceParams {
    /// Hex-encoded account address.
    pub account: String,
    /// Hex-encoded coin identifier.
    pub coin: String,
}

/// Parameters for `coins_submit_transaction`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SubmitTransactionParams {
    /// Hex-encoded, fully-signed transaction bytes.
    pub transaction: String,
}

/// Parameters for `coins_transaction_status`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct TransactionStatusParams {
    /// Hex-encoded transaction hash returned by `coins_submit_transaction`.
    pub hash: String,
}

// ── server ────────────────────────────────────────────────────────────────────

/// MCP server that proxies requests to a Nunchi node.
#[derive(Clone)]
#[allow(dead_code)]
pub struct NunchiServer {
    rpc: RpcClient,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl NunchiServer {
    pub fn new(rpc: RpcClient) -> Self {
        Self {
            rpc,
            tool_router: Self::tool_router(),
        }
    }

    /// Query the current nonce (sequence number) of an account.
    ///
    /// The nonce must be included in the next transaction submitted by this account.
    /// Returns a JSON object with `account` (hex) and `nonce` (u64).
    #[tool(
        name = "coins_nonce",
        description = "Query the current nonce of an account on the Nunchi chain. \
                        Returns the next expected nonce to use in a transaction."
    )]
    async fn coins_nonce(&self, Parameters(p): Parameters<NonceParams>) -> String {
        match self
            .rpc
            .call("coins.nonce", json!({ "account": p.account }))
            .await
        {
            Ok(v) => v.to_string(),
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Look up a token registered in the Nunchi coin ledger.
    ///
    /// Returns full metadata: symbol, name, decimals, issuer, total supply, and optional max supply.
    /// Returns `null` if no token exists for the given coin ID.
    #[tool(
        name = "coins_token",
        description = "Look up a token registered in the Nunchi coin ledger by its hex coin ID. \
                        Returns symbol, name, decimals, issuer, total_supply, and max_supply."
    )]
    async fn coins_token(&self, Parameters(p): Parameters<TokenParams>) -> String {
        match self
            .rpc
            .call("coins.token", json!({ "coin": p.coin }))
            .await
        {
            Ok(v) => v.to_string(),
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Query the token balance of an account.
    ///
    /// Returns a JSON object with `account` (hex), `coin` (hex), and `amount` (string u128).
    #[tool(
        name = "coins_balance",
        description = "Query how many units of a specific coin an account holds. \
                        Returns the amount as a decimal string (u128)."
    )]
    async fn coins_balance(&self, Parameters(p): Parameters<BalanceParams>) -> String {
        match self
            .rpc
            .call(
                "coins.balance",
                json!({ "account": p.account, "coin": p.coin }),
            )
            .await
        {
            Ok(v) => v.to_string(),
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Fetch the current authenticated state root of the coin ledger.
    ///
    /// The state root is a SHA-256 hash over all coin balances and accounts.
    /// It can be used to verify the integrity of query responses.
    #[tool(
        name = "coins_state_root",
        description = "Fetch the current authenticated state root (SHA-256 hex) of the Nunchi coin ledger."
    )]
    async fn coins_state_root(&self) -> String {
        match self.rpc.call("coins.state_root", json!(null)).await {
            Ok(v) => v.to_string(),
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Submit a signed transaction to the node's mempool.
    ///
    /// The transaction must be hex-encoded bytes produced by the Nunchi SDK's
    /// `Transaction::sign` function.  On success returns the transaction hash.
    #[tool(
        name = "coins_submit_transaction",
        description = "Submit a signed Nunchi coin transaction to the node's mempool. \
                        Provide hex-encoded transaction bytes. \
                        Returns the transaction hash on success."
    )]
    async fn coins_submit_transaction(
        &self,
        Parameters(p): Parameters<SubmitTransactionParams>,
    ) -> String {
        match self
            .rpc
            .call(
                "coins.submit_transaction",
                json!({ "transaction": p.transaction }),
            )
            .await
        {
            Ok(v) => v.to_string(),
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Check the mempool status of a previously submitted transaction.
    ///
    /// Returns one of: `pending`, `finalized` (with block height), `dropped` (with reason),
    /// or `unknown` (evicted from the pool or never seen).
    #[tool(
        name = "coins_transaction_status",
        description = "Check the mempool status of a Nunchi coin transaction by its hash. \
                        Status is one of: pending, finalized (includes height), dropped (includes reason), unknown."
    )]
    async fn coins_transaction_status(
        &self,
        Parameters(p): Parameters<TransactionStatusParams>,
    ) -> String {
        match self
            .rpc
            .call(
                "coins.transaction_status",
                json!({ "hash": p.hash }),
            )
            .await
        {
            Ok(v) => v.to_string(),
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Get the current height and state root of the chain.
    ///
    /// Returns `applied_height` (u64) – the last finalized block – and `state_root` (hex).
    #[tool(
        name = "chain_status",
        description = "Get the current applied block height and state root of the Nunchi chain."
    )]
    async fn chain_status(&self) -> String {
        match self.rpc.call("chain.status", json!(null)).await {
            Ok(v) => v.to_string(),
            Err(e) => format!("Error: {e}"),
        }
    }
}

#[tool_handler(
    name = "nunchi-mcp",
    version = "2026.5.0",
    instructions = "This server exposes a running Nunchi blockchain node as a set of tools. \
                    All addresses and coin IDs are lowercase hex strings (32 bytes = 64 hex chars). \
                    All amounts are decimal strings representing u128 integers. \
                    Call chain_status first to confirm the node is reachable."
)]
impl ServerHandler for NunchiServer {}
