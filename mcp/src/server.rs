//! MCP server handler: exposes Nunchi JSON-RPC methods and SDK utilities as AI tools.
//!
//! Tools fall into three groups:
//! * **Chain tools** – proxy a live Nunchi node's JSON-RPC surface (prefix `coins_` / `chain_`).
//! * **SDK tools** – offline operations that require no running node (prefix `sdk_`):
//!   address derivation, coin-ID derivation, and transaction building/signing.
//! * **Repo tools** – browse the Nunchi SDK source code (prefix `repo_`):
//!   list files, read file contents, and search for patterns across the codebase.
//!
//! All addresses, coin IDs, public keys, private keys, and transactions are passed as lowercase
//! hex strings produced by the SDK's `commonware_codec::Encode` wire format.

use std::path::{Path, PathBuf};

use commonware_codec::{DecodeExt, Encode};
use commonware_formatting::{from_hex, hex};
use nunchi_coins::{
    external_account_id, multisig_account_id, CoinId, CoinOperation, CoinSpec, MultisigPolicy,
    PrivateKey, TokenFactory, TokenName, TokenSymbol, Transaction,
};
use nunchi_crypto::PublicKey;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    tool, tool_handler, tool_router, ServerHandler,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use walkdir::WalkDir;

use crate::client::RpcClient;

// ── hex helpers ───────────────────────────────────────────────────────────────

fn decode_value<T: commonware_codec::Read<Cfg = ()>>(
    hex_str: &str,
    type_name: &str,
) -> anyhow::Result<T> {
    let bytes = from_hex(hex_str).ok_or_else(|| anyhow::anyhow!("{type_name} is not valid hex"))?;
    T::decode(bytes.as_ref()).map_err(|e| anyhow::anyhow!("invalid {type_name}: {e}"))
}

fn encode_value<T: Encode>(value: &T) -> String {
    hex(value.encode().as_ref())
}

// ── parameter structs — chain tools ──────────────────────────────────────────

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

// ── parameter structs — SDK offline tools ────────────────────────────────────

/// Parameters for `sdk_derive_address`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DeriveAddressParams {
    /// Hex-encoded curve-tagged public key bytes (curve tag byte + key bytes,
    /// as produced by `PrivateKey::public_key().encode()`).
    pub public_key_hex: String,
}

/// Parameters for `sdk_derive_multisig_address`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DeriveMultisigAddressParams {
    /// Minimum number of signers required to authorize a transaction.
    pub threshold: u16,
    /// Hex-encoded curve-tagged public keys for all policy members.
    pub public_keys_hex: Vec<String>,
}

/// Parameters for `sdk_derive_coin_id`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DeriveCoinIdParams {
    /// Hex-encoded issuer account address (32 bytes).
    pub issuer: String,
    /// Chain-wide factory nonce (use `coins_factory_nonce`, not the issuer account nonce).
    pub nonce: u64,
    /// Token ticker symbol (≤ 32 bytes, UTF-8).
    pub symbol: String,
    /// Full token name (≤ 128 bytes, UTF-8).
    pub name: String,
    /// Number of decimal places.
    pub decimals: u8,
    /// Initial minted supply, as a decimal u128 string.
    pub initial_supply: String,
    /// Optional hard cap on total supply, as a decimal u128 string.  Omit for uncapped tokens.
    pub max_supply: Option<String>,
}

/// Parameters for `sdk_build_transfer`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BuildTransferParams {
    /// Hex-encoded curve-tagged private key bytes.
    pub private_key_hex: String,
    /// Sender's current nonce (from `coins_nonce`).
    pub nonce: u64,
    /// Hex-encoded coin ID.
    pub coin: String,
    /// Hex-encoded sender account address.
    pub from: String,
    /// Hex-encoded recipient account address.
    pub to: String,
    /// Amount to transfer, as a decimal u128 string.
    pub amount: String,
}

/// Parameters for `sdk_build_mint`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BuildMintParams {
    /// Hex-encoded curve-tagged private key bytes (must be the token issuer's key).
    pub private_key_hex: String,
    /// Issuer's current nonce (from `coins_nonce`).
    pub nonce: u64,
    /// Hex-encoded coin ID to mint.
    pub coin: String,
    /// Hex-encoded recipient account address.
    pub to: String,
    /// Amount to mint, as a decimal u128 string.
    pub amount: String,
}

/// Parameters for `sdk_build_burn`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BuildBurnParams {
    /// Hex-encoded curve-tagged private key bytes.
    pub private_key_hex: String,
    /// Account's current nonce (from `coins_nonce`).
    pub nonce: u64,
    /// Hex-encoded coin ID to burn.
    pub coin: String,
    /// Hex-encoded source account address.
    pub from: String,
    /// Amount to burn, as a decimal u128 string.
    pub amount: String,
}

/// Parameters for `sdk_build_create_token`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BuildCreateTokenParams {
    /// Hex-encoded curve-tagged private key bytes (will become the token issuer).
    pub private_key_hex: String,
    /// Issuer's current nonce (from `coins_nonce`).
    pub nonce: u64,
    /// Token ticker symbol (≤ 32 bytes, UTF-8).
    pub symbol: String,
    /// Full token name (≤ 128 bytes, UTF-8).
    pub name: String,
    /// Number of decimal places (e.g. 9 for nano-unit precision).
    pub decimals: u8,
    /// Initial minted supply, as a decimal u128 string.
    pub initial_supply: String,
    /// Optional hard cap on total supply, as a decimal u128 string.
    pub max_supply: Option<String>,
}

/// Parameters for `sdk_build_register_account_policy`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct BuildRegisterAccountPolicyParams {
    /// Hex-encoded curve-tagged private key bytes of the transaction signer.
    pub private_key_hex: String,
    /// Multisig account nonce (from `coins_nonce` on the derived account). Zero before registration.
    pub nonce: u64,
    /// Hex-encoded address derived from the policy being registered.
    pub account_id: String,
    /// Minimum threshold of signers required. This tool can sign only a threshold of 1.
    pub threshold: u16,
    /// Hex-encoded curve-tagged public keys of all policy members.
    pub signer_public_keys_hex: Vec<String>,
}

// ── parameter structs — repo tools ────────────────────────────────────────────

/// Parameters for `repo_list_files`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RepoListFilesParams {
    /// Sub-path within the repository to list.  Use `""` or `"."` for the root.
    pub path: Option<String>,
}

/// Parameters for `repo_read_file`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RepoReadFileParams {
    /// Path to the file, relative to the repository root (e.g. `"coins/src/lib.rs"`).
    pub path: String,
}

/// Parameters for `repo_search_code`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RepoSearchCodeParams {
    /// String pattern to search for (plain substring match, case-sensitive by default).
    pub pattern: String,
    /// Limit search to a sub-path within the repository.  Use `""` or `"."` for all files.
    pub path: Option<String>,
    /// When `true`, performs a case-insensitive match. Defaults to `false`.
    pub case_insensitive: Option<bool>,
}

// ── server ────────────────────────────────────────────────────────────────────

/// MCP server exposing the Nunchi SDK's chain RPC, offline SDK utilities, and repo source code.
#[derive(Clone)]
#[allow(dead_code)]
pub struct NunchiServer {
    rpc: RpcClient,
    repo_path: PathBuf,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl NunchiServer {
    pub fn new(rpc: RpcClient, repo_path: PathBuf) -> Self {
        Self {
            rpc,
            repo_path,
            tool_router: Self::tool_router(),
        }
    }

    // ── chain RPC tools ───────────────────────────────────────────────────────

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
        match account_query_param(&p.account) {
            Ok(account) => {
                self.rpc_call("coins.nonce", json!({ "account": account }))
                    .await
            }
            Err(error) => format!("Error: {error}"),
        }
    }

    /// Query the token factory nonce used to derive the next coin id.
    ///
    /// This is a chain-wide counter, not an account nonce. `sdk_derive_coin_id` must use this
    /// value. Returns a JSON object with `nonce` (u64).
    #[tool(
        name = "coins_factory_nonce",
        description = "Query the chain-wide token factory nonce. \
                        Use this value as the nonce argument to sdk_derive_coin_id. \
                        It is not the issuer account nonce from coins_nonce."
    )]
    async fn coins_factory_nonce(&self) -> String {
        self.rpc_call("coins.factory_nonce", json!([])).await
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
        self.rpc_call("coins.token", json!({ "coin": p.coin }))
            .await
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
        match account_query_param(&p.account) {
            Ok(account) => {
                self.rpc_call(
                    "coins.balance",
                    json!({ "account": account, "coin": p.coin }),
                )
                .await
            }
            Err(error) => format!("Error: {error}"),
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
        self.rpc_call("coins.state_root", json!([])).await
    }

    /// Submit a signed transaction to the node's mempool.
    ///
    /// The transaction must be hex-encoded bytes produced by one of the `sdk_build_*` tools
    /// or the Nunchi SDK's `Transaction::sign` function.  On success returns the transaction hash.
    #[tool(
        name = "coins_submit_transaction",
        description = "Submit a signed Nunchi coin transaction to the node's mempool. \
                        Provide hex-encoded transaction bytes (e.g. from sdk_build_transfer). \
                        Returns the transaction hash on success."
    )]
    async fn coins_submit_transaction(
        &self,
        Parameters(p): Parameters<SubmitTransactionParams>,
    ) -> String {
        self.rpc_call(
            "coins.submit_transaction",
            json!({ "transaction": p.transaction }),
        )
        .await
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
        self.rpc_call("coins.transaction_status", json!({ "hash": p.hash }))
            .await
    }

    /// Get the current height and state root of the chain.
    ///
    /// Returns `applied_height` (u64) – the last finalized block – and `state_root` (hex).
    #[tool(
        name = "chain_status",
        description = "Get the current applied block height and state root of the Nunchi chain."
    )]
    async fn chain_status(&self) -> String {
        self.rpc_call("chain.status", json!([])).await
    }

    // ── SDK offline tools ─────────────────────────────────────────────────────

    /// Derive the Nunchi account address for an external (single-signer) account.
    ///
    /// The address is deterministically derived from the public key and is stable across
    /// key rotations only for external accounts.  For multisig accounts use
    /// `sdk_derive_multisig_address`.
    #[tool(
        name = "sdk_derive_address",
        description = "Derive the Nunchi account address from a curve-tagged public key hex. \
                        Works offline – no node required. \
                        Returns the 32-byte (64 hex char) account address."
    )]
    async fn sdk_derive_address(&self, Parameters(p): Parameters<DeriveAddressParams>) -> String {
        match decode_value::<PublicKey>(&p.public_key_hex, "public key") {
            Ok(pk) => encode_value(&external_account_id(&pk)),
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Derive the bootstrap address of a multisig account from its initial policy.
    ///
    /// The address is the hash of the canonical policy. A different policy is a different
    /// account. The coin ledger rejects a registration whose account id is not that hash.
    #[tool(
        name = "sdk_derive_multisig_address",
        description = "Derive the Nunchi multisig account address from a threshold and list of \
                        curve-tagged public key hex strings. \
                        Works offline – no node required. \
                        Returns the 32-byte (64 hex char) account address."
    )]
    async fn sdk_derive_multisig_address(
        &self,
        Parameters(p): Parameters<DeriveMultisigAddressParams>,
    ) -> String {
        match build_multisig_policy(p.threshold, &p.public_keys_hex) {
            Ok(policy) => encode_value(&multisig_account_id(&policy)),
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Compute the deterministic coin ID that the Nunchi ledger will assign to a new token.
    ///
    /// Use `coins_factory_nonce` for `nonce`. The coin id is derived from the issuer address,
    /// the chain-wide factory nonce, and the token spec. An account nonce will not match the
    /// id the ledger assigns.
    #[tool(
        name = "sdk_derive_coin_id",
        description = "Compute the deterministic coin ID (64 hex chars) that the Nunchi ledger \
                        will assign to a new token created by a given issuer at a given nonce. \
                        Works offline – no node required."
    )]
    async fn sdk_derive_coin_id(&self, Parameters(p): Parameters<DeriveCoinIdParams>) -> String {
        match build_coin_spec_from_params(
            &p.symbol,
            &p.name,
            p.decimals,
            &p.initial_supply,
            p.max_supply.as_deref(),
        ) {
            Ok(spec) => match decode_value::<nunchi_coins::Address>(&p.issuer, "issuer address") {
                Ok(issuer) => encode_value(&TokenFactory::derive_coin_id(&issuer, p.nonce, &spec)),
                Err(e) => format!("Error: {e}"),
            },
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Build and sign a coin Transfer transaction.
    ///
    /// Returns hex-encoded transaction bytes ready to pass to `coins_submit_transaction`.
    /// The private key must control the `from` address.
    #[tool(
        name = "sdk_build_transfer",
        description = "Build and sign a Nunchi coin Transfer transaction offline. \
                        Returns hex-encoded transaction bytes to submit via coins_submit_transaction."
    )]
    async fn sdk_build_transfer(&self, Parameters(p): Parameters<BuildTransferParams>) -> String {
        match (|| -> anyhow::Result<String> {
            let signer = decode_value::<PrivateKey>(&p.private_key_hex, "private key")?;
            let coin = decode_value::<CoinId>(&p.coin, "coin id")?;
            let from = decode_value::<nunchi_coins::Address>(&p.from, "from address")?;
            let to = decode_value::<nunchi_coins::Address>(&p.to, "to address")?;
            let amount = p
                .amount
                .parse::<u128>()
                .map_err(|_| anyhow::anyhow!("amount is not a valid u128"))?;
            ensure_external_signer(&signer, &from, "from address")?;
            let tx = Transaction::sign(
                &signer,
                p.nonce,
                CoinOperation::Transfer {
                    coin,
                    from,
                    to,
                    amount,
                },
            );
            Ok(encode_value(&tx))
        })() {
            Ok(hex) => hex,
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Build and sign a coin Mint transaction.
    ///
    /// Only the token issuer's key can mint new supply.
    /// Returns hex-encoded transaction bytes ready to pass to `coins_submit_transaction`.
    #[tool(
        name = "sdk_build_mint",
        description = "Build and sign a Nunchi coin Mint transaction offline (issuer only). \
                        Returns hex-encoded transaction bytes to submit via coins_submit_transaction."
    )]
    async fn sdk_build_mint(&self, Parameters(p): Parameters<BuildMintParams>) -> String {
        match (|| -> anyhow::Result<String> {
            let signer = decode_value::<PrivateKey>(&p.private_key_hex, "private key")?;
            let coin = decode_value::<CoinId>(&p.coin, "coin id")?;
            let to = decode_value::<nunchi_coins::Address>(&p.to, "to address")?;
            let amount = p
                .amount
                .parse::<u128>()
                .map_err(|_| anyhow::anyhow!("amount is not a valid u128"))?;
            let tx = Transaction::sign(&signer, p.nonce, CoinOperation::Mint { coin, to, amount });
            Ok(encode_value(&tx))
        })() {
            Ok(hex) => hex,
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Build and sign a coin Burn transaction.
    ///
    /// Returns hex-encoded transaction bytes ready to pass to `coins_submit_transaction`.
    #[tool(
        name = "sdk_build_burn",
        description = "Build and sign a Nunchi coin Burn transaction offline. \
                        Destroys the specified amount of coins from the `from` account. \
                        Returns hex-encoded transaction bytes to submit via coins_submit_transaction."
    )]
    async fn sdk_build_burn(&self, Parameters(p): Parameters<BuildBurnParams>) -> String {
        match (|| -> anyhow::Result<String> {
            let signer = decode_value::<PrivateKey>(&p.private_key_hex, "private key")?;
            let coin = decode_value::<CoinId>(&p.coin, "coin id")?;
            let from = decode_value::<nunchi_coins::Address>(&p.from, "from address")?;
            let amount = p
                .amount
                .parse::<u128>()
                .map_err(|_| anyhow::anyhow!("amount is not a valid u128"))?;
            ensure_external_signer(&signer, &from, "from address")?;
            let tx =
                Transaction::sign(&signer, p.nonce, CoinOperation::Burn { coin, from, amount });
            Ok(encode_value(&tx))
        })() {
            Ok(hex) => hex,
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Build and sign a CreateToken transaction.
    ///
    /// Creates a new token in the Nunchi coin ledger.  The signer becomes the token issuer
    /// and the only account authorized to mint additional supply.
    /// Returns hex-encoded transaction bytes ready to pass to `coins_submit_transaction`.
    #[tool(
        name = "sdk_build_create_token",
        description = "Build and sign a Nunchi CreateToken transaction offline. \
                        Creates a new token with the given symbol, name, decimals, and supply policy. \
                        The signing key becomes the token issuer. \
                        Returns hex-encoded transaction bytes to submit via coins_submit_transaction."
    )]
    async fn sdk_build_create_token(
        &self,
        Parameters(p): Parameters<BuildCreateTokenParams>,
    ) -> String {
        match (|| -> anyhow::Result<String> {
            let signer = decode_value::<PrivateKey>(&p.private_key_hex, "private key")?;
            let spec = build_coin_spec_from_params(
                &p.symbol,
                &p.name,
                p.decimals,
                &p.initial_supply,
                p.max_supply.as_deref(),
            )?;
            let tx = Transaction::sign(&signer, p.nonce, CoinOperation::CreateToken { spec });
            Ok(encode_value(&tx))
        })() {
            Ok(hex) => hex,
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Build and sign a RegisterAccountPolicy transaction.
    ///
    /// Registers the multisig policy whose derived address is `account_id`. The coin ledger
    /// rejects a policy that does not hash to that account, and it rejects single-key
    /// authorization. The signer must be a member and the threshold must be 1, because this
    /// tool holds a single key. `nonce` is that multisig account's nonce.
    /// Returns hex-encoded transaction bytes ready to pass to `coins_submit_transaction`.
    #[tool(
        name = "sdk_build_register_account_policy",
        description = "Build and sign a Nunchi RegisterAccountPolicy transaction offline. \
                        Registers the initial threshold-1 multisig policy for account_id. \
                        account_id must be the address derived from that policy. \
                        Returns hex-encoded transaction bytes to submit via coins_submit_transaction."
    )]
    async fn sdk_build_register_account_policy(
        &self,
        Parameters(p): Parameters<BuildRegisterAccountPolicyParams>,
    ) -> String {
        match build_register_account_policy(
            &p.private_key_hex,
            p.nonce,
            &p.account_id,
            p.threshold,
            &p.signer_public_keys_hex,
        ) {
            Ok(tx) => encode_value(&tx),
            Err(e) => format!("Error: {e}"),
        }
    }

    // ── repo source-code tools ────────────────────────────────────────────────

    /// List all source files in the repository (or a sub-directory).
    ///
    /// Hidden directories (`.git`, `.github`) and build artifacts (`target/`) are
    /// automatically excluded.  Returns a newline-separated list of paths relative
    /// to the repository root.
    #[tool(
        name = "repo_list_files",
        description = "List source files in the Nunchi SDK repository. \
                        Supply an optional sub-path to narrow the listing. \
                        Returns newline-separated relative paths. \
                        Hidden directories and build artifacts are excluded."
    )]
    async fn repo_list_files(&self, Parameters(p): Parameters<RepoListFilesParams>) -> String {
        let sub = p.path.as_deref().unwrap_or(".");
        match list_repo_files(&self.repo_path, sub) {
            Ok(files) => files.join("\n"),
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Read the full content of a file in the repository.
    ///
    /// The path must be relative to the repository root (e.g. `"coins/src/lib.rs"`).
    /// Files larger than 256 KiB are truncated with a notice appended.
    #[tool(
        name = "repo_read_file",
        description = "Read the source code of a file in the Nunchi SDK repository. \
                        Provide the path relative to the repository root (e.g. coins/src/lib.rs). \
                        Files larger than 256 KiB are truncated."
    )]
    async fn repo_read_file(&self, Parameters(p): Parameters<RepoReadFileParams>) -> String {
        match read_repo_file(&self.repo_path, &p.path) {
            Ok(content) => content,
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Search for a plain-text pattern across source files in the repository.
    ///
    /// Returns matching lines in `path:line_number: content` format, capped at 200 matches.
    /// Supply an optional sub-path to restrict the search to a directory.
    #[tool(
        name = "repo_search_code",
        description = "Search for a text pattern in the Nunchi SDK source code. \
                        Returns matching lines as `path:line: content`. \
                        Optionally restrict to a sub-path and toggle case sensitivity. \
                        Results are capped at 200 matches."
    )]
    async fn repo_search_code(&self, Parameters(p): Parameters<RepoSearchCodeParams>) -> String {
        let sub = p.path.as_deref().unwrap_or(".");
        let case_insensitive = p.case_insensitive.unwrap_or(false);
        match search_repo_code(&self.repo_path, sub, &p.pattern, case_insensitive) {
            Ok(matches) => {
                if matches.is_empty() {
                    "No matches found.".to_string()
                } else {
                    matches.join("\n")
                }
            }
            Err(e) => format!("Error: {e}"),
        }
    }

    // ── private helpers ───────────────────────────────────────────────────────

    async fn rpc_call(&self, method: &str, params: Value) -> String {
        match self.rpc.call(method, params).await {
            Ok(value) => normalize_rpc_result(method, value).to_string(),
            Err(e) => format!("Error: {e}"),
        }
    }
}

// ── free helpers ──────────────────────────────────────────────────────────────

fn build_multisig_policy(
    threshold: u16,
    public_keys_hex: &[String],
) -> anyhow::Result<MultisigPolicy> {
    let keys: Vec<PublicKey> = public_keys_hex
        .iter()
        .enumerate()
        .map(|(i, hex_str)| decode_value::<PublicKey>(hex_str, &format!("public_key[{i}]")))
        .collect::<anyhow::Result<_>>()?;
    MultisigPolicy::new(threshold, keys).map_err(|e| anyhow::anyhow!("invalid policy: {e}"))
}

/// JSON-RPC account parameters are Bech32. MCP callers pass the hex wire encoding.
fn account_query_param(account_hex: &str) -> anyhow::Result<String> {
    Ok(decode_value::<nunchi_coins::Address>(account_hex, "account address")?.to_bech32())
}

fn ensure_external_signer(
    signer: &PrivateKey,
    account: &nunchi_coins::Address,
    label: &str,
) -> anyhow::Result<()> {
    if &external_account_id(&signer.public_key()) != account {
        anyhow::bail!("{label} does not match the signing key");
    }
    Ok(())
}

fn build_register_account_policy(
    private_key_hex: &str,
    nonce: u64,
    account_id_hex: &str,
    threshold: u16,
    signer_public_keys_hex: &[String],
) -> anyhow::Result<Transaction> {
    let signer = decode_value::<PrivateKey>(private_key_hex, "private key")?;
    let account_id = decode_value::<nunchi_coins::Address>(account_id_hex, "account_id")?;
    let policy = build_multisig_policy(threshold, signer_public_keys_hex)?;
    let derived = multisig_account_id(&policy);
    if account_id != derived {
        anyhow::bail!("account_id does not match the address derived from this policy");
    }
    if threshold != 1 {
        anyhow::bail!("a single signing key can only register a threshold-1 policy");
    }
    if !policy.contains(&signer.public_key()) {
        anyhow::bail!("signing key is not a member of the policy");
    }
    let tx = Transaction::sign_multisig(
        account_id,
        policy.clone(),
        &[&signer],
        nonce,
        CoinOperation::RegisterAccountPolicy {
            account_id: derived,
            policy,
        },
    );
    tx.verify()
        .map_err(|error| anyhow::anyhow!("registration transaction is not valid: {error}"))?;
    Ok(tx)
}

fn rewrite_bech32_field(value: &mut Value, field: &str) {
    let Some(text) = value.get(field).and_then(Value::as_str).map(str::to_owned) else {
        return;
    };
    if let Ok(address) = nunchi_coins::Address::from_bech32(&text) {
        value[field] = Value::String(encode_value(&address));
    }
}

/// Node query responses use Bech32 account strings. MCP callers stay on hex wire encoding.
fn normalize_rpc_result(method: &str, mut value: Value) -> Value {
    match method {
        "coins.nonce" | "coins.balance" => rewrite_bech32_field(&mut value, "account"),
        "coins.token" => rewrite_bech32_field(&mut value, "issuer"),
        _ => {}
    }
    value
}

fn build_coin_spec_from_params(
    symbol: &str,
    name: &str,
    decimals: u8,
    initial_supply: &str,
    max_supply: Option<&str>,
) -> anyhow::Result<CoinSpec> {
    let symbol = TokenSymbol::new(symbol).map_err(|e| anyhow::anyhow!("invalid symbol: {e}"))?;
    let name = TokenName::new(name).map_err(|e| anyhow::anyhow!("invalid name: {e}"))?;
    let initial_supply = initial_supply
        .parse::<u128>()
        .map_err(|_| anyhow::anyhow!("initial_supply is not a valid u128"))?;
    let max_supply = max_supply
        .map(|s| {
            s.parse::<u128>()
                .map_err(|_| anyhow::anyhow!("max_supply is not a valid u128"))
        })
        .transpose()?;
    Ok(CoinSpec::new(
        symbol,
        name,
        decimals,
        initial_supply,
        max_supply,
    ))
}

#[tool_handler(
    name = "nunchi-mcp",
    version = "2026.9.0-alpha.1",
    instructions = "This server exposes the full Nunchi SDK as a set of tools. \
                    There are three groups: \
                    (1) Chain tools (prefix coins_ / chain_) that query a running node or submit transactions. \
                    (2) SDK tools (prefix sdk_) that work offline to build/sign transactions, \
                        derive account addresses, and compute token identifiers. \
                    (3) Repo tools (prefix repo_) that browse the Nunchi SDK source code: \
                        repo_list_files lists files, repo_read_file reads a file's content, \
                        repo_search_code searches for patterns across the codebase. \
                    All addresses and coin IDs are lowercase hex strings (32 bytes = 64 hex chars). \
                    Public and private keys are curve-tagged hex strings produced by the SDK Encode trait \
                    (first byte is the curve tag: 0x01 = Ed25519, 0x02 = Secp256r1). \
                    All amounts are decimal strings representing u128 integers. \
                    Typical workflow: sdk_derive_address → coins_nonce → sdk_build_* → coins_submit_transaction → coins_transaction_status. \
                    Account arguments to coins_nonce and coins_balance are hex-encoded addresses; the server translates them to the Bech32 form the node expects. \
                    Coin ids use coins_factory_nonce, not an account nonce. \
                    Call chain_status first to confirm the node is reachable."
)]
impl ServerHandler for NunchiServer {}

// ── repo helpers ──────────────────────────────────────────────────────────────

/// Directories excluded from all repo listing and search operations.
const EXCLUDED_DIRS: &[&str] = &[".git", ".github", "target"];

/// Maximum file size returned by `repo_read_file` (256 KiB).
const MAX_FILE_BYTES: u64 = 256 * 1024;

/// Maximum number of search hits returned by `repo_search_code`.
const MAX_SEARCH_HITS: usize = 200;

/// Resolve and validate a sub-path inside the repository root.
///
/// Returns an error if the resolved path would escape the repository root (path traversal guard).
fn resolve_repo_path(repo_root: &Path, sub: &str) -> anyhow::Result<PathBuf> {
    let sub = sub.trim_matches('/');
    let candidate = if sub.is_empty() || sub == "." {
        repo_root.to_path_buf()
    } else {
        repo_root.join(sub)
    };
    // Canonicalize to resolve `..` and symlinks, then verify it stays inside the root.
    let canonical_root = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    let canonical_candidate = candidate
        .canonicalize()
        .unwrap_or_else(|_| candidate.clone());
    if !canonical_candidate.starts_with(&canonical_root) {
        anyhow::bail!("path traversal denied: '{sub}' escapes the repository root");
    }
    Ok(candidate)
}

/// Returns `true` if any component of `path` is an excluded directory.
fn is_excluded(path: &Path) -> bool {
    path.components().any(|c| {
        EXCLUDED_DIRS
            .iter()
            .any(|ex| c.as_os_str() == std::ffi::OsStr::new(ex))
    })
}

fn list_repo_files(repo_root: &Path, sub: &str) -> anyhow::Result<Vec<String>> {
    let base = resolve_repo_path(repo_root, sub)?;
    let canonical_root = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());

    let mut files = Vec::new();
    for entry in WalkDir::new(&base)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            // Skip excluded directory names.
            !is_excluded(e.path())
        })
        .flatten()
    {
        if entry.file_type().is_file() {
            let rel = entry
                .path()
                .strip_prefix(&canonical_root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .into_owned();
            files.push(rel);
        }
    }
    files.sort();
    Ok(files)
}

fn read_repo_file(repo_root: &Path, rel_path: &str) -> anyhow::Result<String> {
    let full = resolve_repo_path(repo_root, rel_path)?;
    if !full.is_file() {
        anyhow::bail!("not a file: '{rel_path}'");
    }
    let meta = std::fs::metadata(&full)?;
    if meta.len() > MAX_FILE_BYTES {
        let mut content = std::fs::read_to_string(&full)?;
        content.truncate(MAX_FILE_BYTES as usize);
        content.push_str("\n\n[… truncated: file exceeds 256 KiB]");
        return Ok(content);
    }
    Ok(std::fs::read_to_string(&full)?)
}

fn search_repo_code(
    repo_root: &Path,
    sub: &str,
    pattern: &str,
    case_insensitive: bool,
) -> anyhow::Result<Vec<String>> {
    let base = resolve_repo_path(repo_root, sub)?;
    let canonical_root = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());

    let needle_lower = pattern.to_lowercase();
    let mut hits = Vec::new();

    'outer: for entry in WalkDir::new(&base)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_excluded(e.path()))
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        // Skip large files and binary-looking files (no UTF-8 extension check).
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(entry.path()) else {
            continue; // skip binary / unreadable files
        };

        let rel = entry
            .path()
            .strip_prefix(&canonical_root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .into_owned();

        for (line_num, line) in content.lines().enumerate() {
            let matched = if case_insensitive {
                line.to_lowercase().contains(&needle_lower)
            } else {
                line.contains(pattern)
            };
            if matched {
                hits.push(format!("{}:{}: {}", rel, line_num + 1, line));
                if hits.len() >= MAX_SEARCH_HITS {
                    hits.push(format!(
                        "[… results truncated at {MAX_SEARCH_HITS} matches]"
                    ));
                    break 'outer;
                }
            }
        }
    }
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nunchi_coins::Authorization;
    use rmcp::handler::server::wrapper::Parameters;

    fn key_hex(seed: u64) -> String {
        encode_value(&PrivateKey::ed25519_from_seed(seed))
    }

    fn pubkey_hex(seed: u64) -> String {
        encode_value(&PrivateKey::ed25519_from_seed(seed).public_key())
    }

    #[test]
    fn account_query_param_uses_bech32() {
        let address = external_account_id(&PrivateKey::ed25519_from_seed(4).public_key());
        let param = account_query_param(&encode_value(&address)).unwrap();
        assert_eq!(param, address.to_bech32());
        assert!(account_query_param(&param).is_err());
    }

    #[tokio::test]
    async fn coin_queries_fail_closed_for_bad_input_and_unreachable_nodes() {
        let server = NunchiServer::new(
            crate::client::RpcClient::new("http://127.0.0.1:9"),
            std::path::PathBuf::from("."),
        );
        let address = encode_value(&external_account_id(
            &PrivateKey::ed25519_from_seed(4).public_key(),
        ));

        let bad_nonce = server
            .coins_nonce(Parameters(NonceParams {
                account: "not-hex".to_string(),
            }))
            .await;
        assert!(bad_nonce.starts_with("Error:"), "{bad_nonce}");

        let offline_nonce = server
            .coins_nonce(Parameters(NonceParams {
                account: address.clone(),
            }))
            .await;
        assert!(offline_nonce.starts_with("Error:"), "{offline_nonce}");

        let bad_balance = server
            .coins_balance(Parameters(BalanceParams {
                account: "not-hex".to_string(),
                coin: address.clone(),
            }))
            .await;
        assert!(bad_balance.starts_with("Error:"), "{bad_balance}");

        let offline_balance = server
            .coins_balance(Parameters(BalanceParams {
                account: address,
                coin: "aa".repeat(32),
            }))
            .await;
        assert!(offline_balance.starts_with("Error:"), "{offline_balance}");

        let factory = server.coins_factory_nonce().await;
        assert!(factory.starts_with("Error:"), "{factory}");
        let root = server.coins_state_root().await;
        assert!(root.starts_with("Error:"), "{root}");
        let status = server.chain_status().await;
        assert!(status.starts_with("Error:"), "{status}");
    }

    #[test]
    fn normalize_rpc_result_rewrites_bech32_accounts_to_hex() {
        let address = external_account_id(&PrivateKey::ed25519_from_seed(4).public_key());
        let mut nonce = json!({ "account": address.to_bech32(), "nonce": 3 });
        nonce = normalize_rpc_result("coins.nonce", nonce);
        assert_eq!(nonce["account"], encode_value(&address));
        assert_eq!(nonce["nonce"], 3);

        let mut token = json!({ "issuer": address.to_bech32(), "symbol": "NCHI" });
        token = normalize_rpc_result("coins.token", token);
        assert_eq!(token["issuer"], encode_value(&address));
        assert_eq!(token["symbol"], "NCHI");

        let root = normalize_rpc_result("coins.state_root", json!({ "root": "ab" }));
        assert_eq!(root["root"], "ab");
    }

    #[test]
    fn register_account_policy_is_a_verifiable_threshold_one_multisig() {
        let signer = key_hex(7);
        let member = pubkey_hex(7);
        let other = pubkey_hex(8);
        let policy = build_multisig_policy(1, &[member.clone(), other.clone()]).unwrap();
        let account = encode_value(&multisig_account_id(&policy));

        let tx = build_register_account_policy(&signer, 0, &account, 1, &[member, other]).unwrap();
        assert!(matches!(tx.authorization, Authorization::Multisig { .. }));
        assert_eq!(tx.account_id, multisig_account_id(&policy));
        assert_eq!(tx.verify(), Ok(()));

        let wrong_account = encode_value(&external_account_id(
            &PrivateKey::ed25519_from_seed(7).public_key(),
        ));
        assert!(
            build_register_account_policy(&signer, 0, &wrong_account, 1, &[pubkey_hex(7)]).is_err()
        );
        assert!(build_register_account_policy(
            &signer,
            0,
            &encode_value(&multisig_account_id(
                &build_multisig_policy(2, &[pubkey_hex(7), pubkey_hex(8)]).unwrap()
            )),
            2,
            &[pubkey_hex(7), pubkey_hex(8)]
        )
        .is_err());
    }

    #[test]
    fn transfer_and_burn_reject_a_from_address_the_key_does_not_control() {
        let signer = PrivateKey::ed25519_from_seed(1);
        let other = external_account_id(&PrivateKey::ed25519_from_seed(2).public_key());
        let own = external_account_id(&signer.public_key());
        assert!(ensure_external_signer(&signer, &other, "from address").is_err());
        assert!(ensure_external_signer(&signer, &own, "from address").is_ok());
    }
}
