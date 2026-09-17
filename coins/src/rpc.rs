//! JSON-RPC surface for the coin module.

#[cfg(feature = "mempool")]
mod mempool;
#[cfg(feature = "mempool")]
pub use mempool::{
    register_mempool, CoinMempoolServer, CoinsMempoolRpc, MempoolIngress, SubmitTransactionParams,
    SubmitTransactionResponse, SubmitTransactionResult, SubmitTransactionsParams,
    SubmitTransactionsResponse, TransactionStatusResponse,
};

use std::sync::Arc;

use commonware_cryptography::sha256::Digest;
use futures::lock::Mutex as AsyncMutex;
use jsonrpsee::{
    core::{async_trait, RegisterMethodError, RpcResult},
    proc_macros::rpc,
};
use nunchi_rpc::{decode_hex, encode_hex, invalid_params, module_error, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::{Address, CoinDB, CoinId, Ledger, LedgerError, TokenDefinition};
use nunchi_common::CommitState;

/// Read-only coin state required by the coin RPC server.
#[async_trait]
pub trait CoinQuery: Clone + Send + Sync + 'static {
    async fn nonce(&self, account: Address) -> Result<u64, LedgerError>;

    async fn factory_nonce(&self) -> Result<u64, LedgerError>;

    async fn token(&self, coin: CoinId) -> Result<Option<TokenDefinition>, LedgerError>;

    async fn balance(&self, account: Address, coin: CoinId) -> Result<u128, LedgerError>;

    async fn state_root(&self) -> Result<Digest, LedgerError>;
}

/// Shared committed coin ledger handle suitable for RPC query servers.
pub struct SharedLedger<D> {
    ledger: Arc<AsyncMutex<Ledger<D>>>,
}

impl<D> SharedLedger<D> {
    pub fn new(ledger: Ledger<D>) -> Self {
        Self {
            ledger: Arc::new(AsyncMutex::new(ledger)),
        }
    }

    pub async fn lock(&self) -> futures::lock::MutexGuard<'_, Ledger<D>> {
        self.ledger.lock().await
    }
}

impl<D> Clone for SharedLedger<D> {
    fn clone(&self) -> Self {
        Self {
            ledger: self.ledger.clone(),
        }
    }
}

#[async_trait]
impl<D> CoinQuery for SharedLedger<D>
where
    D: CoinDB + CommitState + Send + Sync + 'static,
{
    async fn nonce(&self, account: Address) -> Result<u64, LedgerError> {
        self.lock().await.nonce(&account).await
    }

    async fn factory_nonce(&self) -> Result<u64, LedgerError> {
        self.lock().await.factory_nonce().await
    }

    async fn token(&self, coin: CoinId) -> Result<Option<TokenDefinition>, LedgerError> {
        self.lock().await.token(&coin).await
    }

    async fn balance(&self, account: Address, coin: CoinId) -> Result<u128, LedgerError> {
        self.lock().await.balance(&account, &coin).await
    }

    async fn state_root(&self) -> Result<Digest, LedgerError> {
        Ok(self.lock().await.root())
    }
}

/// Concrete coin RPC server over a query backend.
#[derive(Clone)]
pub struct CoinsRpc<Q> {
    query: Q,
}

impl<Q> CoinsRpc<Q> {
    pub fn new(query: Q) -> Self {
        Self { query }
    }
}

#[rpc(server, namespace = "coins", namespace_separator = ".")]
pub trait Coins {
    #[method(name = "nonce", param_kind = map)]
    async fn nonce(&self, account: String) -> RpcResult<NonceResponse>;

    #[method(name = "factory_nonce")]
    async fn factory_nonce(&self) -> RpcResult<FactoryNonceResponse>;

    #[method(name = "token", param_kind = map)]
    async fn token(&self, coin: String) -> RpcResult<Option<TokenResponse>>;

    #[method(name = "balance", param_kind = map)]
    async fn balance(&self, account: String, coin: String) -> RpcResult<BalanceResponse>;

    #[method(name = "state_root")]
    async fn state_root(&self) -> RpcResult<RootResponse>;
}

#[async_trait]
impl<Q> CoinsServer for CoinsRpc<Q>
where
    Q: CoinQuery,
{
    async fn nonce(&self, account: String) -> RpcResult<NonceResponse> {
        let account = decode_account(&account)?;
        let nonce = self.query.nonce(account.clone()).await.map_err(rpc_error)?;
        Ok(NonceResponse {
            account: account.to_bech32(),
            nonce,
        })
    }

    async fn factory_nonce(&self) -> RpcResult<FactoryNonceResponse> {
        let nonce = self.query.factory_nonce().await.map_err(rpc_error)?;
        Ok(FactoryNonceResponse { nonce })
    }

    async fn token(&self, coin: String) -> RpcResult<Option<TokenResponse>> {
        let coin = decode_coin(&coin)?;
        let token = self.query.token(coin).await.map_err(rpc_error)?;
        Ok(token.map(TokenResponse::from))
    }

    async fn balance(&self, account: String, coin: String) -> RpcResult<BalanceResponse> {
        let account = decode_account(&account)?;
        let coin = decode_coin(&coin)?;
        let amount = self
            .query
            .balance(account.clone(), coin)
            .await
            .map_err(rpc_error)?;
        Ok(BalanceResponse {
            account: account.to_bech32(),
            coin: encode_hex(&coin),
            amount: amount.to_string(),
        })
    }

    async fn state_root(&self) -> RpcResult<RootResponse> {
        let root = self.query.state_root().await.map_err(rpc_error)?;
        Ok(RootResponse {
            root: encode_hex(&root),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NonceResponse {
    pub account: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FactoryNonceResponse {
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenResponse {
    pub id: String,
    pub issuer: String,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub total_supply: String,
    pub max_supply: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BalanceResponse {
    pub account: String,
    pub coin: String,
    pub amount: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootResponse {
    pub root: String,
}

/// Register the coin module's query RPC methods into a downstream router.
///
/// Transaction submission lives in [`register_mempool`] (behind the `mempool`
/// feature) so chains without a pool can still serve queries.
pub fn register<Context, Q>(
    router: &mut RpcRouter<Context>,
    rpc: CoinsRpc<Q>,
) -> Result<(), RegisterMethodError>
where
    Q: CoinQuery,
{
    router.merge(rpc.into_rpc())
}

fn decode_account(value: &str) -> RpcResult<Address> {
    Address::from_bech32(value)
        .map_err(|err| invalid_params(format!("invalid account address: {err}")))
}

fn decode_coin(value: &str) -> RpcResult<CoinId> {
    decode_hex(value, "coin")
}

fn rpc_error(error: LedgerError) -> jsonrpsee::types::ErrorObjectOwned {
    module_error(error.to_string())
}

impl From<TokenDefinition> for TokenResponse {
    fn from(token: TokenDefinition) -> Self {
        Self {
            id: encode_hex(&token.id),
            issuer: token.issuer.to_bech32(),
            symbol: token.symbol.into(),
            name: token.name.into(),
            decimals: token.decimals,
            total_supply: token.total_supply.to_string(),
            max_supply: token.max_supply.map(|supply| supply.to_string()),
        }
    }
}
