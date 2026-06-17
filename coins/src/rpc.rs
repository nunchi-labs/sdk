//! JSON-RPC surface for the coin module.

use std::sync::Arc;

use commonware_cryptography::sha256::Digest;
use futures::lock::Mutex as AsyncMutex;
use jsonrpsee::{
    core::{async_trait, RegisterMethodError, RpcResult},
    proc_macros::rpc,
};
use nunchi_rpc::{decode_hex, encode_hex, module_error, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::{Address, CoinDB, CoinId, Ledger, LedgerError, TokenDefinition};
use nunchi_common::CommitState;

/// Read-only coin state required by the coin RPC server.
#[async_trait]
pub trait CoinQuery: Clone + Send + Sync + 'static {
    async fn nonce(&self, account: Address) -> Result<u64, LedgerError>;

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
            account: encode_hex(&account),
            nonce,
        })
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
            account: encode_hex(&account),
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
/// TODO(@distractedm1nd): Transaction submission is intentionally not registered here while the example chain owns the
/// transaction ingress. Once mempool ownership moves into the coin module, `coins.submit_transaction`
/// can be added to `Coins` and implemented on [`CoinsRpc`].
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
    decode_hex(value, "account")
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
            issuer: encode_hex(&token.issuer),
            symbol: token.symbol,
            name: token.name,
            decimals: token.decimals,
            total_supply: token.total_supply.to_string(),
            max_supply: token.max_supply.map(|supply| supply.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use commonware_cryptography::{Hasher, Sha256};
    use commonware_runtime::Runner as _;

    use super::*;
    use crate::{external_account_id, CoinSpec, PrivateKey, TokenFactory};

    #[derive(Clone)]
    struct MockQuery {
        inner: Arc<MockState>,
    }

    struct MockState {
        account: Address,
        coin: CoinId,
        token: TokenDefinition,
    }

    impl MockQuery {
        fn new() -> Self {
            let account = external_account_id(&PrivateKey::ed25519_from_seed(1).public_key());
            let spec = CoinSpec::new("GOLD", "Gold", 9, 1_000, Some(2_000));
            let coin = TokenFactory::derive_coin_id(&account, 0, &spec);
            let token = TokenDefinition::from_spec(coin, account.clone(), spec);
            Self {
                inner: Arc::new(MockState {
                    account,
                    coin,
                    token,
                }),
            }
        }
    }

    #[async_trait]
    impl CoinQuery for MockQuery {
        async fn nonce(&self, account: Address) -> Result<u64, LedgerError> {
            assert_eq!(account, self.inner.account);
            Ok(7)
        }

        async fn token(&self, coin: CoinId) -> Result<Option<TokenDefinition>, LedgerError> {
            assert_eq!(coin, self.inner.coin);
            Ok(Some(self.inner.token.clone()))
        }

        async fn balance(&self, account: Address, coin: CoinId) -> Result<u128, LedgerError> {
            assert_eq!(account, self.inner.account);
            assert_eq!(coin, self.inner.coin);
            Ok(42)
        }

        async fn state_root(&self) -> Result<Digest, LedgerError> {
            Ok(Sha256::hash(b"root"))
        }
    }

    #[test]
    fn coin_rpc_queries() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let query = MockQuery::new();
            let mut router = RpcRouter::new(());
            register(&mut router, CoinsRpc::new(query.clone())).expect("register coin RPC");
            let module = router.into_module();
            let account = encode_hex(&query.inner.account);
            let coin = encode_hex(&query.inner.coin);

            let mut nonce_params = jsonrpsee::core::params::ObjectParams::new();
            nonce_params
                .insert("account", account.clone())
                .expect("serialize nonce params");
            let nonce: NonceResponse = module
                .call("coins.nonce", nonce_params)
                .await
                .expect("nonce response");
            assert_eq!(nonce.nonce, 7);

            let mut token_params = jsonrpsee::core::params::ObjectParams::new();
            token_params
                .insert("coin", coin.clone())
                .expect("serialize token params");
            let token: Option<TokenResponse> = module
                .call("coins.token", token_params)
                .await
                .expect("token response");
            assert_eq!(token.unwrap().symbol, "GOLD");

            let mut balance_params = jsonrpsee::core::params::ObjectParams::new();
            balance_params
                .insert("account", account)
                .expect("serialize balance account param");
            balance_params
                .insert("coin", coin)
                .expect("serialize balance coin param");
            let balance: BalanceResponse = module
                .call("coins.balance", balance_params)
                .await
                .expect("balance response");
            assert_eq!(balance.amount, "42");

            let root: RootResponse = module
                .call(
                    "coins.state_root",
                    jsonrpsee::core::EmptyServerParams::new(),
                )
                .await
                .expect("root response");
            assert_eq!(root.root, encode_hex(&Sha256::hash(b"root")));
        });
    }
}
