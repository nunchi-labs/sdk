use std::sync::Arc;

use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::Runner as _;
use nunchi_rpc::{encode_hex, RpcRouter};
use async_trait::async_trait;

use crate::{
    external_account_id, CoinId, CoinSpec, LedgerError, PrivateKey, TokenDefinition, TokenFactory,
    TokenName, TokenSymbol,
};

#[derive(Clone)]
struct MockQuery {
    inner: Arc<MockState>,
}

struct MockState {
    account: crate::Address,
    coin: CoinId,
    token: TokenDefinition,
}

impl MockQuery {
    fn new() -> Self {
        let account = external_account_id(&PrivateKey::ed25519_from_seed(1).public_key());
        let spec = CoinSpec::new(
            TokenSymbol::new("GOLD").expect("valid token symbol"),
            TokenName::new("Gold").expect("valid token name"),
            9,
            1_000,
            Some(2_000),
        );
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
impl crate::rpc::CoinQuery for MockQuery {
    async fn nonce(&self, account: crate::Address) -> Result<u64, LedgerError> {
        assert_eq!(account, self.inner.account);
        Ok(7)
    }

    async fn token(&self, coin: CoinId) -> Result<Option<TokenDefinition>, LedgerError> {
        assert_eq!(coin, self.inner.coin);
        Ok(Some(self.inner.token.clone()))
    }

    async fn balance(&self, account: crate::Address, coin: CoinId) -> Result<u128, LedgerError> {
        assert_eq!(account, self.inner.account);
        assert_eq!(coin, self.inner.coin);
        Ok(42)
    }

    async fn state_root(&self) -> Result<commonware_cryptography::sha256::Digest, LedgerError> {
        Ok(Sha256::hash(b"root"))
    }
}

#[test]
fn coin_rpc_queries() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let query = MockQuery::new();
        let mut router = RpcRouter::new(());
        crate::rpc::register(&mut router, crate::rpc::CoinsRpc::new(query.clone()))
            .expect("register coin RPC");
        let module = router.into_module();
        let account = encode_hex(&query.inner.account);
        let coin = encode_hex(&query.inner.coin);

        let mut nonce_params = jsonrpsee::core::params::ObjectParams::new();
        nonce_params
            .insert("account", account.clone())
            .expect("serialize nonce params");
        let nonce: crate::rpc::NonceResponse = module
            .call("coins.nonce", nonce_params)
            .await
            .expect("nonce response");
        assert_eq!(nonce.nonce, 7);

        let mut token_params = jsonrpsee::core::params::ObjectParams::new();
        token_params
            .insert("coin", coin.clone())
            .expect("serialize token params");
        let token: Option<crate::rpc::TokenResponse> = module
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
        let balance = module
            .call::<_, crate::rpc::BalanceResponse>("coins.balance", balance_params)
            .await
            .expect("balance response");
        assert_eq!(balance.amount, "42");

        let root: crate::rpc::RootResponse = module
            .call("coins.state_root", jsonrpsee::core::EmptyServerParams::new())
            .await
            .expect("root response");
        assert_eq!(root.root, encode_hex(&Sha256::hash(b"root")));
    });
}
