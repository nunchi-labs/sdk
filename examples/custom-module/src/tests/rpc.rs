use std::collections::HashMap;

use async_trait::async_trait;
use commonware_runtime::Runner as _;
use nunchi_common::Address;
use nunchi_crypto::PrivateKey;
use nunchi_rpc::{encode_hex, RpcRouter};

use crate::{
    rpc::{register, CustomQuery, CustomRpc, ValueResponse},
    CustomError,
};

#[derive(Clone)]
struct StubQuery {
    values: HashMap<Address, u64>,
}

impl StubQuery {
    fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    fn with_value(mut self, account: Address, value: u64) -> Self {
        self.values.insert(account, value);
        self
    }
}

#[async_trait]
impl CustomQuery for StubQuery {
    async fn value(&self, account: Address) -> Result<Option<u64>, CustomError> {
        Ok(self.values.get(&account).copied())
    }
}

fn module(query: StubQuery) -> jsonrpsee::RpcModule<()> {
    let mut router = RpcRouter::new(());
    register(&mut router, CustomRpc::new(query)).expect("register custom RPC");
    router.into_module()
}

#[test]
fn value_returns_some_for_known_account() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let signer = PrivateKey::ed25519_from_seed(1);
        let account = Address::external(&signer.public_key());
        let query = StubQuery::new().with_value(account.clone(), 42);
        let module = module(query);

        let mut params = jsonrpsee::core::params::ObjectParams::new();
        params
            .insert("account", encode_hex(&account))
            .expect("serialize account param");
        let response: ValueResponse = module
            .call("custom.value", params)
            .await
            .expect("value response");
        assert_eq!(response.value, Some(42));
    });
}

#[test]
fn value_returns_none_for_unknown_account() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let signer = PrivateKey::ed25519_from_seed(2);
        let account = Address::external(&signer.public_key());
        let query = StubQuery::new(); // no values inserted
        let module = module(query);

        let mut params = jsonrpsee::core::params::ObjectParams::new();
        params
            .insert("account", encode_hex(&account))
            .expect("serialize account param");
        let response: ValueResponse = module
            .call("custom.value", params)
            .await
            .expect("value response");
        assert_eq!(response.value, None);
    });
}

#[test]
fn value_rejects_malformed_hex_account() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let query = StubQuery::new();
        let module = module(query);

        let mut params = jsonrpsee::core::params::ObjectParams::new();
        params
            .insert("account", "not_valid_hex")
            .expect("serialize account param");
        let error = module
            .call::<_, ValueResponse>("custom.value", params)
            .await
            .expect_err("malformed hex should be rejected");
        assert!(
            error.to_string().contains("account"),
            "error should mention 'account': {error}"
        );
    });
}

#[test]
fn register_merges_without_panic() {
    let query = StubQuery::new();
    let mut router = RpcRouter::new(());
    register(&mut router, CustomRpc::new(query)).expect("register custom RPC should succeed");
}
