//! JSON-RPC surface for the custom module.

use jsonrpsee::{
    core::{async_trait, RegisterMethodError, RpcResult},
    proc_macros::rpc,
};
use nunchi_common::Address;
use nunchi_rpc::{decode_hex, module_error, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::CustomError;

/// Read-only custom state required by the custom RPC server.
#[async_trait]
pub trait CustomQuery: Clone + Send + Sync + 'static {
    async fn value(&self, account: Address) -> Result<Option<u64>, CustomError>;
}

/// Concrete custom RPC server over a query backend.
#[derive(Clone)]
pub struct CustomRpc<Q> {
    query: Q,
}

impl<Q> CustomRpc<Q> {
    pub fn new(query: Q) -> Self {
        Self { query }
    }
}

#[rpc(server, namespace = "custom", namespace_separator = ".")]
pub trait Custom {
    #[method(name = "value", param_kind = map)]
    async fn value(&self, account: String) -> RpcResult<ValueResponse>;
}

#[async_trait]
impl<Q> CustomServer for CustomRpc<Q>
where
    Q: CustomQuery,
{
    async fn value(&self, account: String) -> RpcResult<ValueResponse> {
        let account = decode_hex(&account, "account")?;
        let value = self.query.value(account).await.map_err(rpc_error)?;
        Ok(ValueResponse { value })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValueResponse {
    pub value: Option<u64>,
}

/// Register the custom module's query RPC methods into a downstream router.
pub fn register<Context, Q>(
    router: &mut RpcRouter<Context>,
    rpc: CustomRpc<Q>,
) -> Result<(), RegisterMethodError>
where
    Q: CustomQuery,
{
    router.merge(rpc.into_rpc())
}

fn rpc_error(error: CustomError) -> jsonrpsee::types::ErrorObjectOwned {
    module_error(error.to_string())
}
