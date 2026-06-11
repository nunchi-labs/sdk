//! Shared JSON-RPC wiring for Nunchi applications.
//!
//! Modules expose small [`jsonrpsee::RpcModule`] fragments over a caller-provided context. A
//! downstream chain owns the context, merges whichever SDK and application modules it wants through
//! [`RpcRouter`], and then serves the resulting module with jsonrpsee.

use std::sync::Arc;

use commonware_codec::{DecodeExt, Encode, Read};
use commonware_formatting::{from_hex, hex};
use jsonrpsee::{
    core::{RegisterMethodError, RpcResult},
    types::{ErrorCode, ErrorObjectOwned, Params},
    Methods, RpcModule,
};
use serde::de::DeserializeOwned;
use thiserror::Error;

pub use jsonrpsee::server::{ServerBuilder, ServerHandle};

const MODULE_ERROR_CODE: i32 = -32000;

/// Errors produced while assembling an RPC router.
#[derive(Debug, Error)]
pub enum RpcBuildError {
    #[error("failed to register RPC method: {0}")]
    Method(#[from] RegisterMethodError),
}

/// Aggregates RPC fragments that share one application context.
pub struct RpcRouter<Context> {
    context: Arc<Context>,
    module: RpcModule<Context>,
}

impl<Context> RpcRouter<Context> {
    /// Create an empty router around `context`.
    pub fn new(context: Context) -> Self {
        let context = Arc::new(context);
        Self {
            module: RpcModule::from_arc(context.clone()),
            context,
        }
    }

    /// Clone the context handle used by all merged modules.
    pub fn context(&self) -> Arc<Context> {
        self.context.clone()
    }

    /// Merge a module fragment into this router.
    pub fn merge(&mut self, methods: impl Into<Methods>) -> Result<(), RegisterMethodError> {
        self.module.merge(methods)
    }

    /// Return a snapshot of the registered method names.
    pub fn method_names(&self) -> Vec<&'static str> {
        self.module.method_names().collect()
    }

    /// Finish router construction.
    pub fn into_module(self) -> RpcModule<Context> {
        self.module
    }
}

impl<Context> From<RpcRouter<Context>> for Methods {
    fn from(router: RpcRouter<Context>) -> Self {
        router.into_module().into()
    }
}

/// Parse JSON-RPC parameters as either named params or a single positional object.
pub fn params<T: DeserializeOwned>(params: &Params<'_>) -> RpcResult<T> {
    params.parse::<T>().or_else(|_| params.one::<T>())
}

/// Encode a Commonware-codec value as lowercase hex for JSON responses.
pub fn encode_hex<T: Encode>(value: &T) -> String {
    hex(value.encode().as_ref())
}

/// Decode a Commonware-codec value from lowercase or `0x`-prefixed hex.
pub fn decode_hex<T>(value: &str, type_name: &'static str) -> RpcResult<T>
where
    T: Read<Cfg = ()>,
{
    let bytes = from_hex(value).ok_or_else(|| invalid_params(format!("{type_name} is not hex")))?;
    T::decode(bytes.as_ref()).map_err(|err| invalid_params(format!("invalid {type_name}: {err}")))
}

/// Convert invalid user input into a JSON-RPC invalid-params error.
pub fn invalid_params(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::InvalidParams.code(),
        "Invalid params",
        Some(message.into()),
    )
}

/// Convert module/application failures into a JSON-RPC server error.
pub fn module_error(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(MODULE_ERROR_CODE, "Module error", Some(message.into()))
}
