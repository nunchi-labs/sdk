//! Shared JSON-RPC wiring for Nunchi applications.
//!
//! Modules expose small [`jsonrpsee::RpcModule`] fragments over a caller-provided context. A
//! downstream chain owns the context, merges whichever SDK and application modules it wants through
//! [`RpcRouter`], and then serves the resulting module with jsonrpsee.

commonware_macros::stability_scope!(ALPHA {
use std::sync::Arc;

use commonware_codec::{DecodeExt, Encode, Read};
use commonware_formatting::{from_hex, hex};
use jsonrpsee::{
    core::{RegisterMethodError, RpcResult},
    types::{ErrorCode, ErrorObjectOwned, Params},
    Methods, RpcModule,
};
use serde::de::{DeserializeOwned, IgnoredAny};
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
///
/// An object is parsed directly so a field error is preserved. An array is parsed
/// as `T` first (the array is the value) and then as a one-element array of `T`.
pub fn params<T: DeserializeOwned>(params: &Params<'_>) -> RpcResult<T> {
    if params.is_object() {
        return params.parse();
    }
    let parsed = params.parse();
    if parsed.is_ok() {
        return parsed;
    }
    match params.one() {
        Ok(value) => Ok(value),
        // A one-element array is the positional form of an object. Its inner
        // deserialize error is the one callers can act on. Any other array is
        // the value itself, so keep the direct parse error.
        Err(one_error) if singleton_array(params) => Err(one_error),
        Err(_) => parsed,
    }
}

fn singleton_array(params: &Params<'_>) -> bool {
    let mut sequence = params.sequence();
    match sequence.next::<IgnoredAny>() {
        Ok(_) => sequence.next::<IgnoredAny>().is_err(),
        Err(_) => false,
    }
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
    T::decode(bytes).map_err(|err| invalid_params(format!("invalid {type_name}: {err}")))
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Height {
        height: u64,
    }

    fn error_data(error: &ErrorObjectOwned) -> String {
        error
            .data()
            .map(ToString::to_string)
            .unwrap_or_default()
    }

    #[test]
    fn named_object_parses() {
        let params = Params::new(Some(r#"{"height":7}"#));
        assert_eq!(super::params::<Height>(&params).unwrap().height, 7);
    }

    #[test]
    fn positional_object_parses() {
        let params = Params::new(Some(r#"[{"height":7}]"#));
        assert_eq!(super::params::<Height>(&params).unwrap().height, 7);
    }

    #[test]
    fn named_field_error_is_not_replaced_by_the_positional_fallback() {
        let params = Params::new(Some(r#"{"height":"nope"}"#));
        let error = super::params::<Height>(&params).unwrap_err();
        let data = error_data(&error);
        assert!(
            data.contains("u64"),
            "named param error should describe the field type, got {data}"
        );
        assert!(
            !data.contains("array"),
            "positional fallback must not hide the named param error, got {data}"
        );
    }

    #[test]
    fn invalid_positional_object_reports_the_inner_field_error() {
        let params = Params::new(Some(r#"[{"height":"nope"}]"#));
        let error = super::params::<Height>(&params).unwrap_err();
        let data = error_data(&error);
        assert!(
            data.contains("u64"),
            "positional object error should describe the field type, got {data}"
        );
    }

    #[test]
    fn array_value_is_not_unwrapped_as_one_element() {
        let params = Params::new(Some("[1, 2, 3]"));
        let values: Vec<u64> = super::params(&params).unwrap();
        assert_eq!(values, vec![1, 2, 3]);
    }
}
});
