//! Aggregated JSON-RPC for the coins-chain example.

use jsonrpsee::{
    core::{RegisterMethodError, RpcResult},
    RpcModule,
};
use nunchi_coins::rpc::{CoinQuery, CoinsMempoolRpc, CoinsRpc, MempoolIngress};
use nunchi_rpc::{encode_hex, module_error, RpcBuildError, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::execution::SharedAppliedHeight;

pub use nunchi_coins::rpc::{
    SubmitTransactionParams, SubmitTransactionResponse, TransactionStatusResponse,
};

/// Shared RPC context for one coins-chain node.
///
/// Generic over the coin query backend: a live node serves from its stateful databases (see
/// [`crate::execution::NodeHandle::query`]); tests can serve from any other [`CoinQuery`]
/// implementation such as [`nunchi_coins::rpc::SharedLedger`].
#[derive(Clone)]
pub struct RpcContext<Q> {
    query: Q,
    applied_height: SharedAppliedHeight,
}

impl<Q: CoinQuery> RpcContext<Q> {
    pub fn new(query: Q, applied_height: SharedAppliedHeight) -> Self {
        Self {
            query,
            applied_height,
        }
    }

    pub fn query(&self) -> &Q {
        &self.query
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatusResponse {
    pub applied_height: u64,
    pub state_root: String,
}

/// Build the complete coins-chain RPC module.
///
/// Downstream applications can follow this pattern: create one router over their node context,
/// merge SDK modules via their `register` entry points (such as [`nunchi_coins::rpc::register`]
/// and [`nunchi_coins::rpc::register_mempool`]), then merge any app-specific methods.
pub fn module<Q, I>(
    query: Q,
    mempool: I,
    applied_height: SharedAppliedHeight,
) -> Result<RpcModule<RpcContext<Q>>, RpcBuildError>
where
    Q: CoinQuery,
    I: MempoolIngress,
{
    let mut router = RpcRouter::new(RpcContext::new(query.clone(), applied_height));
    nunchi_coins::rpc::register(&mut router, CoinsRpc::new(query))?;
    nunchi_coins::rpc::register_mempool(&mut router, CoinsMempoolRpc::new(mempool))?;
    router.merge(chain_module(router.context())?)?;
    Ok(router.into_module())
}

fn chain_module<Q>(
    context: std::sync::Arc<RpcContext<Q>>,
) -> Result<RpcModule<RpcContext<Q>>, RegisterMethodError>
where
    Q: CoinQuery,
{
    let mut module = RpcModule::from_arc(context);
    module.register_async_method("chain.status", |_raw, context, _| async move {
        let state_root = context
            .query
            .state_root()
            .await
            .map_err(|err| module_error(format!("failed to read state root: {err}")))?;
        let applied_height = *context.applied_height.lock().await;
        RpcResult::Ok(StatusResponse {
            applied_height: applied_height.get(),
            state_root: encode_hex(&state_root),
        })
    })?;
    Ok(module)
}
