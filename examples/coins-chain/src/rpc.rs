//! Aggregated JSON-RPC for the coins-chain example.

use jsonrpsee::{
    core::{RegisterMethodError, RpcResult},
    RpcModule,
};
use nunchi_coins::{
    rpc::{CoinQuery, CoinsRpc},
    Transaction,
};
use nunchi_rpc::{
    decode_hex, encode_hex, invalid_params, module_error, params, RpcBuildError, RpcRouter,
};
use serde::{Deserialize, Serialize};

use crate::{execution::SharedAppliedHeight, Submitter};

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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitTransactionParams {
    /// Commonware-codec encoded `nunchi_coins::Transaction` bytes, formatted as hex.
    pub transaction: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitTransactionResponse {
    pub hash: String,
}

/// Build the complete coins-chain RPC module.
///
/// Downstream applications can follow this pattern: create one router over their node context,
/// merge SDK modules via their `register` entry points (such as [`nunchi_coins::rpc::register`]),
/// then merge any app-specific methods.
pub fn module<Q>(
    query: Q,
    submitter: Submitter,
    applied_height: SharedAppliedHeight,
) -> Result<RpcModule<RpcContext<Q>>, RpcBuildError>
where
    Q: CoinQuery,
{
    let mut router = RpcRouter::new(RpcContext::new(query.clone(), applied_height));
    nunchi_coins::rpc::register(&mut router, CoinsRpc::new(query))?;
    router.merge(coin_submit_module(router.context(), submitter)?)?;
    router.merge(chain_module(router.context())?)?;
    Ok(router.into_module())
}

fn coin_submit_module<Q>(
    context: std::sync::Arc<RpcContext<Q>>,
    submitter: Submitter,
) -> Result<RpcModule<RpcContext<Q>>, RegisterMethodError>
where
    Q: CoinQuery,
{
    let mut module = RpcModule::from_arc(context);
    module.register_method("coins.submit_transaction", move |raw, _, _| {
        let params: SubmitTransactionParams = params(&raw)?;
        let transaction: Transaction = decode_hex(&params.transaction, "coin transaction")?;
        // Reject invalid signatures at the door; the txpool would only drop them silently.
        // Acceptance is still no guarantee of inclusion: ingress past this point is
        // fire-and-forget, and application-level validity (nonce, balances) is enforced
        // at proposal and execution time.
        transaction
            .verify()
            .map_err(|err| invalid_params(format!("transaction failed verification: {err}")))?;
        let hash = transaction.digest();
        submitter.submit(transaction);
        RpcResult::Ok(SubmitTransactionResponse {
            hash: encode_hex(&hash),
        })
    })?;
    Ok(module)
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
