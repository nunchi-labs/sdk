//! Aggregated JSON-RPC for the coins-chain example.

use commonware_cryptography::sha256::Digest;
use jsonrpsee::{
    core::{RegisterMethodError, RpcResult},
    types::ErrorObjectOwned,
    RpcModule,
};
use nunchi_coins::rpc::{CoinQuery, CoinsRpc};
use nunchi_mempool::{AdmissionError, MempoolHandle, TxStatus};
use nunchi_rpc::{
    decode_hex, encode_hex, invalid_params, module_error, params, RpcBuildError, RpcRouter,
};
use serde::{Deserialize, Serialize};

use crate::{execution::SharedAppliedHeight, CoinTransaction, Transaction};

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
    mempool: MempoolHandle<Transaction>,
    applied_height: SharedAppliedHeight,
}

impl<Q: CoinQuery> RpcContext<Q> {
    pub fn new(
        query: Q,
        mempool: MempoolHandle<Transaction>,
        applied_height: SharedAppliedHeight,
    ) -> Self {
        Self {
            query,
            mempool,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionStatusParams {
    pub hash: String,
}

/// Build the complete coins-chain RPC module.
///
/// Downstream applications can follow this pattern: create one router over their node context,
/// merge SDK query modules via their `register` entry points (such as
/// [`nunchi_coins::rpc::register`]), then merge any app-specific methods.
pub fn module<Q>(
    query: Q,
    mempool: MempoolHandle<Transaction>,
    applied_height: SharedAppliedHeight,
) -> Result<RpcModule<RpcContext<Q>>, RpcBuildError>
where
    Q: CoinQuery,
{
    let mut router = RpcRouter::new(RpcContext::new(query.clone(), mempool, applied_height));
    nunchi_coins::rpc::register(&mut router, CoinsRpc::new(query))?;
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
    module.register_async_method("coins.submit_transaction", |raw, context, _| async move {
        let params: SubmitTransactionParams = params(&raw)?;
        let transaction: CoinTransaction = decode_hex(&params.transaction, "coin transaction")?;
        let hash = context
            .mempool
            .submit(transaction.into())
            .await
            .map_err(admission_error)?;
        RpcResult::Ok(SubmitTransactionResponse {
            hash: encode_hex(&hash),
        })
    })?;
    module.register_async_method("coins.transaction_status", |raw, context, _| async move {
        let params: TransactionStatusParams = params(&raw)?;
        let digest: Digest = decode_hex(&params.hash, "transaction hash")?;
        let status = context.mempool.status(digest).await;
        RpcResult::Ok(transaction_status_response(encode_hex(&digest), status))
    })?;
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

fn transaction_status_response(hash: String, status: Option<TxStatus>) -> TransactionStatusResponse {
    let (status, height, drop_reason) = match status {
        Some(TxStatus::Pending) => ("pending", None, None),
        Some(TxStatus::Finalized { height }) => ("finalized", Some(height), None),
        Some(TxStatus::Dropped { reason }) => ("dropped", None, Some(reason.as_str())),
        None => ("unknown", None, None),
    };
    TransactionStatusResponse {
        hash,
        status: status.to_string(),
        height,
        drop_reason: drop_reason.map(str::to_string),
    }
}

fn admission_error(error: AdmissionError) -> ErrorObjectOwned {
    match error {
        AdmissionError::InvalidSignature(_)
        | AdmissionError::TxTooLarge { .. }
        | AdmissionError::Duplicate
        | AdmissionError::StaleNonce { .. } => invalid_params(error.to_string()),
        AdmissionError::AccountQueueFull | AdmissionError::PoolFull | AdmissionError::Shutdown => {
            module_error(error.to_string())
        }
    }
}
