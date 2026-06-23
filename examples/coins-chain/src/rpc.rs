//! Aggregated JSON-RPC for the coins-chain example.

use commonware_cryptography::sha256::Digest;
use jsonrpsee::{
    core::{RegisterMethodError, RpcResult},
    types::ErrorObjectOwned,
    RpcModule,
};
use nunchi_coins::rpc::{CoinQuery, CoinsMempoolRpc, CoinsRpc, MempoolIngress};
use nunchi_coins::Transaction as CoinTransaction;
use nunchi_mempool::{AdmissionError, MempoolHandle, TxStatus};
use nunchi_rpc::{decode_hex, encode_hex, invalid_params, module_error, RpcBuildError, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::{execution::SharedAppliedHeight, Transaction};

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

#[derive(Clone)]
struct ChainMempoolIngress {
    mempool: MempoolHandle<Transaction>,
}

impl ChainMempoolIngress {
    fn new(mempool: MempoolHandle<Transaction>) -> Self {
        Self { mempool }
    }
}

#[jsonrpsee::core::async_trait]
impl MempoolIngress for ChainMempoolIngress {
    async fn submit(&self, transaction: CoinTransaction) -> Result<Digest, AdmissionError> {
        self.mempool.submit(transaction.into()).await
    }

    async fn status(&self, digest: Digest) -> Option<TxStatus> {
        self.mempool.status(digest).await
    }
}

/// Build the complete coins-chain RPC module.
///
/// Downstream applications can follow this pattern: create one router over their node context,
/// merge SDK modules via their `register` entry points (such as [`nunchi_coins::rpc::register`]
/// and [`nunchi_coins::rpc::register_mempool`]), then merge any app-specific methods.
pub fn module<Q>(
    query: Q,
    mempool: MempoolHandle<Transaction>,
    applied_height: SharedAppliedHeight,
) -> Result<RpcModule<RpcContext<Q>>, RpcBuildError>
where
    Q: CoinQuery,
{
    let mut router = RpcRouter::new(RpcContext::new(query.clone(), applied_height));
    nunchi_coins::rpc::register(&mut router, CoinsRpc::new(query))?;
    nunchi_coins::rpc::register_mempool(
        &mut router,
        CoinsMempoolRpc::new(ChainMempoolIngress::new(mempool.clone())),
    )?;
    router.merge(chain_mempool_module(router.context(), mempool)?)?;
    router.merge(chain_module(router.context())?)?;
    Ok(router.into_module())
}

/// Build the aggregate chain transaction mempool RPC fragment.
///
/// Unlike `coins.submit_transaction`, this accepts [`crate::Transaction`], so callers can submit
/// authority and oracle transactions through the same node RPC ingress used by block production.
pub fn chain_mempool_module<Q>(
    context: std::sync::Arc<RpcContext<Q>>,
    mempool: MempoolHandle<Transaction>,
) -> Result<RpcModule<RpcContext<Q>>, RegisterMethodError>
where
    Q: CoinQuery,
{
    let mut module = RpcModule::from_arc(context);
    register_chain_mempool_methods(&mut module, mempool)?;
    Ok(module)
}

/// Build only the aggregate chain transaction mempool RPC fragment.
pub fn standalone_chain_mempool_module(
    mempool: MempoolHandle<Transaction>,
) -> Result<RpcModule<()>, RegisterMethodError> {
    let mut module = RpcModule::new(());
    register_chain_mempool_methods(&mut module, mempool)?;
    Ok(module)
}

fn register_chain_mempool_methods<Context>(
    module: &mut RpcModule<Context>,
    mempool: MempoolHandle<Transaction>,
) -> Result<(), RegisterMethodError>
where
    Context: Send + Sync + 'static,
{
    let submit_mempool = mempool.clone();
    module.register_async_method("chain.submit_transaction", move |raw, _, _| {
        let mempool = submit_mempool.clone();
        async move {
            let params: SubmitTransactionParams = nunchi_rpc::params(&raw)?;
            let transaction: Transaction = decode_hex(&params.transaction, "chain transaction")?;
            let hash = mempool.submit(transaction).await.map_err(admission_error)?;
            RpcResult::Ok(SubmitTransactionResponse {
                hash: encode_hex(&hash),
            })
        }
    })?;
    let status_mempool = mempool;
    module.register_async_method("chain.transaction_status", move |raw, _, _| {
        let mempool = status_mempool.clone();
        async move {
            let params: TransactionStatusParams = nunchi_rpc::params(&raw)?;
            let digest: Digest = decode_hex(&params.hash, "transaction hash")?;
            let status = mempool.status(digest).await;
            let (status, height, drop_reason) = match status {
                Some(TxStatus::Pending) => ("pending", None, None),
                Some(TxStatus::Finalized { height }) => ("finalized", Some(height), None),
                Some(TxStatus::Dropped { reason }) => ("dropped", None, Some(reason.as_str())),
                None => ("unknown", None, None),
            };
            RpcResult::Ok(TransactionStatusResponse {
                hash: encode_hex(&digest),
                status: status.to_string(),
                height,
                drop_reason: drop_reason.map(str::to_string),
            })
        }
    })?;
    Ok(())
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionStatusParams {
    pub hash: String,
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
