//! Aggregated JSON-RPC for the coins-chain example.

use commonware_cryptography::sha256::Digest;
use jsonrpsee::{
    core::{RegisterMethodError, RpcResult},
    RpcModule,
};
use nunchi_coins::rpc::{
    CoinQuery, CoinsMempoolRpc, CoinsRpc, MempoolIngress as CoinMempoolIngress,
};
use nunchi_coins::Transaction as CoinTransaction;
use nunchi_mempool::{AdmissionError, MempoolHandle, TxStatus};
use nunchi_perpetuals::rpc::{
    MempoolIngress as PerpetualMempoolIngress, PerpetualQuery, PerpetualsMempoolRpc, PerpetualsRpc,
};
use nunchi_perpetuals::Transaction as PerpetualTransaction;
use nunchi_rpc::{encode_hex, module_error, RpcBuildError, RpcRouter};
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
impl CoinMempoolIngress for ChainMempoolIngress {
    async fn submit(&self, transaction: CoinTransaction) -> Result<Digest, AdmissionError> {
        self.mempool.submit(transaction.into()).await
    }

    async fn status(&self, digest: Digest) -> Option<TxStatus> {
        self.mempool.status(digest).await
    }
}

#[jsonrpsee::core::async_trait]
impl PerpetualMempoolIngress for ChainMempoolIngress {
    async fn submit(&self, transaction: PerpetualTransaction) -> Result<Digest, AdmissionError> {
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
    Q: CoinQuery + PerpetualQuery,
{
    let ingress = ChainMempoolIngress::new(mempool);
    let mut router = RpcRouter::new(RpcContext::new(query.clone(), applied_height));
    nunchi_coins::rpc::register(&mut router, CoinsRpc::new(query.clone()))?;
    nunchi_coins::rpc::register_mempool(&mut router, CoinsMempoolRpc::new(ingress.clone()))?;
    nunchi_perpetuals::rpc::register(&mut router, PerpetualsRpc::new(query))?;
    nunchi_perpetuals::rpc::register_mempool(&mut router, PerpetualsMempoolRpc::new(ingress))?;
    router.merge(chain_module(router.context())?)?;
    Ok(router.into_module())
}

fn chain_module<Q>(
    context: std::sync::Arc<RpcContext<Q>>,
) -> Result<RpcModule<RpcContext<Q>>, RegisterMethodError>
where
    Q: CoinQuery + PerpetualQuery,
{
    let mut module = RpcModule::from_arc(context);
    module.register_async_method("chain.status", |_raw, context, _| async move {
        let state_root = CoinQuery::state_root(&context.query)
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
