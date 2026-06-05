//! Aggregated JSON-RPC for the coins-chain example.

use commonware_consensus::types::Height;
use commonware_storage::Context as StorageContext;
use jsonrpsee::{
    core::{RegisterMethodError, RpcResult},
    RpcModule,
};
use nunchi_coins::{rpc::CoinsRpc, Transaction};
use nunchi_rpc::{decode_hex, encode_hex, params, RpcBuildError, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::{execution::NodeHandle, txpool::Submitter};

/// Shared RPC context for one coins-chain node.
#[derive(Clone)]
pub struct RpcContext<E: StorageContext> {
    handle: NodeHandle<E>,
}

impl<E: StorageContext> RpcContext<E> {
    pub fn new(handle: NodeHandle<E>) -> Self {
        Self { handle }
    }

    pub fn handle(&self) -> &NodeHandle<E> {
        &self.handle
    }

    pub async fn applied_height(&self) -> Height {
        *self.handle.applied_height.lock().await
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
/// merge SDK modules such as `nunchi_coins::rpc::module`, then merge any app-specific methods.
pub fn module<E>(handle: NodeHandle<E>) -> Result<RpcModule<RpcContext<E>>, RpcBuildError>
where
    E: StorageContext + Send + 'static,
{
    let coins = handle.ledger.clone();
    let submitter = handle.submitter.clone();
    let mut router = RpcRouter::new(RpcContext::new(handle));
    nunchi_coins::rpc::register(&mut router, CoinsRpc::new(coins))?;
    router.merge(coin_submit_module(router.context(), submitter)?)?;
    router.merge(chain_module(router.context())?)?;
    Ok(router.into_module())
}

fn coin_submit_module<E>(
    context: std::sync::Arc<RpcContext<E>>,
    submitter: Submitter,
) -> Result<RpcModule<RpcContext<E>>, RegisterMethodError>
where
    E: StorageContext + Send + 'static,
{
    let mut module = RpcModule::from_arc(context);
    module.register_method("coins.submit_transaction", move |raw, _, _| {
        let params: SubmitTransactionParams = params(&raw)?;
        let transaction: Transaction = decode_hex(&params.transaction, "coin transaction")?;
        let hash = transaction.digest();
        submitter.submit(transaction);
        RpcResult::Ok(SubmitTransactionResponse {
            hash: encode_hex(&hash),
        })
    })?;
    Ok(module)
}

fn chain_module<E>(
    context: std::sync::Arc<RpcContext<E>>,
) -> Result<RpcModule<RpcContext<E>>, RegisterMethodError>
where
    E: StorageContext + Send + 'static,
{
    let mut module = RpcModule::from_arc(context);
    module.register_async_method("chain.status", |_raw, context, _| async move {
        let ledger = context.handle.ledger.lock().await;
        let applied_height = *context.handle.applied_height.lock().await;
        RpcResult::Ok(StatusResponse {
            applied_height: applied_height.get(),
            state_root: encode_hex(&ledger.root()),
        })
    })?;
    Ok(module)
}
