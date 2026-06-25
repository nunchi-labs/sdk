//! JSON-RPC for the bridge-chain example.

use commonware_consensus::{marshal::Identifier, types::Height, Viewable};
use commonware_cryptography::sha256::Digest;
use jsonrpsee::{
    core::{RegisterMethodError, RpcResult},
    RpcModule,
};
use nunchi_bridge::{BridgeMailbox, SubmitResult};
use nunchi_dkg::Finalization;
use nunchi_rpc::{decode_hex, encode_hex, module_error, params, RpcBuildError};
use serde::{Deserialize, Serialize};

use crate::execution::NodeHandle;

/// Shared RPC context for one bridge-chain node.
#[derive(Clone)]
pub struct RpcContext<E>
where
    E: commonware_storage::Context
        + commonware_runtime::Spawner
        + commonware_runtime::Metrics
        + commonware_runtime::Clock
        + rand::Rng,
{
    node: NodeHandle<E>,
}

impl<E> RpcContext<E>
where
    E: commonware_storage::Context
        + commonware_runtime::Spawner
        + commonware_runtime::Metrics
        + commonware_runtime::Clock
        + rand::Rng,
{
    pub const fn new(node: NodeHandle<E>) -> Self {
        Self { node }
    }

    pub const fn bridge(&self) -> &BridgeMailbox {
        &self.node.bridge
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FinalizationParams {
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitFinalizationParams {
    pub finalization: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitFinalizationResponse {
    pub result: String,
    pub accepted_view: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatusResponse {
    pub applied_height: u64,
    pub latest_local_height: Option<u64>,
    pub latest_foreign_view: Option<u64>,
}

/// Build the complete bridge-chain RPC module.
pub fn module<E>(node: NodeHandle<E>) -> Result<RpcModule<RpcContext<E>>, RpcBuildError>
where
    E: commonware_storage::Context
        + commonware_runtime::Spawner
        + commonware_runtime::Metrics
        + commonware_runtime::Clock
        + rand::Rng
        + Send
        + Sync
        + 'static,
{
    let context = std::sync::Arc::new(RpcContext::new(node));
    let mut module = RpcModule::from_arc(context);
    register(&mut module)?;
    Ok(module)
}

fn register<E>(module: &mut RpcModule<RpcContext<E>>) -> Result<(), RegisterMethodError>
where
    E: commonware_storage::Context
        + commonware_runtime::Spawner
        + commonware_runtime::Metrics
        + commonware_runtime::Clock
        + rand::Rng
        + Send
        + Sync
        + 'static,
{
    module.register_async_method("bridge.status", |_raw, context, _| async move {
        let applied_height = *context.node.applied_height.lock().await;
        let latest_local_height = context
            .node
            .marshal
            .get_info(Identifier::<Digest>::Latest)
            .await
            .map(|(height, _)| height.get());
        let latest_foreign_view = context.node.bridge.latest().await.map(|f| f.view().get());
        RpcResult::Ok(StatusResponse {
            applied_height: applied_height.get(),
            latest_local_height,
            latest_foreign_view,
        })
    })?;

    module.register_async_method("bridge.finalization", |raw, context, _| async move {
        let params: FinalizationParams = params(&raw)?;
        let height = Height::new(params.height);
        let finalization = context.node.marshal.get_finalization(height).await;
        RpcResult::Ok(finalization.map(|f| encode_hex(&f)))
    })?;

    module.register_async_method("bridge.latestFinalization", |_raw, context, _| async move {
        let Some((height, _)) = context
            .node
            .marshal
            .get_info(Identifier::<Digest>::Latest)
            .await
        else {
            return RpcResult::Ok(None::<String>);
        };
        let Some(finalization) = context.node.marshal.get_finalization(height).await else {
            return Err(module_error(format!(
                "latest finalized height {} has no stored finalization",
                height.get()
            )));
        };
        RpcResult::Ok(Some(encode_hex(&finalization)))
    })?;

    module.register_async_method("bridge.submitFinalization", |raw, context, _| async move {
        let params: SubmitFinalizationParams = params(&raw)?;
        let finalization: Finalization = decode_hex(&params.finalization, "finalization")?;
        let result = context.node.bridge.submit(finalization).await;
        let latest = context.node.bridge.latest().await;
        let accepted_view = latest.map(|f| f.view().get());
        RpcResult::Ok(SubmitFinalizationResponse {
            result: submit_result(result).to_string(),
            accepted_view,
        })
    })?;

    module.register_async_method("bridge.latestAccepted", |_raw, context, _| async move {
        RpcResult::Ok(context.node.bridge.latest().await.map(|f| encode_hex(&f)))
    })?;

    Ok(())
}

fn submit_result(result: SubmitResult) -> &'static str {
    match result {
        SubmitResult::Rejected => "rejected",
        SubmitResult::Updated => "updated",
        SubmitResult::Stale => "stale",
    }
}
