//! JSON-RPC surface for bridge finalization exchange.

use commonware_consensus::{
    marshal::{core::Mailbox as MarshalMailbox, standard::Standard, Identifier},
    types::Height,
    Block as ConsensusBlock, Viewable,
};
use commonware_cryptography::sha256::Digest;
use jsonrpsee::{
    core::{async_trait, RegisterMethodError, RpcResult},
    proc_macros::rpc,
};
use nunchi_chain::SharedAppliedHeight;
use nunchi_dkg::{Finalization, Scheme};
use nunchi_rpc::{decode_hex, encode_hex, module_error, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::{BridgeMailbox, SubmitResult};

/// Local finalization lookup required by the bridge RPC server.
#[async_trait]
pub trait LocalFinalizations: Clone + Send + Sync + 'static {
    async fn latest_height(&self) -> Option<u64>;

    async fn finalization(&self, height: Height) -> Option<Finalization>;

    async fn latest_finalization(&self) -> Result<Option<Finalization>, String>;
}

#[async_trait]
impl<B> LocalFinalizations for MarshalMailbox<Scheme, Standard<B>>
where
    B: ConsensusBlock<Digest = Digest>,
{
    async fn latest_height(&self) -> Option<u64> {
        self.get_info(Identifier::<Digest>::Latest)
            .await
            .map(|(height, _)| height.get())
    }

    async fn finalization(&self, height: Height) -> Option<Finalization> {
        self.get_finalization(height).await
    }

    async fn latest_finalization(&self) -> Result<Option<Finalization>, String> {
        let Some((height, _)) = self.get_info(Identifier::<Digest>::Latest).await else {
            return Ok(None);
        };
        let Some(finalization) = self.get_finalization(height).await else {
            return Err(format!(
                "latest finalized height {} has no stored finalization",
                height.get()
            ));
        };
        Ok(Some(finalization))
    }
}

/// Concrete bridge RPC server.
#[derive(Clone)]
pub struct BridgeRpc<L> {
    bridge: BridgeMailbox,
    local: L,
    applied_height: SharedAppliedHeight,
}

impl<L> BridgeRpc<L> {
    pub fn new(bridge: BridgeMailbox, local: L, applied_height: SharedAppliedHeight) -> Self {
        Self {
            bridge,
            local,
            applied_height,
        }
    }
}

#[rpc(server, namespace = "bridge", namespace_separator = ".")]
pub trait Bridge {
    #[method(name = "status")]
    async fn status(&self) -> RpcResult<StatusResponse>;

    #[method(name = "finalization", param_kind = map)]
    async fn finalization(&self, height: u64) -> RpcResult<Option<String>>;

    #[method(name = "latestFinalization")]
    async fn latest_finalization(&self) -> RpcResult<Option<String>>;

    #[method(name = "submitFinalization", param_kind = map)]
    async fn submit_finalization(
        &self,
        finalization: String,
    ) -> RpcResult<SubmitFinalizationResponse>;

    #[method(name = "latestAccepted")]
    async fn latest_accepted(&self) -> RpcResult<Option<String>>;
}

#[async_trait]
impl<L> BridgeServer for BridgeRpc<L>
where
    L: LocalFinalizations,
{
    async fn status(&self) -> RpcResult<StatusResponse> {
        let applied_height = *self.applied_height.lock().await;
        let latest_local_height = self.local.latest_height().await;
        let latest_foreign_view = self.bridge.latest().await.map(|f| f.view().get());
        Ok(StatusResponse {
            applied_height: applied_height.get(),
            latest_local_height,
            latest_foreign_view,
        })
    }

    async fn finalization(&self, height: u64) -> RpcResult<Option<String>> {
        let finalization = self.local.finalization(Height::new(height)).await;
        Ok(finalization.map(|f| encode_hex(&f)))
    }

    async fn latest_finalization(&self) -> RpcResult<Option<String>> {
        self.local
            .latest_finalization()
            .await
            .map(|finalization| finalization.map(|f| encode_hex(&f)))
            .map_err(module_error)
    }

    async fn submit_finalization(
        &self,
        finalization: String,
    ) -> RpcResult<SubmitFinalizationResponse> {
        let finalization: Finalization = decode_hex(&finalization, "finalization")?;
        let result = self.bridge.submit(finalization).await;
        let accepted_view = self.bridge.latest().await.map(|f| f.view().get());
        Ok(SubmitFinalizationResponse {
            result: submit_result(result).to_string(),
            accepted_view,
        })
    }

    async fn latest_accepted(&self) -> RpcResult<Option<String>> {
        Ok(self.bridge.latest().await.map(|f| encode_hex(&f)))
    }
}

/// Register the bridge RPC methods into a downstream router.
pub fn register<Context, L>(
    router: &mut RpcRouter<Context>,
    rpc: BridgeRpc<L>,
) -> Result<(), RegisterMethodError>
where
    L: LocalFinalizations,
{
    router.merge(rpc.into_rpc())
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

fn submit_result(result: SubmitResult) -> &'static str {
    match result {
        SubmitResult::Rejected => "rejected",
        SubmitResult::Updated => "updated",
        SubmitResult::Stale => "stale",
    }
}
