//! Transaction ingress and status RPC methods for perpetuals transactions.

use commonware_cryptography::sha256::Digest;
use jsonrpsee::{
    core::{async_trait, RegisterMethodError, RpcResult},
    proc_macros::rpc,
    types::ErrorObjectOwned,
};
use nunchi_mempool::{AdmissionError, MempoolHandle, TxStatus};
use nunchi_rpc::{decode_hex, encode_hex, invalid_params, module_error, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::Transaction;

/// Mempool ingress required by the perps RPC server's write surface.
#[async_trait]
pub trait MempoolIngress: Clone + Send + Sync + 'static {
    async fn submit(&self, transaction: Transaction) -> Result<Digest, AdmissionError>;

    async fn status(&self, digest: Digest) -> Option<TxStatus>;
}

#[async_trait]
impl MempoolIngress for MempoolHandle<Transaction> {
    async fn submit(&self, transaction: Transaction) -> Result<Digest, AdmissionError> {
        MempoolHandle::submit(self, transaction).await
    }

    async fn status(&self, digest: Digest) -> Option<TxStatus> {
        MempoolHandle::status(self, digest).await
    }
}

/// Concrete perps mempool RPC server over an ingress backend.
#[derive(Clone)]
pub struct PerpetualsMempoolRpc<I> {
    ingress: I,
}

impl<I> PerpetualsMempoolRpc<I> {
    pub fn new(ingress: I) -> Self {
        Self { ingress }
    }
}

#[rpc(server, namespace = "perpetuals", namespace_separator = ".")]
pub trait PerpetualMempool {
    #[method(name = "submit_transaction", param_kind = map)]
    async fn submit_transaction(&self, transaction: String)
        -> RpcResult<SubmitTransactionResponse>;

    #[method(name = "transaction_status", param_kind = map)]
    async fn transaction_status(&self, hash: String) -> RpcResult<TransactionStatusResponse>;
}

#[async_trait]
impl<I> PerpetualMempoolServer for PerpetualsMempoolRpc<I>
where
    I: MempoolIngress,
{
    async fn submit_transaction(
        &self,
        transaction: String,
    ) -> RpcResult<SubmitTransactionResponse> {
        let transaction: Transaction = decode_hex(&transaction, "perpetuals transaction")?;
        let hash = self
            .ingress
            .submit(transaction)
            .await
            .map_err(admission_error)?;
        Ok(SubmitTransactionResponse {
            hash: encode_hex(&hash),
        })
    }

    async fn transaction_status(&self, hash: String) -> RpcResult<TransactionStatusResponse> {
        let digest: Digest = decode_hex(&hash, "transaction hash")?;
        let status = self.ingress.status(digest).await;
        Ok(TransactionStatusResponse::new(encode_hex(&digest), status))
    }
}

/// Client-side parameter struct for `perpetuals.submit_transaction`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitTransactionParams {
    /// Hex-encoded perpetuals transaction bytes.
    pub transaction: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitTransactionResponse {
    pub hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionStatusResponse {
    pub hash: String,
    /// One of `pending`, `finalized`, `dropped`, or `unknown`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drop_reason: Option<String>,
}

impl TransactionStatusResponse {
    fn new(hash: String, status: Option<TxStatus>) -> Self {
        let (status, height, drop_reason) = match status {
            Some(TxStatus::Pending) => ("pending", None, None),
            Some(TxStatus::Finalized { height }) => ("finalized", Some(height), None),
            Some(TxStatus::Dropped { reason }) => ("dropped", None, Some(reason.as_str())),
            None => ("unknown", None, None),
        };
        Self {
            hash,
            status: status.to_string(),
            height,
            drop_reason: drop_reason.map(str::to_string),
        }
    }
}

/// Register the perpetuals module's mempool RPC methods into a downstream router.
pub fn register_mempool<Context, I>(
    router: &mut RpcRouter<Context>,
    rpc: PerpetualsMempoolRpc<I>,
) -> Result<(), RegisterMethodError>
where
    I: MempoolIngress,
{
    router.merge(rpc.into_rpc())
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
