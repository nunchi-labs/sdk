//! Transaction ingress and status RPC methods, backed by a `nunchi-mempool`.

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

/// Mempool ingress required by the coin RPC server's write surface.
#[async_trait]
pub trait MempoolIngress: Clone + Send + Sync + 'static {
    async fn submit(&self, transaction: Transaction) -> Result<Digest, AdmissionError>;

    async fn submit_many(
        &self,
        transactions: Vec<Transaction>,
    ) -> Vec<Result<Digest, AdmissionError>> {
        let mut results = Vec::with_capacity(transactions.len());
        for transaction in transactions {
            results.push(self.submit(transaction).await);
        }
        results
    }

    async fn status(&self, digest: Digest) -> Option<TxStatus>;
}

#[async_trait]
impl MempoolIngress for MempoolHandle<Transaction> {
    async fn submit(&self, transaction: Transaction) -> Result<Digest, AdmissionError> {
        MempoolHandle::submit(self, transaction).await
    }

    async fn submit_many(
        &self,
        transactions: Vec<Transaction>,
    ) -> Vec<Result<Digest, AdmissionError>> {
        MempoolHandle::submit_many(self, transactions).await
    }

    async fn status(&self, digest: Digest) -> Option<TxStatus> {
        MempoolHandle::status(self, digest).await
    }
}

/// Concrete coin mempool RPC server over an ingress backend.
#[derive(Clone)]
pub struct CoinsMempoolRpc<I> {
    ingress: I,
}

impl<I> CoinsMempoolRpc<I> {
    pub fn new(ingress: I) -> Self {
        Self { ingress }
    }
}

#[rpc(server, namespace = "coins", namespace_separator = ".")]
pub trait CoinMempool {
    #[method(name = "submit_transaction", param_kind = map)]
    async fn submit_transaction(&self, transaction: String)
        -> RpcResult<SubmitTransactionResponse>;

    #[method(name = "submit_transactions", param_kind = map)]
    async fn submit_transactions(
        &self,
        transactions: Vec<String>,
    ) -> RpcResult<SubmitTransactionsResponse>;

    #[method(name = "transaction_status", param_kind = map)]
    async fn transaction_status(&self, hash: String) -> RpcResult<TransactionStatusResponse>;
}

#[async_trait]
impl<I> CoinMempoolServer for CoinsMempoolRpc<I>
where
    I: MempoolIngress,
{
    async fn submit_transaction(
        &self,
        transaction: String,
    ) -> RpcResult<SubmitTransactionResponse> {
        let transaction: Transaction = decode_hex(&transaction, "coin transaction")?;
        let hash = self
            .ingress
            .submit(transaction)
            .await
            .map_err(admission_error)?;
        Ok(SubmitTransactionResponse {
            hash: encode_hex(&hash),
        })
    }

    async fn submit_transactions(
        &self,
        transactions: Vec<String>,
    ) -> RpcResult<SubmitTransactionsResponse> {
        let mut decoded = Vec::with_capacity(transactions.len());
        let mut results = vec![None; transactions.len()];
        for (index, transaction) in transactions.into_iter().enumerate() {
            match decode_hex::<Transaction>(&transaction, "coin transaction") {
                Ok(transaction) => decoded.push((index, transaction)),
                Err(error) => {
                    results[index] = Some(SubmitTransactionResult::err(error.to_string()))
                }
            }
        }

        if !decoded.is_empty() {
            let (indices, transactions): (Vec<_>, Vec<_>) = decoded.into_iter().unzip();
            for (index, result) in indices
                .into_iter()
                .zip(self.ingress.submit_many(transactions).await)
            {
                results[index] = Some(match result {
                    Ok(hash) => SubmitTransactionResult::ok(encode_hex(&hash)),
                    Err(error) => SubmitTransactionResult::err(error.to_string()),
                });
            }
        }

        Ok(SubmitTransactionsResponse {
            results: results
                .into_iter()
                .map(|result| result.expect("every result is filled"))
                .collect(),
        })
    }

    async fn transaction_status(&self, hash: String) -> RpcResult<TransactionStatusResponse> {
        let digest: Digest = decode_hex(&hash, "transaction hash")?;
        let status = self.ingress.status(digest).await;
        Ok(TransactionStatusResponse::new(encode_hex(&digest), status))
    }
}

/// Client-side parameter struct for `coins.submit_transaction`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitTransactionParams {
    /// Hex-encoded transaction bytes.
    pub transaction: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitTransactionResponse {
    pub hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitTransactionsParams {
    /// Hex-encoded transaction bytes.
    pub transactions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitTransactionsResponse {
    pub results: Vec<SubmitTransactionResult>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitTransactionResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SubmitTransactionResult {
    fn ok(hash: String) -> Self {
        Self {
            hash: Some(hash),
            error: None,
        }
    }

    fn err(error: String) -> Self {
        Self {
            hash: None,
            error: Some(error),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionStatusResponse {
    pub hash: String,
    /// One of `pending`, `finalized`, `dropped`, or `unknown`. Status is held
    /// in memory by the pool: it does not survive a node restart, and old
    /// entries are eventually evicted (reported as `unknown`).
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

/// Register the coin module's mempool RPC methods into a downstream router.
pub fn register_mempool<Context, I>(
    router: &mut RpcRouter<Context>,
    rpc: CoinsMempoolRpc<I>,
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
