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
        // Signature verification happens once, inside pool admission.
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use commonware_runtime::Runner as _;
    use nunchi_mempool::DropReason;

    use super::*;
    use crate::{CoinOperation, CoinSpec, PrivateKey};

    #[derive(Clone, Default)]
    struct MockIngress {
        reject: Option<AdmissionError>,
        statuses: Arc<Mutex<HashMap<Digest, TxStatus>>>,
    }

    #[async_trait]
    impl MempoolIngress for MockIngress {
        async fn submit(&self, transaction: Transaction) -> Result<Digest, AdmissionError> {
            match &self.reject {
                Some(error) => Err(error.clone()),
                None => Ok(transaction.digest()),
            }
        }

        async fn status(&self, digest: Digest) -> Option<TxStatus> {
            self.statuses.lock().unwrap().get(&digest).copied()
        }
    }

    fn sample_transaction() -> Transaction {
        let signer = PrivateKey::ed25519_from_seed(1);
        Transaction::sign(
            &signer,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new("GOLD", "Gold", 9, 1_000, None),
            },
        )
    }

    fn module(ingress: MockIngress) -> jsonrpsee::RpcModule<()> {
        let mut router = RpcRouter::new(());
        register_mempool(&mut router, CoinsMempoolRpc::new(ingress)).expect("register mempool RPC");
        router.into_module()
    }

    #[test]
    fn submit_transaction_returns_hash() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let module = module(MockIngress::default());
            let transaction = sample_transaction();

            let mut params = jsonrpsee::core::params::ObjectParams::new();
            params
                .insert("transaction", encode_hex(&transaction))
                .expect("serialize transaction param");
            let response: SubmitTransactionResponse = module
                .call("coins.submit_transaction", params)
                .await
                .expect("submit response");
            assert_eq!(response.hash, encode_hex(&transaction.digest()));
        });
    }

    #[test]
    fn submit_transaction_maps_admission_errors() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let module = module(MockIngress {
                reject: Some(AdmissionError::StaleNonce {
                    nonce: 1,
                    committed: 3,
                }),
                ..Default::default()
            });
            let transaction = sample_transaction();

            let mut params = jsonrpsee::core::params::ObjectParams::new();
            params
                .insert("transaction", encode_hex(&transaction))
                .expect("serialize transaction param");
            let error = module
                .call::<_, SubmitTransactionResponse>("coins.submit_transaction", params)
                .await
                .expect_err("stale nonce should be rejected");
            assert!(error.to_string().contains("committed nonce"));
        });
    }

    #[test]
    fn transaction_status_reports_lifecycle() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let ingress = MockIngress::default();
            let transaction = sample_transaction();
            let digest = transaction.digest();
            ingress.statuses.lock().unwrap().insert(
                digest,
                TxStatus::Dropped {
                    reason: DropReason::Expired,
                },
            );
            let module = module(ingress);

            let mut params = jsonrpsee::core::params::ObjectParams::new();
            params
                .insert("hash", encode_hex(&digest))
                .expect("serialize hash param");
            let response: TransactionStatusResponse = module
                .call("coins.transaction_status", params)
                .await
                .expect("status response");
            assert_eq!(response.status, "dropped");
            assert_eq!(response.drop_reason.as_deref(), Some("expired"));

            // A digest the pool has never seen reports as unknown.
            use commonware_cryptography::{Hasher, Sha256};
            let mut unknown_params = jsonrpsee::core::params::ObjectParams::new();
            unknown_params
                .insert("hash", encode_hex(&Sha256::hash(b"missing")))
                .expect("serialize hash param");
            let response: TransactionStatusResponse = module
                .call("coins.transaction_status", unknown_params)
                .await
                .expect("status response");
            assert_eq!(response.status, "unknown");
            assert_eq!(response.height, None);
        });
    }
}
