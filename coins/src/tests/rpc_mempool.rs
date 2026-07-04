use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use commonware_runtime::Runner as _;
use nunchi_mempool::DropReason;
use nunchi_common::NoFee;
use nunchi_rpc::{encode_hex, RpcRouter};

use crate::{
    rpc::{
        register_mempool, CoinsMempoolRpc, MempoolIngress, SubmitTransactionResponse,
        TransactionStatusResponse,
    },
    CoinOperation, CoinSpec, PrivateKey, TokenName, TokenSymbol, Transaction,
};

#[derive(Clone, Default)]
struct MockIngress {
    reject: Option<nunchi_mempool::AdmissionError>,
    statuses:
        Arc<Mutex<HashMap<commonware_cryptography::sha256::Digest, nunchi_mempool::TxStatus>>>,
}

#[async_trait]
impl MempoolIngress for MockIngress {
    async fn submit(
        &self,
        transaction: Transaction,
    ) -> Result<commonware_cryptography::sha256::Digest, nunchi_mempool::AdmissionError> {
        match &self.reject {
            Some(error) => Err(error.clone()),
            None => Ok(transaction.digest()),
        }
    }

    async fn status(
        &self,
        digest: commonware_cryptography::sha256::Digest,
    ) -> Option<nunchi_mempool::TxStatus> {
        self.statuses.lock().unwrap().get(&digest).copied()
    }
}

fn sample_transaction() -> Transaction {
    let signer = PrivateKey::ed25519_from_seed(1);
    Transaction::sign(
        &signer,
        0, NoFee,         CoinOperation::CreateToken {
            spec: CoinSpec::new(
                TokenSymbol::new("GOLD").unwrap(),
                TokenName::new("Gold").unwrap(),
                9,
                1_000,
                None,
            ),
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
            reject: Some(nunchi_mempool::AdmissionError::StaleNonce {
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
            nunchi_mempool::TxStatus::Dropped {
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
