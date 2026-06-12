//! End-to-end test of the aggregated coins-chain RPC, served over real HTTP.
//!
//! Uses commonware's tokio runtime so jsonrpsee can bind a socket and spawn its
//! connection tasks, exercising the same server path an operator would run.

use commonware_consensus::types::Height;
use commonware_runtime::{tokio, Runner as _, Supervisor as _};
use futures::lock::Mutex as AsyncMutex;
use jsonrpsee::{
    core::client::ClientT, http_client::HttpClient, rpc_params, types::error::INVALID_PARAMS_CODE,
};
use nunchi_coins::{rpc::SharedLedger, CoinOperation, CoinSpec, Ledger, PrivateKey, Transaction};
use nunchi_coins_chain::{
    rpc::{self, StatusResponse, SubmitTransactionParams, SubmitTransactionResponse},
    txpool::TxPool,
};
use nunchi_common::QmdbState;
use nunchi_rpc::{encode_hex, ServerBuilder};
use std::sync::Arc;

#[test]
fn rpc_serves_status_and_filters_submissions_over_http() {
    tokio::Runner::default().start(|context| async move {
        // An RPC backend without the full engine: a transaction pool plus a fresh ledger.
        let (txpool, submitter) = TxPool::new();
        let _txpool = txpool.start(context.child("txpool"));
        let db = QmdbState::init(context.child("coins_state"), "rpc-test-coins")
            .await
            .expect("init coin state");
        let ledger = SharedLedger::new(Ledger::new(db));
        let applied_height = Arc::new(AsyncMutex::new(Height::zero()));
        let expected_root = encode_hex(&ledger.lock().await.root());

        let module = rpc::module(ledger.clone(), submitter.clone(), applied_height)
            .expect("build RPC module");
        let server = ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .expect("bind RPC server");
        let address = server.local_addr().expect("server address");
        let server = server.start(module);

        let client = HttpClient::builder()
            .build(format!("http://{address}"))
            .expect("build RPC client");

        // The chain starts at height zero with an empty committed root.
        let status: StatusResponse = client
            .request("chain.status", rpc_params![])
            .await
            .expect("chain.status");
        assert_eq!(status.applied_height, 0);
        assert_eq!(status.state_root, expected_root);

        // A well-signed transaction is accepted and lands in the pool.
        let alice = PrivateKey::from_seed(100);
        let transaction = Transaction::sign(
            &alice,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new("GOLD", "Gold", 9, 1_000_000, None),
            },
        );
        let accepted: SubmitTransactionResponse = client
            .request(
                "coins.submit_transaction",
                rpc_params![SubmitTransactionParams {
                    transaction: encode_hex(&transaction),
                }],
            )
            .await
            .expect("submit valid transaction");
        assert_eq!(accepted.hash, encode_hex(&transaction.digest()));
        assert_eq!(
            submitter.pending(usize::MAX).await,
            vec![transaction.clone()]
        );

        // Corrupting the signature is rejected at ingress instead of being dropped silently.
        let mut tampered = encode_hex(&transaction);
        let last = tampered.pop().expect("non-empty encoding");
        tampered.push(if last == '0' { '1' } else { '0' });
        let rejection = client
            .request::<SubmitTransactionResponse, _>(
                "coins.submit_transaction",
                rpc_params![SubmitTransactionParams {
                    transaction: tampered,
                }],
            )
            .await
            .expect_err("tampered transaction must be rejected");
        match rejection {
            jsonrpsee::core::client::Error::Call(err) => {
                assert_eq!(err.code(), INVALID_PARAMS_CODE);
            }
            other => panic!("expected invalid-params call error, got {other:?}"),
        }
        // The pool still only holds the valid submission.
        assert_eq!(submitter.pending(usize::MAX).await, vec![transaction]);

        server.stop().expect("stop RPC server");
    });
}
