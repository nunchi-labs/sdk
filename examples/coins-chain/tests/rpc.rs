//! End-to-end test of the aggregated coins-chain RPC, served over real HTTP.
//!
//! Uses commonware's tokio runtime so jsonrpsee can bind a socket and spawn its
//! connection tasks, exercising the same server path an operator would run.

use commonware_consensus::types::Height;
use commonware_cryptography::Hasher;
use commonware_runtime::{tokio, Runner as _, Supervisor as _};
use futures::lock::Mutex as AsyncMutex;
use jsonrpsee::{
    core::client::ClientT, core::params::ObjectParams, http_client::HttpClient, rpc_params,
    types::error::INVALID_PARAMS_CODE,
};
use nunchi_coins::{
    rpc::SharedLedger, CoinOperation, CoinSpec, Ledger, PrivateKey, TokenName, TokenSymbol,
    Transaction as CoinTransaction,
};
use nunchi_coins_chain::rpc::{
    self, StatusResponse, SubmitTransactionResponse, TransactionStatusResponse,
};
use nunchi_coins_chain::Transaction;
use nunchi_common::QmdbState;
use nunchi_mempool::{Mempool, PoolConfig};
use nunchi_oracle::{OracleConfig, OracleOperation, Transaction as OracleTransaction};
use nunchi_rpc::{encode_hex, ServerBuilder};
use std::sync::Arc;

fn submit_params(transaction: &str) -> ObjectParams {
    let mut params = ObjectParams::new();
    params
        .insert("transaction", transaction)
        .expect("serialize transaction param");
    params
}

#[test]
fn rpc_serves_status_and_filters_submissions_over_http() {
    tokio::Runner::default().start(|context| async move {
        // An RPC backend without the full engine: a mempool plus a fresh ledger.
        let (mempool, submitter) = Mempool::<Transaction>::new(PoolConfig::default());
        let _mempool = mempool.start(context.child("mempool"));
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
        let transaction = CoinTransaction::sign(
            &alice,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new(
                    TokenSymbol::new("GOLD").expect("valid token symbol"),
                    TokenName::new("Gold").expect("valid token name"),
                    9,
                    1_000_000,
                    None,
                ),
            },
        );
        let accepted: SubmitTransactionResponse = client
            .request(
                "coins.submit_transaction",
                submit_params(&encode_hex(&transaction)),
            )
            .await
            .expect("submit valid transaction");
        assert_eq!(accepted.hash, encode_hex(&transaction.digest()));
        assert_eq!(
            submitter.pending(usize::MAX).await,
            vec![transaction.clone().into()]
        );

        // The aggregate chain RPC accepts non-coin transactions, including oracle updates.
        let oracle_admin = nunchi_crypto::PrivateKey::from_seed(200);
        let oracle = OracleTransaction::sign(
            &oracle_admin,
            0,
            OracleOperation::ConfigureMarket {
                market: nunchi_oracle::MarketId(commonware_cryptography::Sha256::hash(
                    b"rpc-oracle-market",
                )),
                config: OracleConfig {
                    admin: nunchi_coins::Address::from(oracle_admin.public_key()),
                    price_decimals: 6,
                    max_staleness_ms: 1_000,
                    max_confidence_bps: 500,
                    high_volatility_bps: 1_000,
                    divergence_warn_bps: 500,
                    divergence_halt_bps: 2_000,
                    source_priority: vec![nunchi_oracle::SourceId(
                        commonware_cryptography::Sha256::hash(b"rpc-oracle-source"),
                    )],
                    allow_negative: false,
                },
            },
        );
        let accepted_oracle: SubmitTransactionResponse = client
            .request(
                "chain.submit_transaction",
                submit_params(&encode_hex(&Transaction::from(oracle.clone()))),
            )
            .await
            .expect("submit oracle chain transaction");
        assert_eq!(accepted_oracle.hash, encode_hex(&oracle.digest()));

        // The pool reports the admitted transaction as pending.
        let mut status_params = ObjectParams::new();
        status_params
            .insert("hash", accepted.hash.clone())
            .expect("serialize hash param");
        let tx_status: TransactionStatusResponse = client
            .request("coins.transaction_status", status_params)
            .await
            .expect("transaction status");
        assert_eq!(tx_status.status, "pending");
        let mut oracle_status_params = ObjectParams::new();
        oracle_status_params
            .insert("hash", accepted_oracle.hash.clone())
            .expect("serialize hash param");
        let oracle_status: TransactionStatusResponse = client
            .request("chain.transaction_status", oracle_status_params)
            .await
            .expect("oracle transaction status");
        assert_eq!(oracle_status.status, "pending");

        // Resubmitting the identical transaction is rejected as a duplicate.
        let duplicate = client
            .request::<SubmitTransactionResponse, _>(
                "coins.submit_transaction",
                submit_params(&encode_hex(&transaction)),
            )
            .await
            .expect_err("duplicate transaction must be rejected");
        match duplicate {
            jsonrpsee::core::client::Error::Call(err) => {
                assert_eq!(err.code(), INVALID_PARAMS_CODE);
            }
            other => panic!("expected invalid-params call error, got {other:?}"),
        }

        // Corrupting the signature is rejected at ingress instead of being dropped silently.
        let mut tampered = encode_hex(&transaction);
        let last = tampered.pop().expect("non-empty encoding");
        tampered.push(if last == '0' { '1' } else { '0' });
        let rejection = client
            .request::<SubmitTransactionResponse, _>(
                "coins.submit_transaction",
                submit_params(&tampered),
            )
            .await
            .expect_err("tampered transaction must be rejected");
        match rejection {
            jsonrpsee::core::client::Error::Call(err) => {
                assert_eq!(err.code(), INVALID_PARAMS_CODE);
            }
            other => panic!("expected invalid-params call error, got {other:?}"),
        }
        // The pool still only holds the valid submissions.
        assert_eq!(
            submitter.pending(usize::MAX).await,
            vec![transaction.into(), oracle.into()]
        );

        server.stop().expect("stop RPC server");
    });
}
