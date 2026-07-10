use commonware_consensus::types::Height;
use commonware_glue::stateful::db::DatabaseSet as _;
use commonware_runtime::{deterministic, Runner as _};
use commonware_utils::sync::AsyncRwLock;
use futures::lock::Mutex as AsyncMutex;
use nunchi_chain::StateCommitment;
use nunchi_coins::{
    multisig_account_id, AccountPolicy, CoinOperation, CoinSpec, Ledger, MultisigPolicy,
    PrivateKey, TokenName, TokenSymbol, Transaction as CoinTransaction,
};
use nunchi_common::{NoopEventSink, QmdbBackend, QmdbBatch, QmdbDatabaseSet, QmdbState};
use nunchi_mempool::{Mempool, PoolConfig};
use std::sync::Arc;

use crate::application::*;

fn spec() -> CoinSpec {
    CoinSpec::new(
        TokenSymbol::new("NCH").expect("valid token symbol"),
        TokenName::new("Nunchi").expect("valid token name"),
        9,
        1_000,
        None,
    )
}

#[test]
fn proposal_skips_unregistered_multisig() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (_mempool, submitter) = Mempool::new(PoolConfig::default());
        let config = QmdbState::<deterministic::Context>::config(&context, "application-test");
        let db = QmdbBackend::init(context, config)
            .await
            .expect("init state db");
        let databases: QmdbDatabaseSet<deterministic::Context> = Arc::new(AsyncRwLock::new(db));
        let genesis_target = databases.committed_targets().await;
        let genesis_state = StateCommitment {
            root: genesis_target.root,
            range: genesis_target.range,
        };
        let applied_height = Arc::new(AsyncMutex::new(Height::zero()));
        let app = BasicApplication::new(
            submitter,
            16,
            applied_height,
            genesis_state,
            genesis_payload(),
        );

        let alice_a = PrivateKey::ed25519_from_seed(1);
        let alice_b = PrivateKey::secp256r1_from_seed(2);
        let policy =
            MultisigPolicy::new(2, vec![alice_a.public_key(), alice_b.public_key()]).unwrap();
        let account_id = multisig_account_id(&policy);
        let tx = CoinTransaction::sign_multisig(
            account_id.clone(),
            policy.clone(),
            &[&alice_a, &alice_b],
            0,
            CoinOperation::CreateToken { spec: spec() },
        );

        let batches = databases.new_batches().await;
        let (included, _) = app
            .build_valid_transactions(batches, Default::default(), vec![tx.clone().into()])
            .await
            .expect("build_valid_transactions should succeed");
        assert!(included.is_empty());

        let batches = databases.new_batches().await;
        let mut ledger = Ledger::new(QmdbBatch::new(batches));
        ledger
            .register_account_policy(account_id, AccountPolicy::Multisig(policy))
            .await
            .expect("register policy");
        let merkleized = ledger
            .into_inner()
            .merkleize()
            .await
            .expect("merkleize policy registration");
        databases.finalize(merkleized).await;

        let batches = databases.new_batches().await;
        let (included, _) = app
            .build_valid_transactions(batches, Default::default(), vec![tx.clone().into()])
            .await
            .expect("build_valid_transactions should succeed");
        assert_eq!(included, vec![tx.into()]);
    });
}

/// Profiling probe for the block execution hot path: measures
/// `build_valid_transactions` (the proposal-validate path) over a full
/// 4096-transfer block against QMDB-backed state. Run explicitly:
/// `cargo test --release -p nunchi-coins-chain profile_block -- --ignored --nocapture`
#[test]
#[ignore]
fn profile_block_execution() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let (_mempool, submitter) = Mempool::new(PoolConfig::default());
        let config = QmdbState::<deterministic::Context>::config(&context, "profile-test");
        let db = QmdbBackend::init(context, config)
            .await
            .expect("init state db");
        let databases: QmdbDatabaseSet<deterministic::Context> = Arc::new(AsyncRwLock::new(db));
        let genesis_target = databases.committed_targets().await;
        let genesis_state = StateCommitment {
            root: genesis_target.root,
            range: genesis_target.range,
        };
        let applied_height = Arc::new(AsyncMutex::new(Height::zero()));
        let app = BasicApplication::new(
            submitter,
            4096,
            applied_height,
            genesis_state,
            genesis_payload(),
        );

        const ACCOUNTS: usize = 256;
        const TXS_PER_ACCOUNT: usize = 16;

        // Seed: issuer creates the token, then mints a balance to every account.
        let issuer = PrivateKey::ed25519_from_seed(0);
        let keys: Vec<PrivateKey> = (1..=ACCOUNTS as u64)
            .map(PrivateKey::ed25519_from_seed)
            .collect();
        let accounts: Vec<_> = keys
            .iter()
            .map(|key| nunchi_coins::Address::external(&key.public_key()))
            .collect();

        let batches = databases.new_batches().await;
        let mut ledger = Ledger::new(QmdbBatch::new(batches));
        let coin = ledger
            .create_token(
                nunchi_coins::Address::external(&issuer.public_key()),
                CoinSpec::new(
                    TokenSymbol::new("NCH").expect("symbol"),
                    TokenName::new("Nunchi").expect("name"),
                    9,
                    0,
                    None,
                ),
            )
            .await
            .expect("create token");
        for (index, account) in accounts.iter().enumerate() {
            let mint = CoinTransaction::sign(
                &issuer,
                index as u64,
                CoinOperation::Mint {
                    coin,
                    to: account.clone(),
                    amount: 1_000_000,
                },
            );
            ledger
                .apply_transaction(&mint, NoopEventSink)
                .await
                .expect("mint");
        }
        let merkleized = ledger.into_inner().merkleize().await.expect("merkleize");
        databases.finalize(merkleized).await;

        // A full block: 256 accounts x 16 sequential-nonce transfers.
        let mut candidates = Vec::with_capacity(ACCOUNTS * TXS_PER_ACCOUNT);
        for nonce in 0..TXS_PER_ACCOUNT as u64 {
            for (index, key) in keys.iter().enumerate() {
                let to = accounts[(index + 1) % ACCOUNTS].clone();
                candidates.push(
                    CoinTransaction::sign(
                        key,
                        nonce,
                        CoinOperation::Transfer {
                            coin,
                            from: accounts[index].clone(),
                            to,
                            amount: 1,
                        },
                    )
                    .into(),
                );
            }
        }
        println!("candidates: {}", candidates.len());

        for round in 0..3 {
            let batches = databases.new_batches().await;
            let started = std::time::Instant::now();
            let (included, _merkleized) = app
                .build_valid_transactions(batches, Default::default(), candidates.clone())
                .await
                .expect("build");
            let elapsed = started.elapsed();
            println!(
                "round {round}: build_valid_transactions({}) took {:?} ({:.1}us/tx), included {}",
                candidates.len(),
                elapsed,
                elapsed.as_secs_f64() * 1e6 / candidates.len() as f64,
                included.len(),
            );
        }
    });
}
