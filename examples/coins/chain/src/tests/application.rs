use commonware_consensus::types::Height;
use commonware_cryptography::{Hasher, Sha256};
use commonware_glue::stateful::db::DatabaseSet as _;
use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use nunchi_common::shared_database;
use futures::lock::Mutex as AsyncMutex;
use nunchi_chain::{ConsensusExtension, StateCommitment};
use nunchi_clob::{
    market_id, AssetId, ClobActor, ClobConfig, ClobExtension, ClobLedger, ClobOperation, OrderId,
    Side, TimeInForce, Transaction as ClobTransaction,
};
use nunchi_coins::{
    multisig_account_id, AccountPolicy, CoinOperation, CoinSpec, Ledger, MultisigPolicy,
    PrivateKey, TokenName, TokenSymbol, Transaction as CoinTransaction,
};
use nunchi_common::{QmdbBackend, QmdbBatch, QmdbDatabaseSet, QmdbState, RuntimeContext};
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

fn clob_asset(seed: &'static [u8]) -> AssetId {
    AssetId(Sha256::hash(seed))
}

fn clob_market() -> nunchi_clob::MarketId {
    market_id(&clob_asset(b"base"), &clob_asset(b"quote"), 5, 2)
}

fn committed_context(height: u64) -> RuntimeContext {
    RuntimeContext {
        epoch: 0,
        height,
        timestamp_ms: height * 1_000,
        block_digest: Some(Sha256::hash(&height.to_be_bytes())),
    }
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
        let databases: QmdbDatabaseSet<deterministic::Context> = shared_database(db);
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

#[test]
fn clob_mailbox_extension_records_verified_fill() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut state = QmdbState::init(context.child("state"), "clob-extension-state")
            .await
            .unwrap();
        let creator = nunchi_crypto::PrivateKey::ed25519_from_seed(10);
        let maker = nunchi_crypto::PrivateKey::ed25519_from_seed(11);
        let taker = nunchi_crypto::PrivateKey::ed25519_from_seed(12);
        let second_taker = nunchi_crypto::PrivateKey::ed25519_from_seed(13);

        let market_tx = ClobTransaction::sign(
            &creator,
            0,
            ClobOperation::CreateMarket {
                base_asset: clob_asset(b"base"),
                quote_asset: clob_asset(b"quote"),
                tick_size: 5,
                lot_size: 2,
            },
        );
        let market = {
            let mut ledger = ClobLedger::new(&mut state);
            ledger
                .apply_transaction(&market_tx, Default::default())
                .await
                .unwrap();
            ledger.market(&clob_market()).await.unwrap().unwrap()
        };

        let (actor, mailbox) = ClobActor::new(ClobConfig::default());
        let _actor_handle = actor.start(context.child("clob"));
        mailbox.upsert_market(market);
        let ask = ClobTransaction::sign(
            &maker,
            0,
            ClobOperation::PlaceOrder {
                market: clob_market(),
                side: Side::Ask,
                price: 100,
                base_quantity: 6,
                time_in_force: TimeInForce::GoodTilCancelled,
            },
        );
        let bid = ClobTransaction::sign(
            &taker,
            0,
            ClobOperation::PlaceOrder {
                market: clob_market(),
                side: Side::Bid,
                price: 100,
                base_quantity: 4,
                time_in_force: TimeInForce::ImmediateOrCancel,
            },
        );
        mailbox.submit_order(ask.clone()).await.unwrap();
        mailbox.submit_order(bid.clone()).await.unwrap();

        let mut extension = ClobExtension::new(mailbox);
        let payload = extension.propose().await;
        assert_eq!(payload.fills.len(), 1);
        let first_context = committed_context(2);
        assert!(extension
            .apply_payload(&mut state, first_context, &payload)
            .await);
        extension
            .commit_payload(&mut state, first_context, &payload)
            .await;

        {
            let ledger = ClobLedger::new(&mut state);
            let fills = ledger.market_fills(&clob_market()).await.unwrap();
            assert_eq!(fills.len(), 1);
            assert_eq!(fills[0].maker_order, OrderId(ask.digest()));
            assert_eq!(fills[0].taker_order, OrderId(bid.digest()));
        }

        let second_bid = ClobTransaction::sign(
            &second_taker,
            0,
            ClobOperation::PlaceOrder {
                market: clob_market(),
                side: Side::Bid,
                price: 100,
                base_quantity: 2,
                time_in_force: TimeInForce::ImmediateOrCancel,
            },
        );
        extension
            .mailbox()
            .submit_order(second_bid.clone())
            .await
            .unwrap();
        let second_payload = extension.propose().await;
        assert_eq!(second_payload.orders, vec![second_bid.clone()]);
        assert_eq!(second_payload.fills.len(), 1);
        let second_context = committed_context(3);
        assert!(extension
            .apply_payload(&mut state, second_context, &second_payload)
            .await);
        extension
            .commit_payload(&mut state, second_context, &second_payload)
            .await;

        let ledger = ClobLedger::new(&mut state);
        let fills = ledger.market_fills(&clob_market()).await.unwrap();
        assert_eq!(fills.len(), 2);
        assert_eq!(fills[1].maker_order, OrderId(ask.digest()));
        assert_eq!(fills[1].taker_order, OrderId(second_bid.digest()));
    });
}
