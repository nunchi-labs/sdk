use nunchi_authority::AuthorityError;
use nunchi_bridge::{
    escrow_address, transfer_record, AssetId, BridgeGenesis, BridgeError, BridgeOperation,
    BridgeTransaction, BridgeTransferRecord, ChainId,
};
use nunchi_clob::ClobError;
use nunchi_coins::{
    CoinDB, CoinOperation, CoinSpec, CoinsGenesis, FeeCharged, FeeGenesis, Ledger, LedgerError,
    TokenCreated, TokenFactory, TokenGenesis, TokenName, TokenSymbol, FEE_CHARGED_EVENT,
    TOKEN_CREATED_EVENT, TRANSFERRED_EVENT,
};
use nunchi_common::{Address, QmdbState, Runtime, RuntimeContext, VecEventSink};
use nunchi_crypto::PrivateKey;
use nunchi_oracle::OracleError;

use crate::runtime::*;
use crate::Transaction;
use commonware_codec::{DecodeExt, EncodeSize};
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _};

#[test]
fn runtime_error_classifies_storage_errors() {
    assert!(RuntimeError::Coins(LedgerError::Storage("disk".into())).is_storage());
    assert!(RuntimeError::Authority(AuthorityError::Storage("disk".into())).is_storage());
    assert!(RuntimeError::Clob(ClobError::Storage("disk".into())).is_storage());
    assert!(RuntimeError::Oracle(OracleError::Storage("disk".into())).is_storage());
    assert!(RuntimeError::Bridge(BridgeError::Storage("disk".into())).is_storage());

    assert!(!RuntimeError::Authority(AuthorityError::NotConfigured).is_storage());
    assert!(!RuntimeError::Coins(LedgerError::InvalidTokenSpec("bad")).is_storage());
    assert!(!RuntimeError::Clob(ClobError::OffchainOnly).is_storage());
    assert!(!RuntimeError::Oracle(OracleError::PayloadTooLarge).is_storage());
    assert!(!RuntimeError::Bridge(BridgeError::ChainNotConfigured).is_storage());
}

#[test]
fn runtime_apply_forwards_coin_events() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "coins-runtime-events")
            .await
            .unwrap();
        let key = PrivateKey::ed25519_from_seed(1);
        let tx = nunchi_coins::Transaction::sign(
            &key,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new(
                    TokenSymbol::new("NCH").unwrap(),
                    TokenName::new("Nunchi").unwrap(),
                    9,
                    1_000,
                    Some(2_000),
                ),
            },
        );
        let tx = Transaction::from(tx);
        let mut events = VecEventSink::new();

        CoinsRuntime::apply(&mut state, RuntimeContext::default(), &tx, &mut events)
            .await
            .unwrap();

        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        assert_eq!(event.name.as_ref(), TOKEN_CREATED_EVENT);
        let payload = TokenCreated::decode(event.value.as_ref()).unwrap();
        assert_eq!(payload.token.total_supply, 1_000);
        assert_eq!(payload.token.max_supply, Some(2_000));
    });
}

#[test]
fn runtime_validate_has_no_event_sink_surface() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "coins-runtime-validate")
            .await
            .unwrap();
        let key = PrivateKey::ed25519_from_seed(1);
        let tx = Transaction::from(nunchi_coins::Transaction::sign(
            &key,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new(
                    TokenSymbol::new("NCH").unwrap(),
                    TokenName::new("Nunchi").unwrap(),
                    9,
                    1_000,
                    None,
                ),
            },
        ));

        CoinsRuntime::validate(&mut state, RuntimeContext::default(), &tx)
            .await
            .unwrap();
    });
}

async fn fee_state(
    context: deterministic::Context,
    partition: &str,
    genesis: &CoinsGenesis,
) -> QmdbState<deterministic::Context> {
    let mut state = QmdbState::init(context, partition).await.unwrap();
    let mut ledger = Ledger::new(&mut state);
    ledger.apply_genesis(genesis).await.expect("apply genesis");
    state
}

fn fee_genesis(issuer: Address, collector: Address, base: u128, per_byte: u128) -> CoinsGenesis {
    CoinsGenesis {
        account_policies: vec![],
        tokens: vec![TokenGenesis {
            issuer,
            spec: CoinSpec::new(
                TokenSymbol::new("NCH").unwrap(),
                TokenName::new("Nunchi").unwrap(),
                9,
                1_000,
                None,
            ),
            allocations: vec![],
        }],
        fees: Some(FeeGenesis {
            token: 0,
            collector,
            base,
            per_byte,
        }),
    }
}

#[test]
fn runtime_charges_fee_before_dispatch() {
    deterministic::Runner::default().start(|context| async move {
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = Address::external(&alice_key.public_key());
        let bob = Address::external(&PrivateKey::ed25519_from_seed(2).public_key());
        let collector = Address::external(&PrivateKey::ed25519_from_seed(9).public_key());

        let genesis = fee_genesis(alice.clone(), collector.clone(), 7, 3);
        let mut state = fee_state(context, "coins-runtime-fees", &genesis).await;
        let spec = &genesis.tokens[0].spec;
        let coin = TokenFactory::derive_coin_id(&alice, 0, spec);

        let tx = Transaction::from(nunchi_coins::Transaction::sign(
            &alice_key,
            0,
            CoinOperation::Transfer {
                coin,
                from: alice.clone(),
                to: bob.clone(),
                amount: 100,
            },
        ));
        let fee = 7 + 3 * tx.encode_size() as u128;

        let mut events = VecEventSink::new();
        CoinsRuntime::apply(&mut state, RuntimeContext::default(), &tx, &mut events)
            .await
            .expect("apply transfer with fee");

        assert_eq!(state.balance(&alice, &coin).await.unwrap(), 900 - fee);
        assert_eq!(state.balance(&bob, &coin).await.unwrap(), 100);
        assert_eq!(state.balance(&collector, &coin).await.unwrap(), fee);

        assert_eq!(events.len(), 2);
        assert_eq!(events.events()[0].name.as_ref(), FEE_CHARGED_EVENT);
        let charged = FeeCharged::decode(events.events()[0].value.as_ref()).unwrap();
        assert_eq!(charged.payer, alice);
        assert_eq!(charged.collector, collector);
        assert_eq!(charged.amount, fee);
        assert_eq!(events.events()[1].name.as_ref(), TRANSFERRED_EVENT);
    });
}

#[test]
fn bridge_lock_escrows_funds_and_records_transfer() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-lock-escrow").await.unwrap();
        let alice = PrivateKey::ed25519_from_seed(1);
        let alice_addr = Address::external(&alice.public_key());

        // Create a token; alice (the issuer) receives the full 1_000 supply.
        let mut events = VecEventSink::new();
        let create = Transaction::from(nunchi_coins::Transaction::sign(
            &alice,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new(
                    TokenSymbol::new("NCH").unwrap(),
                    TokenName::new("Nunchi").unwrap(),
                    9,
                    1_000,
                    None,
                ),
            },
        ));
        CoinsRuntime::apply(&mut state, RuntimeContext::default(), &create, &mut events)
            .await
            .unwrap();
        let coin = TokenCreated::decode(events.events()[0].value.as_ref())
            .unwrap()
            .token
            .id;

        // Pin the bridge chain id, then lock 400 to a destination chain.
        let local_chain = ChainId(Sha256::hash(b"local-chain"));
        BridgeGenesis::new(local_chain).apply(&mut state);
        let dest = ChainId(Sha256::hash(b"dest-chain"));
        let recipient = Address::external(&PrivateKey::ed25519_from_seed(2).public_key());
        let lock = Transaction::from(BridgeTransaction::sign(
            &alice,
            0,
            BridgeOperation::Lock {
                destination_chain_id: dest,
                local_asset: coin.0,
                amount: 400,
                recipient: recipient.clone(),
            },
        ));
        CoinsRuntime::apply(
            &mut state,
            RuntimeContext::default(),
            &lock,
            &mut VecEventSink::new(),
        )
        .await
        .unwrap();

        // The lock actually moved 400 from alice into the bridge-owned escrow; supply is preserved.
        let (alice_bal, escrow_bal) = {
            let ledger = Ledger::new(&mut state);
            (
                ledger.balance(&alice_addr, &coin).await.unwrap(),
                ledger.balance(&escrow_address(), &coin).await.unwrap(),
            )
        };
        assert_eq!(alice_bal, 600);
        assert_eq!(escrow_bal, 400);

        // The transfer record was written to bridge state, atomically with the escrow.
        let expected = BridgeTransferRecord {
            source_chain_id: local_chain,
            destination_chain_id: dest,
            source_asset: AssetId::derive(&local_chain, &coin.0),
            amount: 400,
            sender: alice_addr,
            recipient,
            nonce: 0,
        };
        assert_eq!(
            transfer_record(&state, &expected.record_id()).await.unwrap(),
            Some(expected)
        );
    });
}

#[test]
fn bridge_lock_reverts_escrow_when_bridge_rejects() {
    // Alice can afford the escrow, but the bridge stage fails (wrong nonce). The escrow move and
    // the record write share an inner overlay, so the whole lock reverts atomically: no partial
    // escrow is left behind even though the coins transfer ran before the bridge validation.
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-lock-atomic").await.unwrap();
        let alice = PrivateKey::ed25519_from_seed(1);
        let alice_addr = Address::external(&alice.public_key());

        let mut events = VecEventSink::new();
        let create = Transaction::from(nunchi_coins::Transaction::sign(
            &alice,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new(
                    TokenSymbol::new("NCH").unwrap(),
                    TokenName::new("Nunchi").unwrap(),
                    9,
                    1_000,
                    None,
                ),
            },
        ));
        CoinsRuntime::apply(&mut state, RuntimeContext::default(), &create, &mut events)
            .await
            .unwrap();
        let coin = TokenCreated::decode(events.events()[0].value.as_ref())
            .unwrap()
            .token
            .id;

        let local_chain = ChainId(Sha256::hash(b"local-chain"));
        BridgeGenesis::new(local_chain).apply(&mut state);
        let dest = ChainId(Sha256::hash(b"dest-chain"));
        let recipient = Address::external(&PrivateKey::ed25519_from_seed(2).public_key());

        // Sufficient balance, but a wrong bridge nonce (expected 0, given 5).
        let lock = Transaction::from(BridgeTransaction::sign(
            &alice,
            5,
            BridgeOperation::Lock {
                destination_chain_id: dest,
                local_asset: coin.0,
                amount: 400,
                recipient: recipient.clone(),
            },
        ));
        let result = CoinsRuntime::apply(
            &mut state,
            RuntimeContext::default(),
            &lock,
            &mut VecEventSink::new(),
        )
        .await;
        assert!(matches!(result, Err(RuntimeError::Bridge(_))));

        // The escrow was rolled back with the failed lock: no side effects.
        let (alice_bal, escrow_bal) = {
            let ledger = Ledger::new(&mut state);
            (
                ledger.balance(&alice_addr, &coin).await.unwrap(),
                ledger.balance(&escrow_address(), &coin).await.unwrap(),
            )
        };
        assert_eq!(alice_bal, 1_000);
        assert_eq!(escrow_bal, 0);

        let record = BridgeTransferRecord {
            source_chain_id: local_chain,
            destination_chain_id: dest,
            source_asset: AssetId::derive(&local_chain, &coin.0),
            amount: 400,
            sender: alice_addr,
            recipient,
            nonce: 5,
        };
        assert_eq!(
            transfer_record(&state, &record.record_id()).await.unwrap(),
            None
        );
    });
}

#[test]
fn runtime_rejects_transaction_that_cannot_pay_fee() {
    deterministic::Runner::default().start(|context| async move {
        let alice = Address::external(&PrivateKey::ed25519_from_seed(1).public_key());
        let bob_key = PrivateKey::ed25519_from_seed(2);
        let bob = Address::external(&bob_key.public_key());
        let collector = Address::external(&PrivateKey::ed25519_from_seed(9).public_key());

        let genesis = fee_genesis(alice.clone(), collector, 7, 3);
        let mut state = fee_state(context, "coins-runtime-fees-unpayable", &genesis).await;
        let coin = TokenFactory::derive_coin_id(&alice, 0, &genesis.tokens[0].spec);

        // Bob holds no fee coin, so the ante rejects the transaction before dispatch.
        let tx = Transaction::from(nunchi_coins::Transaction::sign(
            &bob_key,
            0,
            CoinOperation::Transfer {
                coin,
                from: bob.clone(),
                to: alice,
                amount: 1,
            },
        ));
        let err = CoinsRuntime::validate(&mut state, RuntimeContext::default(), &tx)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RuntimeError::Coins(LedgerError::InsufficientBalance { .. })
        ));
    });
}

#[test]
fn bridge_lock_rejects_insufficient_balance_without_side_effects() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-lock-insufficient")
            .await
            .unwrap();
        let alice = PrivateKey::ed25519_from_seed(1);
        let alice_addr = Address::external(&alice.public_key());

        let mut events = VecEventSink::new();
        let create = Transaction::from(nunchi_coins::Transaction::sign(
            &alice,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new(
                    TokenSymbol::new("NCH").unwrap(),
                    TokenName::new("Nunchi").unwrap(),
                    9,
                    1_000,
                    None,
                ),
            },
        ));
        CoinsRuntime::apply(&mut state, RuntimeContext::default(), &create, &mut events)
            .await
            .unwrap();
        let coin = TokenCreated::decode(events.events()[0].value.as_ref())
            .unwrap()
            .token
            .id;

        let local_chain = ChainId(Sha256::hash(b"local-chain"));
        BridgeGenesis::new(local_chain).apply(&mut state);
        let dest = ChainId(Sha256::hash(b"dest-chain"));
        let recipient = Address::external(&PrivateKey::ed25519_from_seed(2).public_key());

        // Lock more than alice holds: the escrow debit fails before any write.
        let lock = Transaction::from(BridgeTransaction::sign(
            &alice,
            0,
            BridgeOperation::Lock {
                destination_chain_id: dest,
                local_asset: coin.0,
                amount: 2_000,
                recipient: recipient.clone(),
            },
        ));
        let result = CoinsRuntime::apply(
            &mut state,
            RuntimeContext::default(),
            &lock,
            &mut VecEventSink::new(),
        )
        .await;
        assert!(matches!(result, Err(RuntimeError::Coins(_))));

        // No escrow move and no record: the failing lock left no side effects.
        let (alice_bal, escrow_bal) = {
            let ledger = Ledger::new(&mut state);
            (
                ledger.balance(&alice_addr, &coin).await.unwrap(),
                ledger.balance(&escrow_address(), &coin).await.unwrap(),
            )
        };
        assert_eq!(alice_bal, 1_000);
        assert_eq!(escrow_bal, 0);

        let record = BridgeTransferRecord {
            source_chain_id: local_chain,
            destination_chain_id: dest,
            source_asset: AssetId::derive(&local_chain, &coin.0),
            amount: 2_000,
            sender: alice_addr,
            recipient,
            nonce: 0,
        };
        assert_eq!(
            transfer_record(&state, &record.record_id()).await.unwrap(),
            None
        );
    });
}
