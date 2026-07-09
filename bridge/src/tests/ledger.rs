use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256, Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _};
use nunchi_common::{
    state_db::CommitState, Address, MultisigPolicy, NoopEventSink, QmdbState, VecEventSink,
};
use nunchi_crypto::PrivateKey;

use crate::events::{TransferLocked, TRANSFER_LOCKED_EVENT};
use crate::genesis::BridgeGenesis;
use crate::ledger::{BridgeError, BridgeLedger};
use crate::record::{bridge_nonce, transfer_record, AssetId, BridgeTransferRecord, ChainId};
use crate::transaction::{BridgeOperation, Transaction};

fn signer(seed: u64) -> PrivateKey {
    PrivateKey::from_seed(seed)
}

fn addr(key: &PrivateKey) -> Address {
    Address::external(&key.public_key())
}

fn local_chain() -> ChainId {
    ChainId(Sha256::hash(b"local-chain"))
}

fn dest_chain() -> ChainId {
    ChainId(Sha256::hash(b"dest-chain"))
}

fn coin() -> sha256::Digest {
    Sha256::hash(b"coin")
}

fn lock_tx(
    signer: &PrivateKey,
    nonce: u64,
    destination: ChainId,
    local_asset: sha256::Digest,
    amount: u128,
    recipient: Address,
) -> Transaction {
    Transaction::sign(
        signer,
        nonce,
        BridgeOperation::Lock {
            destination_chain_id: destination,
            local_asset,
            amount,
            recipient,
        },
    )
}

#[test]
fn lock_writes_record_and_advances_nonce() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-lock-record-test")
            .await
            .expect("init state");
        BridgeGenesis::new(local_chain()).apply(&mut state);

        let alice = signer(1);
        let recipient = addr(&signer(2));
        let mut ledger = BridgeLedger::new(state);

        // Two identical transfers from the same sender differ only by nonce, and so get distinct
        // content-addressed record ids.
        let id0 = ledger
            .apply_transaction(
                &lock_tx(&alice, 0, dest_chain(), coin(), 1_000, recipient.clone()),
                NoopEventSink,
            )
            .await
            .expect("first lock");
        let id1 = ledger
            .apply_transaction(
                &lock_tx(&alice, 1, dest_chain(), coin(), 1_000, recipient.clone()),
                NoopEventSink,
            )
            .await
            .expect("second lock");
        assert_ne!(id0, id1);

        let expected = BridgeTransferRecord {
            source_chain_id: local_chain(),
            destination_chain_id: dest_chain(),
            source_asset: AssetId::derive(&local_chain(), &coin()),
            amount: 1_000,
            sender: addr(&alice),
            recipient,
            nonce: 0,
        };
        assert_eq!(id0, expected.record_id());

        let mut state = ledger.into_inner();
        state.commit().await.expect("commit");

        assert_eq!(
            transfer_record(&state, &id0).await.expect("read"),
            Some(expected)
        );
        assert!(transfer_record(&state, &id1).await.expect("read").is_some());
        assert_eq!(bridge_nonce(&state, &addr(&alice)).await.expect("nonce"), 2);
    });
}

#[test]
fn lock_emits_transfer_locked_event() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-lock-event-test")
            .await
            .expect("init state");
        BridgeGenesis::new(local_chain()).apply(&mut state);

        let alice = signer(1);
        let recipient = addr(&signer(2));
        let mut ledger = BridgeLedger::new(state);

        let mut sink = VecEventSink::new();
        let record_id = ledger
            .apply_transaction(
                &lock_tx(&alice, 0, dest_chain(), coin(), 500, recipient.clone()),
                &mut sink,
            )
            .await
            .expect("lock");

        assert_eq!(sink.len(), 1);
        let event = &sink.events()[0];
        assert_eq!(event.name.as_ref(), TRANSFER_LOCKED_EVENT);
        let decoded = TransferLocked::decode(event.value.as_ref()).expect("decode event");
        assert_eq!(decoded.record_id, record_id);
        assert_eq!(decoded.source_chain_id, local_chain());
        assert_eq!(decoded.destination_chain_id, dest_chain());
        assert_eq!(decoded.source_asset, AssetId::derive(&local_chain(), &coin()));
        assert_eq!(decoded.amount, 500);
        assert_eq!(decoded.sender, addr(&alice));
        assert_eq!(decoded.recipient, recipient);
        assert_eq!(decoded.nonce, 0);
    });
}

#[test]
fn lock_rejects_wrong_nonce() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-lock-nonce-test")
            .await
            .expect("init state");
        BridgeGenesis::new(local_chain()).apply(&mut state);

        let alice = signer(1);
        let mut ledger = BridgeLedger::new(state);

        // Expected nonce is 0; a transaction claiming nonce 1 is rejected.
        let err = ledger
            .apply_transaction(
                &lock_tx(&alice, 1, dest_chain(), coin(), 1_000, addr(&signer(2))),
                NoopEventSink,
            )
            .await
            .expect_err("wrong nonce");
        assert_eq!(
            err,
            BridgeError::NonceMismatch {
                expected: 0,
                actual: 1
            }
        );
    });
}

#[test]
fn lock_rejects_zero_amount() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-lock-amount-test")
            .await
            .expect("init state");
        BridgeGenesis::new(local_chain()).apply(&mut state);

        let alice = signer(1);
        let mut ledger = BridgeLedger::new(state);
        let err = ledger
            .apply_transaction(
                &lock_tx(&alice, 0, dest_chain(), coin(), 0, addr(&signer(2))),
                NoopEventSink,
            )
            .await
            .expect_err("zero amount");
        assert_eq!(err, BridgeError::InvalidAmount);
    });
}

#[test]
fn lock_rejects_self_bridge() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-lock-self-test")
            .await
            .expect("init state");
        BridgeGenesis::new(local_chain()).apply(&mut state);

        let alice = signer(1);
        let mut ledger = BridgeLedger::new(state);
        // Destination equals this chain.
        let err = ledger
            .apply_transaction(
                &lock_tx(&alice, 0, local_chain(), coin(), 1_000, addr(&signer(2))),
                NoopEventSink,
            )
            .await
            .expect_err("self bridge");
        assert_eq!(err, BridgeError::SelfBridge);
    });
}

#[test]
fn lock_rejects_when_chain_not_configured() {
    deterministic::Runner::default().start(|context| async move {
        // No BridgeGenesis applied: local chain id is unset.
        let state = QmdbState::init(context, "bridge-lock-unconfigured-test")
            .await
            .expect("init state");

        let alice = signer(1);
        let mut ledger = BridgeLedger::new(state);
        let err = ledger
            .apply_transaction(
                &lock_tx(&alice, 0, dest_chain(), coin(), 1_000, addr(&signer(2))),
                NoopEventSink,
            )
            .await
            .expect_err("unconfigured");
        assert_eq!(err, BridgeError::ChainNotConfigured);
    });
}

#[test]
fn lock_rejects_bad_signature() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-lock-signature-test")
            .await
            .expect("init state");
        BridgeGenesis::new(local_chain()).apply(&mut state);

        let alice = signer(1);
        let mut ledger = BridgeLedger::new(state);

        // Tamper the operation after signing so the signature no longer matches.
        let mut tx = lock_tx(&alice, 0, dest_chain(), coin(), 1_000, addr(&signer(2)));
        let BridgeOperation::Lock { amount, .. } = &mut tx.payload.operation;
        *amount += 1;
        let err = ledger
            .apply_transaction(&tx, NoopEventSink)
            .await
            .expect_err("bad signature");
        assert!(matches!(err, BridgeError::BadSignature(_)));
    });
}

#[test]
fn lock_rejects_multisig_authorization() {
    // Multisig authorization is rejected outright: `tx.verify()` does not bind `account_id` to the
    // policy, so accepting a transaction-supplied policy would be a fund-drain vector. The
    // transaction below is a valid 2-of-2 multisig (signatures verify), so the rejection comes from
    // the authorization-kind check, not a bad signature.
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-lock-multisig-test")
            .await
            .expect("init state");
        BridgeGenesis::new(local_chain()).apply(&mut state);

        let a = signer(1);
        let b = signer(2);
        let policy = MultisigPolicy::new(2, vec![a.public_key(), b.public_key()]).unwrap();
        let account = Address::multisig(&policy);
        let tx = Transaction::sign_multisig(
            account,
            policy,
            &[&a, &b],
            0,
            BridgeOperation::Lock {
                destination_chain_id: dest_chain(),
                local_asset: coin(),
                amount: 1_000,
                recipient: addr(&signer(3)),
            },
        );

        let mut ledger = BridgeLedger::new(state);
        let err = ledger
            .apply_transaction(&tx, NoopEventSink)
            .await
            .expect_err("multisig rejected");
        assert_eq!(err, BridgeError::UnsupportedAuthorization);
    });
}

#[test]
fn operation_and_transaction_codec_round_trip() {
    let op = BridgeOperation::Lock {
        destination_chain_id: dest_chain(),
        local_asset: coin(),
        amount: 42,
        recipient: addr(&signer(3)),
    };
    assert_eq!(
        BridgeOperation::decode(op.encode().as_ref()).expect("decode op"),
        op
    );

    let tx = lock_tx(&signer(1), 5, dest_chain(), coin(), 42, addr(&signer(3)));
    assert_eq!(
        Transaction::decode(tx.encode().as_ref()).expect("decode tx"),
        tx
    );
}
