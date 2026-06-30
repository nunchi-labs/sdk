use super::MemoryState;
use crate::{
    CustomDB, CustomError, CustomLedger, CustomOperation, Transaction, ValueCleared, ValueSet,
    VALUE_CLEARED_EVENT, VALUE_SET_EVENT,
};
use commonware_codec::DecodeExt;
use nunchi_common::{Address, NoopEventSink, VecEventSink};
use nunchi_crypto::{PrivateKey, SignatureError};

fn address(key: &PrivateKey) -> Address {
    Address::external(&key.public_key())
}

fn event_sink() -> VecEventSink {
    VecEventSink::new()
}

#[test]
fn set_value_emits_event() {
    let mut state = MemoryState::default();
    futures::executor::block_on(async {
        let signer = PrivateKey::ed25519_from_seed(1);
        let account = address(&signer);
        let tx = Transaction::sign(&signer, 0, CustomOperation::SetValue { value: 42 });
        let mut ledger = CustomLedger::new(&mut state);
        let mut events = event_sink();

        ledger.apply_transaction(&tx, &mut events).await.unwrap();

        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        assert_eq!(event.name.as_ref(), VALUE_SET_EVENT);
        assert_eq!(
            ValueSet::decode(event.value.as_ref()).unwrap(),
            ValueSet {
                account_id: account,
                value: 42,
            }
        );
    });
}

#[test]
fn clear_value_emits_event() {
    let mut state = MemoryState::default();
    futures::executor::block_on(async {
        let signer = PrivateKey::ed25519_from_seed(1);
        let account = address(&signer);
        let set = Transaction::sign(&signer, 0, CustomOperation::SetValue { value: 42 });
        let clear = Transaction::sign(&signer, 1, CustomOperation::ClearValue);
        let mut ledger = CustomLedger::new(&mut state);
        let mut events = event_sink();

        ledger.apply_transaction(&set, NoopEventSink).await.unwrap();
        ledger
            .apply_transaction(&clear, &mut events)
            .await
            .unwrap();

        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        assert_eq!(event.name.as_ref(), VALUE_CLEARED_EVENT);
        assert_eq!(
            ValueCleared::decode(event.value.as_ref()).unwrap(),
            ValueCleared {
                account_id: account,
            }
        );
    });
}

#[test]
fn events_are_recorded_in_application_order() {
    let mut state = MemoryState::default();
    futures::executor::block_on(async {
        let signer = PrivateKey::ed25519_from_seed(1);
        let set = Transaction::sign(&signer, 0, CustomOperation::SetValue { value: 42 });
        let clear = Transaction::sign(&signer, 1, CustomOperation::ClearValue);
        let mut ledger = CustomLedger::new(&mut state);
        let mut events = event_sink();

        ledger.apply_transaction(&set, &mut events).await.unwrap();
        ledger
            .apply_transaction(&clear, &mut events)
            .await
            .unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events.events()[0].name.as_ref(), VALUE_SET_EVENT);
        assert_eq!(events.events()[1].name.as_ref(), VALUE_CLEARED_EVENT);
    });
}

#[test]
fn failed_transactions_emit_no_events() {
    let mut state = MemoryState::default();
    futures::executor::block_on(async {
        let signer = PrivateKey::ed25519_from_seed(1);
        let account = address(&signer);
        let mut ledger = CustomLedger::new(&mut state);

        let mut bad_signature =
            Transaction::sign(&signer, 0, CustomOperation::SetValue { value: 1 });
        bad_signature.payload.operation = CustomOperation::SetValue { value: 2 };
        assert_no_event(
            &mut ledger,
            &bad_signature,
            CustomError::BadSignature(SignatureError::InvalidSignature),
        )
        .await;

        let wrong_nonce = Transaction::sign(&signer, 5, CustomOperation::SetValue { value: 1 });
        let mut events = event_sink();
        assert!(matches!(
            ledger.apply_transaction(&wrong_nonce, &mut events).await,
            Err(CustomError::NonceMismatch {
                expected: 0,
                actual: 5,
                ..
            })
        ));
        assert!(events.is_empty());
        assert_eq!(ledger.value(&account).await.unwrap(), None);
    });
}

#[test]
fn nonce_overflow_emits_no_event_and_leaves_value_unchanged() {
    let mut state = MemoryState::default();
    futures::executor::block_on(async {
        let signer = PrivateKey::ed25519_from_seed(1);
        let account = address(&signer);
        let tx = Transaction::sign(
            &signer,
            u64::MAX,
            CustomOperation::SetValue { value: 99 },
        );
        let mut ledger = CustomLedger::new(&mut state);
        ledger.db.set_nonce(&account, u64::MAX);
        ledger.db.set_value(&account, 7);
        let mut events = event_sink();

        assert_eq!(
            ledger.apply_transaction(&tx, &mut events).await,
            Err(CustomError::NonceOverflow)
        );
        assert!(events.is_empty());
        assert_eq!(ledger.value(&account).await.unwrap(), Some(7));
        assert_eq!(ledger.nonce(&account).await.unwrap(), u64::MAX);
    });
}

#[test]
fn none_event_sink_applies_transaction() {
    let mut state = MemoryState::default();
    futures::executor::block_on(async {
        let signer = PrivateKey::ed25519_from_seed(1);
        let account = address(&signer);
        let tx = Transaction::sign(&signer, 0, CustomOperation::SetValue { value: 42 });
        let mut ledger = CustomLedger::new(&mut state);

        ledger.apply_transaction(&tx, NoopEventSink).await.unwrap();

        assert_eq!(ledger.value(&account).await.unwrap(), Some(42));
        assert_eq!(ledger.nonce(&account).await.unwrap(), 1);
    });
}

async fn assert_no_event(
    ledger: &mut CustomLedger<&mut MemoryState>,
    tx: &Transaction,
    expected: CustomError,
) {
    let mut events = event_sink();
    assert_eq!(
        ledger.apply_transaction(tx, &mut events).await,
        Err(expected)
    );
    assert!(events.is_empty());
}
