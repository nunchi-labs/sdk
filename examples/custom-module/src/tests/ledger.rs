use super::MemoryState;
use crate::{CustomLedger, CustomOperation, Transaction};
use nunchi_common::{Address, NoopEventSink};
use nunchi_crypto::PrivateKey;

#[test]
fn ledger_applies_signed_transactions() {
    let mut state = MemoryState::default();
    futures::executor::block_on(async {
        let signer = PrivateKey::ed25519_from_seed(1);
        let account = Address::external(&signer.public_key());
        let set = Transaction::sign(&signer, 0, CustomOperation::SetValue { value: 42 });
        let clear = Transaction::sign(&signer, 1, CustomOperation::ClearValue);

        let mut ledger = CustomLedger::new(&mut state);
        ledger.apply_transaction(&set, NoopEventSink).await.unwrap();
        assert_eq!(ledger.value(&account).await.unwrap(), Some(42));
        assert_eq!(ledger.nonce(&account).await.unwrap(), 1);

        ledger.apply_transaction(&clear, NoopEventSink).await.unwrap();
        assert_eq!(ledger.value(&account).await.unwrap(), None);
        assert_eq!(ledger.nonce(&account).await.unwrap(), 2);
    });
}
