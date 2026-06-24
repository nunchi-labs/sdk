use crate::{CustomLedger, CustomOperation, Transaction};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, StateError, StateStore};
use nunchi_crypto::PrivateKey;
use std::collections::BTreeMap;

#[derive(Default)]
struct MemoryState {
    values: BTreeMap<Digest, Vec<u8>>,
}

impl StateStore for MemoryState {
    async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.values.get(key).cloned())
    }

    fn set(&mut self, key: Digest, value: Vec<u8>) {
        self.values.insert(key, value);
    }

    fn remove(&mut self, key: Digest) {
        self.values.remove(&key);
    }
}

#[test]
fn operation_codec_uses_stable_tags() {
    let set = CustomOperation::SetValue { value: 7 };
    let clear = CustomOperation::ClearValue;

    assert_eq!(set.encode()[0], 0);
    assert_eq!(clear.encode()[0], 1);
    assert_eq!(CustomOperation::decode(set.encode()).unwrap(), set);
    assert_eq!(CustomOperation::decode(clear.encode()).unwrap(), clear);
    assert!(CustomOperation::decode([99].as_slice()).is_err());
}

#[test]
fn ledger_applies_signed_transactions() {
    let mut state = MemoryState::default();
    futures::executor::block_on(async {
        let signer = PrivateKey::ed25519_from_seed(1);
        let account = Address::external(&signer.public_key());
        let set = Transaction::sign(&signer, 0, CustomOperation::SetValue { value: 42 });
        let clear = Transaction::sign(&signer, 1, CustomOperation::ClearValue);

        let mut ledger = CustomLedger::new(&mut state);
        ledger.apply_transaction(&set).await.unwrap();
        assert_eq!(ledger.value(&account).await.unwrap(), Some(42));
        assert_eq!(ledger.nonce(&account).await.unwrap(), 1);

        ledger.apply_transaction(&clear).await.unwrap();
        assert_eq!(ledger.value(&account).await.unwrap(), None);
        assert_eq!(ledger.nonce(&account).await.unwrap(), 2);
    });
}
