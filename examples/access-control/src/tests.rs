use crate::{
    apply_transaction, counter_scope, initialize, ApplicationTransaction, CounterError,
    CounterLedger, CounterOperation, RuntimeError, Transaction as CounterTransaction,
    RESETTER_ROLE,
};
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{deterministic, Runner as _};
use nunchi_access_control::{
    AccessControlOperation, Transaction as AccessControlTransaction,
};
use nunchi_common::{Address, NoopEventSink, StateError, StateStore};
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

fn address(key: &PrivateKey) -> Address {
    Address::external(&key.public_key())
}

#[test]
fn counter_owns_its_access_policy() {
    deterministic::Runner::default().start(|_| async move {
        let owner_key = PrivateKey::ed25519_from_seed(1);
        let owner = address(&owner_key);
        let resetter_key = PrivateKey::ed25519_from_seed(2);
        let resetter = address(&resetter_key);
        let user_key = PrivateKey::ed25519_from_seed(3);
        let user = address(&user_key);
        let mut state = MemoryState::default();

        initialize(&mut state, owner, NoopEventSink).await.unwrap();

        let increment = CounterTransaction::sign(&user_key, 0, CounterOperation::Increment);
        apply_transaction(
            &mut state,
            &ApplicationTransaction::from(increment),
            NoopEventSink,
        )
        .await
        .unwrap();

        let denied = CounterTransaction::sign(
            &user_key,
            1,
            CounterOperation::Reset { value: 10 },
        );
        assert!(matches!(
            apply_transaction(
                &mut state,
                &ApplicationTransaction::from(denied),
                NoopEventSink,
            )
            .await,
            Err(RuntimeError::Counter(CounterError::Unauthorized(_)))
        ));

        let grant = AccessControlTransaction::sign(
            &owner_key,
            0,
            AccessControlOperation::GrantRole {
                scope: counter_scope(),
                role: RESETTER_ROLE,
                account: resetter.clone(),
            },
        );
        apply_transaction(
            &mut state,
            &ApplicationTransaction::from(grant),
            NoopEventSink,
        )
        .await
        .unwrap();

        let reset = CounterTransaction::sign(
            &resetter_key,
            0,
            CounterOperation::Reset { value: 10 },
        );
        apply_transaction(
            &mut state,
            &ApplicationTransaction::from(reset),
            NoopEventSink,
        )
        .await
        .unwrap();

        let increment = CounterTransaction::sign(&user_key, 1, CounterOperation::Increment);
        apply_transaction(
            &mut state,
            &ApplicationTransaction::from(increment),
            NoopEventSink,
        )
        .await
        .unwrap();

        let revoke = AccessControlTransaction::sign(
            &owner_key,
            1,
            AccessControlOperation::RevokeRole {
                scope: counter_scope(),
                role: RESETTER_ROLE,
                account: resetter.clone(),
            },
        );
        apply_transaction(
            &mut state,
            &ApplicationTransaction::from(revoke),
            NoopEventSink,
        )
        .await
        .unwrap();

        let revoked = CounterTransaction::sign(
            &resetter_key,
            1,
            CounterOperation::Reset { value: 99 },
        );
        assert!(matches!(
            apply_transaction(
                &mut state,
                &ApplicationTransaction::from(revoked),
                NoopEventSink,
            )
            .await,
            Err(RuntimeError::Counter(CounterError::Unauthorized(_)))
        ));

        let counter = CounterLedger::new(&mut state);
        assert_eq!(counter.value().await.unwrap(), 11);
        assert_eq!(counter.nonce(&user).await.unwrap(), 2);
        assert_eq!(counter.nonce(&resetter).await.unwrap(), 1);
    });
}
