use super::{address, ledger};
use crate::{
    AccessControlDB, AccessControlError, AccessControlOperation, RoleId, ScopeId, Transaction,
};
use commonware_runtime::{deterministic, Runner as _};
use nunchi_common::Address;
use nunchi_crypto::PrivateKey;

const WRITER: RoleId = RoleId::new(1);
const ADMIN: RoleId = RoleId::new(2);

fn grant(scope: ScopeId, role: RoleId, account: Address) -> AccessControlOperation {
    AccessControlOperation::GrantRole {
        scope,
        role,
        account,
    }
}

#[test]
fn owner_grants_and_revokes_exact_roles() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let owner_key = PrivateKey::ed25519_from_seed(1);
        let owner = address(&owner_key);
        let member = address(&PrivateKey::ed25519_from_seed(2));
        let scope = ScopeId::module(b"example");
        let other_scope = ScopeId::module(b"other");

        let empty_root = ledger.root();
        ledger.register_scope(scope, owner.clone()).await.unwrap();
        assert!(ledger.is_scope_owner(&owner, &scope).await.unwrap());
        assert!(!ledger.has_role(&owner, &scope, WRITER).await.unwrap());

        let tx = Transaction::sign(&owner_key, 0, grant(scope, WRITER, member.clone()));
        ledger.apply_transaction(&tx).await.unwrap();
        assert!(ledger.has_role(&member, &scope, WRITER).await.unwrap());
        assert!(!ledger.has_role(&member, &scope, ADMIN).await.unwrap());
        assert!(!ledger
            .has_role(&member, &other_scope, WRITER)
            .await
            .unwrap());

        let revoke = Transaction::sign(
            &owner_key,
            1,
            AccessControlOperation::RevokeRole {
                scope,
                role: WRITER,
                account: member.clone(),
            },
        );
        ledger.apply_transaction(&revoke).await.unwrap();
        assert!(!ledger.has_role(&member, &scope, WRITER).await.unwrap());
        assert_eq!(ledger.nonce(&owner).await.unwrap(), 2);

        let root = ledger.commit().await.unwrap();
        assert_ne!(root, empty_root);
    });
}

#[test]
fn unauthorized_management_leaves_state_and_nonce_unchanged() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let owner = address(&PrivateKey::ed25519_from_seed(1));
        let attacker_key = PrivateKey::ed25519_from_seed(2);
        let attacker = address(&attacker_key);
        let member = address(&PrivateKey::ed25519_from_seed(3));
        let scope = ScopeId::module(b"example");
        ledger.register_scope(scope, owner).await.unwrap();

        let tx = Transaction::sign(&attacker_key, 0, grant(scope, WRITER, member.clone()));
        assert_eq!(
            ledger.apply_transaction(&tx).await,
            Err(AccessControlError::Unauthorized {
                scope,
                account: Box::new(attacker.clone()),
            })
        );
        assert_eq!(ledger.nonce(&attacker).await.unwrap(), 0);
        assert!(!ledger.has_role(&member, &scope, WRITER).await.unwrap());
    });
}

#[test]
fn duplicate_grants_and_missing_revocations_fail() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let owner_key = PrivateKey::ed25519_from_seed(1);
        let owner = address(&owner_key);
        let member = address(&PrivateKey::ed25519_from_seed(2));
        let scope = ScopeId::module(b"example");
        ledger.register_scope(scope, owner.clone()).await.unwrap();

        let operation = grant(scope, WRITER, member.clone());
        ledger
            .apply_transaction(&Transaction::sign(&owner_key, 0, operation.clone()))
            .await
            .unwrap();
        assert_eq!(
            ledger
                .apply_transaction(&Transaction::sign(&owner_key, 1, operation),)
                .await,
            Err(AccessControlError::RoleAlreadyGranted {
                scope,
                role: WRITER,
                account: Box::new(member.clone()),
            })
        );
        assert_eq!(ledger.nonce(&owner).await.unwrap(), 1);

        let missing = AccessControlOperation::RevokeRole {
            scope,
            role: ADMIN,
            account: member.clone(),
        };
        assert_eq!(
            ledger
                .apply_transaction(&Transaction::sign(&owner_key, 1, missing),)
                .await,
            Err(AccessControlError::RoleNotGranted {
                scope,
                role: ADMIN,
                account: Box::new(member),
            })
        );
        assert_eq!(ledger.nonce(&owner).await.unwrap(), 1);
    });
}

#[test]
fn multisig_management_is_rejected_safely() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = PrivateKey::ed25519_from_seed(1);
        let bob = PrivateKey::ed25519_from_seed(2);
        let policy =
            nunchi_common::MultisigPolicy::new(2, vec![alice.public_key(), bob.public_key()])
                .unwrap();
        let owner = Address::multisig(&policy);
        let scope = ScopeId::module(b"example");
        let member = address(&PrivateKey::ed25519_from_seed(3));
        ledger.register_scope(scope, owner.clone()).await.unwrap();

        let tx = Transaction::sign_multisig(
            owner.clone(),
            policy,
            &[&alice, &bob],
            0,
            grant(scope, WRITER, member.clone()),
        );
        assert!(tx.verify().is_ok());
        assert_eq!(
            ledger.apply_transaction(&tx).await,
            Err(AccessControlError::UnsupportedAuthorization)
        );
        assert_eq!(ledger.nonce(&owner).await.unwrap(), 0);
        assert!(!ledger.has_role(&member, &scope, WRITER).await.unwrap());
    });
}

#[test]
fn nonce_overflow_precedes_mutation() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let owner_key = PrivateKey::ed25519_from_seed(1);
        let owner = address(&owner_key);
        let member = address(&PrivateKey::ed25519_from_seed(2));
        let scope = ScopeId::module(b"example");
        ledger.register_scope(scope, owner.clone()).await.unwrap();
        ledger.db.set_nonce(&owner, u64::MAX);

        let tx = Transaction::sign(&owner_key, u64::MAX, grant(scope, WRITER, member.clone()));
        assert_eq!(
            ledger.apply_transaction(&tx).await,
            Err(AccessControlError::NonceOverflow)
        );
        assert!(!ledger.has_role(&member, &scope, WRITER).await.unwrap());
    });
}
