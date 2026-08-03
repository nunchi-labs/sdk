use super::{address, ledger};
use crate::{
    AccessControlOperation, RoleGranted, RoleId, ScopeId, ScopeRegistered, Transaction,
    ROLE_GRANTED_EVENT, SCOPE_REGISTERED_EVENT,
};
use commonware_codec::DecodeExt;
use commonware_runtime::{deterministic, Runner as _};
use nunchi_common::VecEventSink;
use nunchi_crypto::PrivateKey;

#[test]
fn registration_and_role_changes_emit_decodable_events() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let owner_key = PrivateKey::ed25519_from_seed(1);
        let owner = address(&owner_key);
        let member = address(&PrivateKey::ed25519_from_seed(2));
        let scope = ScopeId::module(b"example");
        let role = RoleId::new(7);
        let mut events = VecEventSink::new();

        ledger
            .register_scope(scope, owner.clone(), &mut events)
            .await
            .unwrap();
        let grant = Transaction::sign(
            &owner_key,
            0,
            AccessControlOperation::GrantRole {
                scope,
                role,
                account: member.clone(),
            },
        );
        ledger
            .apply_transaction(&grant, &mut events)
            .await
            .unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events.events()[0].name.as_ref(), SCOPE_REGISTERED_EVENT);
        assert_eq!(
            ScopeRegistered::decode(events.events()[0].value.as_ref()).unwrap(),
            ScopeRegistered {
                scope,
                owner: owner.clone(),
            }
        );
        assert_eq!(events.events()[1].name.as_ref(), ROLE_GRANTED_EVENT);
        assert_eq!(
            RoleGranted::decode(events.events()[1].value.as_ref()).unwrap(),
            RoleGranted {
                scope,
                role,
                account: member,
                granted_by: owner,
            }
        );
    });
}

#[test]
fn idempotent_scope_registration_emits_once() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let owner = address(&PrivateKey::ed25519_from_seed(1));
        let scope = ScopeId::module(b"example");
        let mut events = VecEventSink::new();

        ledger
            .register_scope(scope, owner.clone(), &mut events)
            .await
            .unwrap();
        ledger
            .register_scope(scope, owner, &mut events)
            .await
            .unwrap();

        assert_eq!(events.len(), 1);
    });
}
