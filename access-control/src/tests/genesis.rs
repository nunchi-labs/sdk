use super::{address, ledger};
use crate::{
    AccessControlError, AccessControlGenesis, RoleGrantGenesis, RoleId, ScopeGenesis, ScopeId,
};
use commonware_runtime::{deterministic, Runner as _};
use nunchi_crypto::PrivateKey;

#[test]
fn genesis_registers_scopes_and_roles() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let owner = address(&PrivateKey::ed25519_from_seed(1));
        let member = address(&PrivateKey::ed25519_from_seed(2));
        let scope = ScopeId::resource(b"example", b"resource");
        let role = RoleId::new(9);
        let genesis = AccessControlGenesis {
            scopes: vec![ScopeGenesis {
                scope,
                owner: owner.clone(),
            }],
            grants: vec![RoleGrantGenesis {
                scope,
                role: role.get(),
                account: member.clone(),
            }],
        };

        ledger.apply_genesis(&genesis).await.unwrap();

        assert!(ledger.is_scope_owner(&owner, &scope).await.unwrap());
        assert!(ledger.has_role(&member, &scope, role).await.unwrap());
    });
}

#[test]
fn invalid_genesis_is_rejected_before_writes() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let owner = address(&PrivateKey::ed25519_from_seed(1));
        let known = ScopeId::module(b"known");
        let unknown = ScopeId::module(b"unknown");
        let genesis = AccessControlGenesis {
            scopes: vec![ScopeGenesis {
                scope: known,
                owner: owner.clone(),
            }],
            grants: vec![RoleGrantGenesis {
                scope: unknown,
                role: 1,
                account: owner,
            }],
        };

        assert_eq!(
            ledger.apply_genesis(&genesis).await,
            Err(AccessControlError::InvalidGenesis(
                "role grant references an unknown scope".to_string()
            ))
        );
        assert_eq!(ledger.scope(&known).await.unwrap(), None);
    });
}
