use crate::{AccessControlDB, AccessControlError, AccessControlLedger, RoleId, ScopeId};
use nunchi_common::Address;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccessControlGenesis {
    #[serde(default)]
    pub scopes: Vec<ScopeGenesis>,
    #[serde(default)]
    pub grants: Vec<RoleGrantGenesis>,
}

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScopeGenesis {
    /// Hex-encoded [`ScopeId`].
    #[serde_as(as = "DisplayFromStr")]
    pub scope: ScopeId,
    /// Bech32-encoded controller [`Address`].
    #[serde_as(as = "DisplayFromStr")]
    pub owner: Address,
}

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoleGrantGenesis {
    /// Hex-encoded [`ScopeId`].
    #[serde_as(as = "DisplayFromStr")]
    pub scope: ScopeId,
    pub role: u16,
    /// Bech32-encoded member [`Address`].
    #[serde_as(as = "DisplayFromStr")]
    pub account: Address,
}

impl<D: AccessControlDB> AccessControlLedger<D> {
    pub async fn apply_genesis(
        &mut self,
        genesis: &AccessControlGenesis,
    ) -> Result<(), AccessControlError> {
        let mut scopes = BTreeMap::new();
        for entry in &genesis.scopes {
            if scopes.insert(entry.scope, entry.owner.clone()).is_some() {
                return Err(AccessControlError::InvalidGenesis(
                    "duplicate scope".to_string(),
                ));
            }
        }

        let mut grants = BTreeSet::new();
        for entry in &genesis.grants {
            let grant = (entry.scope, RoleId::new(entry.role), entry.account.clone());
            if !grants.insert(grant) {
                return Err(AccessControlError::InvalidGenesis(
                    "duplicate role grant".to_string(),
                ));
            }
        }

        for (scope, owner) in &scopes {
            if let Some(existing) = self.db.scope(scope).await? {
                if existing.owner != *owner {
                    return Err(AccessControlError::InvalidGenesis(
                        "scope owner does not match existing state".to_string(),
                    ));
                }
            }
        }
        for (scope, _, _) in &grants {
            if !scopes.contains_key(scope) && self.db.scope(scope).await?.is_none() {
                return Err(AccessControlError::InvalidGenesis(
                    "role grant references an unknown scope".to_string(),
                ));
            }
        }

        for (scope, owner) in scopes {
            self.db.set_scope_owner(&scope, &owner);
        }
        for (scope, role, account) in grants {
            self.db.set_role(&account, &scope, role);
        }
        Ok(())
    }
}
