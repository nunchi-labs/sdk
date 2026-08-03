//! Trusted bootstrap configuration for access-control scopes and memberships.

use crate::{
    AccessControlDB, AccessControlError, AccessControlLedger, RoleId, ScopeId,
};
use commonware_codec::DecodeExt;
use commonware_formatting::from_hex;
use nunchi_common::Address;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// JSON-facing access-control genesis state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccessControlGenesis {
    /// Initial scopes and their controllers.
    #[serde(default)]
    pub scopes: Vec<ScopeGenesis>,
    /// Initial exact role memberships.
    #[serde(default)]
    pub grants: Vec<RoleGrantGenesis>,
}

/// One scope registered at genesis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScopeGenesis {
    /// Hex-encoded [`ScopeId`].
    pub scope: String,
    /// Hex-encoded controller [`Address`].
    pub owner: String,
}

/// One role membership registered at genesis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoleGrantGenesis {
    /// Hex-encoded [`ScopeId`].
    pub scope: String,
    /// Module-defined numeric role.
    pub role: u16,
    /// Hex-encoded member [`Address`].
    pub account: String,
}

impl<D: AccessControlDB> AccessControlLedger<D> {
    /// Seed scope controllers and role memberships from trusted genesis state.
    pub async fn apply_genesis(
        &mut self,
        genesis: &AccessControlGenesis,
    ) -> Result<(), AccessControlError> {
        let mut scopes = BTreeMap::new();
        for entry in &genesis.scopes {
            let scope = decode_hex::<ScopeId>(&entry.scope, "scope")?;
            let owner = decode_hex::<Address>(&entry.owner, "scope owner")?;
            if scopes.insert(scope, owner).is_some() {
                return Err(AccessControlError::InvalidGenesis(
                    "duplicate scope".to_string(),
                ));
            }
        }

        let mut grants = BTreeSet::new();
        for entry in &genesis.grants {
            let scope = decode_hex::<ScopeId>(&entry.scope, "grant scope")?;
            let account = decode_hex::<Address>(&entry.account, "grant account")?;
            let grant = (scope, RoleId::new(entry.role), account);
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

fn decode_hex<T>(value: &str, what: &'static str) -> Result<T, AccessControlError>
where
    T: DecodeExt<()>,
{
    let bytes = from_hex(value).ok_or_else(|| {
        AccessControlError::InvalidGenesis(format!("invalid hex-encoded {what}"))
    })?;
    T::decode(bytes.as_ref())
        .map_err(|err| AccessControlError::InvalidGenesis(format!("invalid {what}: {err}")))
}
