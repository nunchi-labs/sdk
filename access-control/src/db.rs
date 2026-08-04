use crate::{AccessControlError, RoleId, Scope, ScopeId, ACCESS_CONTROL_NAMESPACE};
use async_trait::async_trait;
use commonware_codec::{Encode, Read, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Namespace, StateStore};

const NS: Namespace = Namespace::new(ACCESS_CONTROL_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    Nonce = 0,
    ScopeOwner = 1,
    PendingOwner = 2,
    RoleGrant = 3,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, AccessControlError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| AccessControlError::Storage(err.to_string()))
}

fn role_grant_key(scope: &ScopeId, role: RoleId, account: &Address) -> Digest {
    let mut logical = encoded(scope);
    logical.extend_from_slice(role.encode().as_ref());
    logical.extend_from_slice(account.encode().as_ref());
    NS.key(Table::RoleGrant, &logical)
}

#[async_trait]
pub trait AccessControlDB {
    async fn nonce(&self, account: &Address) -> Result<u64, AccessControlError>;

    fn set_nonce(&mut self, account: &Address, nonce: u64);

    async fn scope(&self, id: &ScopeId) -> Result<Option<Scope>, AccessControlError>;

    fn set_scope_owner(&mut self, id: &ScopeId, owner: &Address);

    async fn pending_owner(&self, id: &ScopeId) -> Result<Option<Address>, AccessControlError>;

    fn set_pending_owner(&mut self, id: &ScopeId, owner: &Address);

    fn remove_pending_owner(&mut self, id: &ScopeId);

    async fn has_role(
        &self,
        account: &Address,
        scope: &ScopeId,
        role: RoleId,
    ) -> Result<bool, AccessControlError>;

    fn set_role(&mut self, account: &Address, scope: &ScopeId, role: RoleId);

    fn remove_role(&mut self, account: &Address, scope: &ScopeId, role: RoleId);
}

#[async_trait]
impl<S: StateStore + Send + Sync> AccessControlDB for S {
    async fn nonce(&self, account: &Address) -> Result<u64, AccessControlError> {
        let key = NS.key(Table::Nonce, account.encode().as_ref());
        match StateStore::get(self, &key)
            .await
            .map_err(|err| AccessControlError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_nonce(&mut self, account: &Address, nonce: u64) {
        let key = NS.key(Table::Nonce, account.encode().as_ref());
        StateStore::set(self, key, encoded(&nonce));
    }

    async fn scope(&self, id: &ScopeId) -> Result<Option<Scope>, AccessControlError> {
        let key = NS.key(Table::ScopeOwner, id.encode().as_ref());
        match StateStore::get(self, &key)
            .await
            .map_err(|err| AccessControlError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(Scope::new(*id, decoded(&bytes)?))),
            None => Ok(None),
        }
    }

    fn set_scope_owner(&mut self, id: &ScopeId, owner: &Address) {
        let key = NS.key(Table::ScopeOwner, id.encode().as_ref());
        StateStore::set(self, key, encoded(owner));
    }

    async fn pending_owner(&self, id: &ScopeId) -> Result<Option<Address>, AccessControlError> {
        let key = NS.key(Table::PendingOwner, id.encode().as_ref());
        match StateStore::get(self, &key)
            .await
            .map_err(|err| AccessControlError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_pending_owner(&mut self, id: &ScopeId, owner: &Address) {
        let key = NS.key(Table::PendingOwner, id.encode().as_ref());
        StateStore::set(self, key, encoded(owner));
    }

    fn remove_pending_owner(&mut self, id: &ScopeId) {
        let key = NS.key(Table::PendingOwner, id.encode().as_ref());
        StateStore::remove(self, key);
    }

    async fn has_role(
        &self,
        account: &Address,
        scope: &ScopeId,
        role: RoleId,
    ) -> Result<bool, AccessControlError> {
        match StateStore::get(self, &role_grant_key(scope, role, account))
            .await
            .map_err(|err| AccessControlError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(false),
        }
    }

    fn set_role(&mut self, account: &Address, scope: &ScopeId, role: RoleId) {
        StateStore::set(self, role_grant_key(scope, role, account), encoded(&true));
    }

    fn remove_role(&mut self, account: &Address, scope: &ScopeId, role: RoleId) {
        StateStore::remove(self, role_grant_key(scope, role, account));
    }
}
