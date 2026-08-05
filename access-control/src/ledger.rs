use crate::{AccessControlDB, AccessControlOperation, RoleId, Scope, ScopeId, Transaction};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Authorization, CommitState};
use nunchi_crypto::SignatureError;
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AccessControlError {
    #[error("bad access-control transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("multisig access-control transactions are not supported")]
    UnsupportedAuthorization,
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("unknown access-control scope {0:?}")]
    UnknownScope(ScopeId),
    #[error("access-control scope {0:?} is already registered to another owner")]
    ScopeAlreadyRegistered(ScopeId),
    #[error("account {account:?} does not own access-control scope {scope:?}")]
    Unauthorized {
        scope: ScopeId,
        account: Box<Address>,
    },
    #[error("role {role:?} is already granted to {account:?} in scope {scope:?}")]
    RoleAlreadyGranted {
        scope: ScopeId,
        role: RoleId,
        account: Box<Address>,
    },
    #[error("role {role:?} is not granted to {account:?} in scope {scope:?}")]
    RoleNotGranted {
        scope: ScopeId,
        role: RoleId,
        account: Box<Address>,
    },
    #[error("invalid access-control genesis: {0}")]
    InvalidGenesis(String),
    #[error("state storage error: {0}")]
    Storage(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessControlLedger<D> {
    pub(crate) db: D,
}

impl<D: AccessControlDB> AccessControlLedger<D> {
    pub fn new(db: D) -> Self {
        Self { db }
    }

    pub fn db(&self) -> &D {
        &self.db
    }

    pub fn into_inner(self) -> D {
        self.db
    }

    pub async fn nonce(&self, account: &Address) -> Result<u64, AccessControlError> {
        self.db.nonce(account).await
    }

    pub async fn scope(&self, id: &ScopeId) -> Result<Option<Scope>, AccessControlError> {
        self.db.scope(id).await
    }

    pub async fn has_role(
        &self,
        account: &Address,
        scope: &ScopeId,
        role: RoleId,
    ) -> Result<bool, AccessControlError> {
        self.db.has_role(account, scope, role).await
    }

    pub async fn is_scope_owner(
        &self,
        account: &Address,
        scope: &ScopeId,
    ) -> Result<bool, AccessControlError> {
        Ok(self
            .db
            .scope(scope)
            .await?
            .is_some_and(|registered| registered.owner == *account))
    }

    pub async fn register_scope(
        &mut self,
        id: ScopeId,
        owner: Address,
    ) -> Result<(), AccessControlError> {
        match self.db.scope(&id).await? {
            Some(existing) if existing.owner == owner => return Ok(()),
            Some(_) => return Err(AccessControlError::ScopeAlreadyRegistered(id)),
            None => {}
        }

        self.db.set_scope_owner(&id, &owner);
        Ok(())
    }

    pub async fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), AccessControlError> {
        tx.verify()?;
        if !matches!(tx.authorization, Authorization::Single { .. }) {
            return Err(AccessControlError::UnsupportedAuthorization);
        }

        let expected = self.db.nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(AccessControlError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }
        let next_nonce = expected
            .checked_add(1)
            .ok_or(AccessControlError::NonceOverflow)?;

        self.apply_operation(&tx.account_id, &tx.payload.operation)
            .await?;
        self.db.set_nonce(&tx.account_id, next_nonce);
        Ok(())
    }

    async fn apply_operation(
        &mut self,
        actor: &Address,
        operation: &AccessControlOperation,
    ) -> Result<(), AccessControlError> {
        match operation {
            AccessControlOperation::GrantRole {
                scope,
                role,
                account,
            } => {
                self.require_owner(actor, scope).await?;
                if self.db.has_role(account, scope, *role).await? {
                    return Err(AccessControlError::RoleAlreadyGranted {
                        scope: *scope,
                        role: *role,
                        account: Box::new(account.clone()),
                    });
                }
                self.db.set_role(account, scope, *role);
                Ok(())
            }
            AccessControlOperation::RevokeRole {
                scope,
                role,
                account,
            } => {
                self.require_owner(actor, scope).await?;
                if !self.db.has_role(account, scope, *role).await? {
                    return Err(AccessControlError::RoleNotGranted {
                        scope: *scope,
                        role: *role,
                        account: Box::new(account.clone()),
                    });
                }
                self.db.remove_role(account, scope, *role);
                Ok(())
            }
        }
    }

    async fn require_owner(
        &self,
        actor: &Address,
        scope: &ScopeId,
    ) -> Result<(), AccessControlError> {
        let registered = self
            .db
            .scope(scope)
            .await?
            .ok_or(AccessControlError::UnknownScope(*scope))?;
        if &registered.owner == actor {
            Ok(())
        } else {
            Err(AccessControlError::Unauthorized {
                scope: *scope,
                account: Box::new(actor.clone()),
            })
        }
    }
}

impl<D: AccessControlDB + CommitState> AccessControlLedger<D> {
    pub async fn commit(&mut self) -> Result<Digest, AccessControlError> {
        self.db
            .commit()
            .await
            .map_err(|err| AccessControlError::Storage(err.to_string()))
    }

    pub fn root(&self) -> Digest {
        self.db.root()
    }
}
