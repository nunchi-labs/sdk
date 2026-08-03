//! Deterministic access-control state machine.

use crate::{
    ownership_transfer_cancelled_event, ownership_transfer_proposed_event, role_granted_event,
    role_revoked_event, scope_owner_changed_event, scope_registered_event, AccessControlDB,
    AccessControlOperation, OwnershipTransferCancelled, OwnershipTransferProposed, RoleGranted,
    RoleId, RoleRevoked, Scope, ScopeId, ScopeOwnerChanged, ScopeRegistered, Transaction,
};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Authorization, CommitState, Event, EventSink};
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
    #[error("scope owner cannot transfer ownership to itself")]
    OwnershipUnchanged,
    #[error("scope {0:?} has no pending ownership transfer")]
    NoPendingOwnershipTransfer(ScopeId),
    #[error("account {account:?} is not the pending owner of scope {scope:?}")]
    NotPendingOwner {
        scope: ScopeId,
        account: Box<Address>,
    },
    #[error("invalid access-control genesis: {0}")]
    InvalidGenesis(String),
    #[error("state storage error: {0}")]
    Storage(String),
}

/// Scope ownership and role-membership state over an authenticated database.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessControlLedger<D> {
    pub(crate) db: D,
}

impl<D: AccessControlDB> AccessControlLedger<D> {
    /// Wrap a database backend as an access-control ledger.
    pub fn new(db: D) -> Self {
        Self { db }
    }

    /// Borrow the underlying database.
    pub fn db(&self) -> &D {
        &self.db
    }

    /// Consume the ledger, returning the underlying database.
    pub fn into_inner(self) -> D {
        self.db
    }

    /// Return the access-control nonce for an account.
    pub async fn nonce(&self, account: &Address) -> Result<u64, AccessControlError> {
        self.db.nonce(account).await
    }

    /// Return a registered scope and its current owner.
    pub async fn scope(&self, id: &ScopeId) -> Result<Option<Scope>, AccessControlError> {
        self.db.scope(id).await
    }

    /// Return the account proposed to take control of a scope.
    pub async fn pending_owner(&self, id: &ScopeId) -> Result<Option<Address>, AccessControlError> {
        self.db.pending_owner(id).await
    }

    /// Return whether `account` has the exact role in the exact scope.
    ///
    /// Scope ownership does not imply role membership. Consuming modules decide whether owners
    /// receive any implicit business permissions.
    pub async fn has_role(
        &self,
        account: &Address,
        scope: &ScopeId,
        role: RoleId,
    ) -> Result<bool, AccessControlError> {
        self.db.has_role(account, scope, role).await
    }

    /// Return whether `account` currently controls the scope.
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

    /// Register a scope on behalf of a consuming module.
    ///
    /// This method performs no transaction authorization. The caller must own the scope derivation
    /// and authorize its initial owner. Re-registering the same scope and owner is idempotent;
    /// assigning an existing scope to a different owner fails.
    pub async fn register_scope<Events>(
        &mut self,
        id: ScopeId,
        owner: Address,
        mut events: Events,
    ) -> Result<(), AccessControlError>
    where
        Events: EventSink + Send,
    {
        match self.db.scope(&id).await? {
            Some(existing) if existing.owner == owner => return Ok(()),
            Some(_) => return Err(AccessControlError::ScopeAlreadyRegistered(id)),
            None => {}
        }

        self.db.set_scope_owner(&id, &owner);
        events.emit(scope_registered_event(ScopeRegistered { scope: id, owner }));
        Ok(())
    }

    /// Verify and apply one signed role-management transaction.
    pub async fn apply_transaction<Events>(
        &mut self,
        tx: &Transaction,
        mut events: Events,
    ) -> Result<(), AccessControlError>
    where
        Events: EventSink + Send,
    {
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

        let event = self
            .apply_operation(&tx.account_id, &tx.payload.operation)
            .await?;
        self.db.set_nonce(&tx.account_id, next_nonce);
        events.emit(event);
        Ok(())
    }

    async fn apply_operation(
        &mut self,
        actor: &Address,
        operation: &AccessControlOperation,
    ) -> Result<Event, AccessControlError> {
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
                Ok(role_granted_event(RoleGranted {
                    scope: *scope,
                    role: *role,
                    account: account.clone(),
                    granted_by: actor.clone(),
                }))
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
                Ok(role_revoked_event(RoleRevoked {
                    scope: *scope,
                    role: *role,
                    account: account.clone(),
                    revoked_by: actor.clone(),
                }))
            }
            AccessControlOperation::ProposeOwnershipTransfer {
                scope,
                proposed_owner,
            } => {
                self.require_owner(actor, scope).await?;
                if actor == proposed_owner {
                    return Err(AccessControlError::OwnershipUnchanged);
                }
                self.db.set_pending_owner(scope, proposed_owner);
                Ok(ownership_transfer_proposed_event(
                    OwnershipTransferProposed {
                        scope: *scope,
                        owner: actor.clone(),
                        proposed_owner: proposed_owner.clone(),
                    },
                ))
            }
            AccessControlOperation::CancelOwnershipTransfer { scope } => {
                self.require_owner(actor, scope).await?;
                let proposed_owner = self
                    .db
                    .pending_owner(scope)
                    .await?
                    .ok_or(AccessControlError::NoPendingOwnershipTransfer(*scope))?;
                self.db.remove_pending_owner(scope);
                Ok(ownership_transfer_cancelled_event(
                    OwnershipTransferCancelled {
                        scope: *scope,
                        owner: actor.clone(),
                        proposed_owner,
                    },
                ))
            }
            AccessControlOperation::AcceptOwnership { scope } => {
                let previous_owner = self
                    .db
                    .scope(scope)
                    .await?
                    .ok_or(AccessControlError::UnknownScope(*scope))?
                    .owner;
                let pending = self
                    .db
                    .pending_owner(scope)
                    .await?
                    .ok_or(AccessControlError::NoPendingOwnershipTransfer(*scope))?;
                if &pending != actor {
                    return Err(AccessControlError::NotPendingOwner {
                        scope: *scope,
                        account: Box::new(actor.clone()),
                    });
                }
                self.db.set_scope_owner(scope, actor);
                self.db.remove_pending_owner(scope);
                Ok(scope_owner_changed_event(ScopeOwnerChanged {
                    scope: *scope,
                    previous_owner,
                    new_owner: actor.clone(),
                }))
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
    /// Flush staged writes, returning the new authenticated state root.
    pub async fn commit(&mut self) -> Result<Digest, AccessControlError> {
        self.db
            .commit()
            .await
            .map_err(|err| AccessControlError::Storage(err.to_string()))
    }

    /// Return the most recently committed authenticated state root.
    pub fn root(&self) -> Digest {
        self.db.root()
    }
}
