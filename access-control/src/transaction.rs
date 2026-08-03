//! Signed access-control management operations.

use crate::{RoleId, ScopeId, ACCESS_CONTROL_NAMESPACE};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::{Address, Operation};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationID {
    GrantRole = 0,
    RevokeRole = 1,
    ProposeOwnershipTransfer = 2,
    CancelOwnershipTransfer = 3,
    AcceptOwnership = 4,
}

/// An invalid access-control operation identifier.
#[derive(Debug, thiserror::Error)]
#[error("invalid access-control operation id: {0}")]
pub struct InvalidAccessControlOperationId(u8);

impl TryFrom<u8> for OperationID {
    type Error = InvalidAccessControlOperationId;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::GrantRole),
            1 => Ok(Self::RevokeRole),
            2 => Ok(Self::ProposeOwnershipTransfer),
            3 => Ok(Self::CancelOwnershipTransfer),
            4 => Ok(Self::AcceptOwnership),
            _ => Err(InvalidAccessControlOperationId(value)),
        }
    }
}

impl Write for OperationID {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_u8(*self as u8);
    }
}

impl Read for OperationID {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Self::try_from(u8::read(buf)?).map_err(|_| {
            Error::Invalid(
                "AccessControlOperationId",
                "invalid access-control operation id",
            )
        })
    }
}

/// Signed changes to access-control state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessControlOperation {
    /// Grant one module-defined role to an account.
    GrantRole {
        scope: ScopeId,
        role: RoleId,
        account: Address,
    },
    /// Revoke one module-defined role from an account.
    RevokeRole {
        scope: ScopeId,
        role: RoleId,
        account: Address,
    },
    /// Propose a new controller for a scope.
    ProposeOwnershipTransfer {
        scope: ScopeId,
        proposed_owner: Address,
    },
    /// Cancel the pending ownership transfer for a scope.
    CancelOwnershipTransfer { scope: ScopeId },
    /// Accept control of a scope after being proposed by its current owner.
    AcceptOwnership { scope: ScopeId },
}

impl Write for AccessControlOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::GrantRole {
                scope,
                role,
                account,
            } => {
                OperationID::GrantRole.write(buf);
                scope.write(buf);
                role.write(buf);
                account.write(buf);
            }
            Self::RevokeRole {
                scope,
                role,
                account,
            } => {
                OperationID::RevokeRole.write(buf);
                scope.write(buf);
                role.write(buf);
                account.write(buf);
            }
            Self::ProposeOwnershipTransfer {
                scope,
                proposed_owner,
            } => {
                OperationID::ProposeOwnershipTransfer.write(buf);
                scope.write(buf);
                proposed_owner.write(buf);
            }
            Self::CancelOwnershipTransfer { scope } => {
                OperationID::CancelOwnershipTransfer.write(buf);
                scope.write(buf);
            }
            Self::AcceptOwnership { scope } => {
                OperationID::AcceptOwnership.write(buf);
                scope.write(buf);
            }
        }
    }
}

impl Read for AccessControlOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match OperationID::read(buf)? {
            OperationID::GrantRole => Ok(Self::GrantRole {
                scope: ScopeId::read(buf)?,
                role: RoleId::read(buf)?,
                account: Address::read(buf)?,
            }),
            OperationID::RevokeRole => Ok(Self::RevokeRole {
                scope: ScopeId::read(buf)?,
                role: RoleId::read(buf)?,
                account: Address::read(buf)?,
            }),
            OperationID::ProposeOwnershipTransfer => Ok(Self::ProposeOwnershipTransfer {
                scope: ScopeId::read(buf)?,
                proposed_owner: Address::read(buf)?,
            }),
            OperationID::CancelOwnershipTransfer => Ok(Self::CancelOwnershipTransfer {
                scope: ScopeId::read(buf)?,
            }),
            OperationID::AcceptOwnership => Ok(Self::AcceptOwnership {
                scope: ScopeId::read(buf)?,
            }),
        }
    }
}

impl EncodeSize for AccessControlOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::GrantRole {
                scope,
                role,
                account,
            }
            | Self::RevokeRole {
                scope,
                role,
                account,
            } => scope.encode_size() + role.encode_size() + account.encode_size(),
            Self::ProposeOwnershipTransfer {
                scope,
                proposed_owner,
            } => scope.encode_size() + proposed_owner.encode_size(),
            Self::CancelOwnershipTransfer { scope } | Self::AcceptOwnership { scope } => {
                scope.encode_size()
            }
        }
    }
}

impl Operation for AccessControlOperation {
    const NAMESPACE: &'static [u8] = ACCESS_CONTROL_NAMESPACE;
}

/// Signed access-control transaction payload.
pub type TransactionPayload = nunchi_common::TransactionPayload<AccessControlOperation>;
/// Signed access-control transaction.
pub type Transaction = nunchi_common::Transaction<AccessControlOperation>;
