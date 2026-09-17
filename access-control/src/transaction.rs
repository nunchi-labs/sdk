use crate::{RoleId, ScopeId, ACCESS_CONTROL_NAMESPACE};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::{Address, Operation};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationID {
    GrantRole = 0,
    RevokeRole = 1,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid access-control operation id: {0}")]
pub struct InvalidAccessControlOperationId(u8);

impl TryFrom<u8> for OperationID {
    type Error = InvalidAccessControlOperationId;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::GrantRole),
            1 => Ok(Self::RevokeRole),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessControlOperation {
    GrantRole {
        scope: ScopeId,
        role: RoleId,
        account: Address,
    },
    RevokeRole {
        scope: ScopeId,
        role: RoleId,
        account: Address,
    },
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
        }
    }
}

impl Operation for AccessControlOperation {
    const NAMESPACE: &'static [u8] = ACCESS_CONTROL_NAMESPACE;
}

pub type TransactionPayload = nunchi_common::TransactionPayload<AccessControlOperation>;
pub type Transaction = nunchi_common::Transaction<AccessControlOperation>;
