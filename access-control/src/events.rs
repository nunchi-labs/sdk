use crate::{RoleId, ScopeId};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::{Address, Event};

pub const SCOPE_REGISTERED_EVENT: &[u8] = b"access_control.scope_registered.v1";
pub const ROLE_GRANTED_EVENT: &[u8] = b"access_control.role_granted.v1";
pub const ROLE_REVOKED_EVENT: &[u8] = b"access_control.role_revoked.v1";
pub const OWNERSHIP_TRANSFER_PROPOSED_EVENT: &[u8] =
    b"access_control.ownership_transfer_proposed.v1";
pub const OWNERSHIP_TRANSFER_CANCELLED_EVENT: &[u8] =
    b"access_control.ownership_transfer_cancelled.v1";
pub const SCOPE_OWNER_CHANGED_EVENT: &[u8] = b"access_control.scope_owner_changed.v1";

/// A module registered a new access-control scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeRegistered {
    pub scope: ScopeId,
    pub owner: Address,
}

impl Write for ScopeRegistered {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.scope.write(buf);
        self.owner.write(buf);
    }
}

impl Read for ScopeRegistered {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            scope: ScopeId::read(buf)?,
            owner: Address::read(buf)?,
        })
    }
}

impl EncodeSize for ScopeRegistered {
    fn encode_size(&self) -> usize {
        self.scope.encode_size() + self.owner.encode_size()
    }
}

/// A scope owner granted a role to an account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleGranted {
    pub scope: ScopeId,
    pub role: RoleId,
    pub account: Address,
    pub granted_by: Address,
}

impl Write for RoleGranted {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.scope.write(buf);
        self.role.write(buf);
        self.account.write(buf);
        self.granted_by.write(buf);
    }
}

impl Read for RoleGranted {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            scope: ScopeId::read(buf)?,
            role: RoleId::read(buf)?,
            account: Address::read(buf)?,
            granted_by: Address::read(buf)?,
        })
    }
}

impl EncodeSize for RoleGranted {
    fn encode_size(&self) -> usize {
        self.scope.encode_size()
            + self.role.encode_size()
            + self.account.encode_size()
            + self.granted_by.encode_size()
    }
}

/// A scope owner revoked a role from an account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleRevoked {
    pub scope: ScopeId,
    pub role: RoleId,
    pub account: Address,
    pub revoked_by: Address,
}

impl Write for RoleRevoked {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.scope.write(buf);
        self.role.write(buf);
        self.account.write(buf);
        self.revoked_by.write(buf);
    }
}

impl Read for RoleRevoked {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            scope: ScopeId::read(buf)?,
            role: RoleId::read(buf)?,
            account: Address::read(buf)?,
            revoked_by: Address::read(buf)?,
        })
    }
}

impl EncodeSize for RoleRevoked {
    fn encode_size(&self) -> usize {
        self.scope.encode_size()
            + self.role.encode_size()
            + self.account.encode_size()
            + self.revoked_by.encode_size()
    }
}

/// A scope owner proposed a replacement owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipTransferProposed {
    pub scope: ScopeId,
    pub owner: Address,
    pub proposed_owner: Address,
}

impl Write for OwnershipTransferProposed {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.scope.write(buf);
        self.owner.write(buf);
        self.proposed_owner.write(buf);
    }
}

impl Read for OwnershipTransferProposed {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            scope: ScopeId::read(buf)?,
            owner: Address::read(buf)?,
            proposed_owner: Address::read(buf)?,
        })
    }
}

impl EncodeSize for OwnershipTransferProposed {
    fn encode_size(&self) -> usize {
        self.scope.encode_size() + self.owner.encode_size() + self.proposed_owner.encode_size()
    }
}

/// A scope owner cancelled a pending ownership transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipTransferCancelled {
    pub scope: ScopeId,
    pub owner: Address,
    pub proposed_owner: Address,
}

impl Write for OwnershipTransferCancelled {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.scope.write(buf);
        self.owner.write(buf);
        self.proposed_owner.write(buf);
    }
}

impl Read for OwnershipTransferCancelled {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            scope: ScopeId::read(buf)?,
            owner: Address::read(buf)?,
            proposed_owner: Address::read(buf)?,
        })
    }
}

impl EncodeSize for OwnershipTransferCancelled {
    fn encode_size(&self) -> usize {
        self.scope.encode_size() + self.owner.encode_size() + self.proposed_owner.encode_size()
    }
}

/// A proposed owner accepted control of a scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeOwnerChanged {
    pub scope: ScopeId,
    pub previous_owner: Address,
    pub new_owner: Address,
}

impl Write for ScopeOwnerChanged {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.scope.write(buf);
        self.previous_owner.write(buf);
        self.new_owner.write(buf);
    }
}

impl Read for ScopeOwnerChanged {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            scope: ScopeId::read(buf)?,
            previous_owner: Address::read(buf)?,
            new_owner: Address::read(buf)?,
        })
    }
}

impl EncodeSize for ScopeOwnerChanged {
    fn encode_size(&self) -> usize {
        self.scope.encode_size() + self.previous_owner.encode_size() + self.new_owner.encode_size()
    }
}

pub fn scope_registered_event(value: ScopeRegistered) -> Event {
    Event::new(
        bytes::Bytes::from_static(SCOPE_REGISTERED_EVENT),
        value.encode(),
    )
}

pub fn role_granted_event(value: RoleGranted) -> Event {
    Event::new(
        bytes::Bytes::from_static(ROLE_GRANTED_EVENT),
        value.encode(),
    )
}

pub fn role_revoked_event(value: RoleRevoked) -> Event {
    Event::new(
        bytes::Bytes::from_static(ROLE_REVOKED_EVENT),
        value.encode(),
    )
}

pub fn ownership_transfer_proposed_event(value: OwnershipTransferProposed) -> Event {
    Event::new(
        bytes::Bytes::from_static(OWNERSHIP_TRANSFER_PROPOSED_EVENT),
        value.encode(),
    )
}

pub fn ownership_transfer_cancelled_event(value: OwnershipTransferCancelled) -> Event {
    Event::new(
        bytes::Bytes::from_static(OWNERSHIP_TRANSFER_CANCELLED_EVENT),
        value.encode(),
    )
}

pub fn scope_owner_changed_event(value: ScopeOwnerChanged) -> Event {
    Event::new(
        bytes::Bytes::from_static(SCOPE_OWNER_CHANGED_EVENT),
        value.encode(),
    )
}
