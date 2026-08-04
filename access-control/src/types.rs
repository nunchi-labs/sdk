use commonware_codec::{DecodeExt, Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_formatting::{from_hex, hex};
use nunchi_common::Address;
use std::{fmt, str::FromStr};

const SCOPE_DOMAIN: &[u8] = b"nunchi/access-control/scope/v1";
const MODULE_SCOPE: u8 = 0;
const RESOURCE_SCOPE: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScopeId(Digest);

impl ScopeId {
    pub fn module(module_namespace: &[u8]) -> Self {
        Self::derive(MODULE_SCOPE, module_namespace, &[])
    }

    pub fn resource(module_namespace: &[u8], resource: &[u8]) -> Self {
        Self::derive(RESOURCE_SCOPE, module_namespace, resource)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }

    fn derive(kind: u8, module_namespace: &[u8], resource: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(SCOPE_DOMAIN);
        hasher.update(&[kind]);
        hasher.update(&Sha256::hash(module_namespace).0);
        hasher.update(&Sha256::hash(resource).0);
        Self(hasher.finalize())
    }
}

impl From<Digest> for ScopeId {
    fn from(value: Digest) -> Self {
        Self(value)
    }
}

impl fmt::Display for ScopeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.encode()))
    }
}

impl FromStr for ScopeId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = from_hex(value).ok_or(Error::Invalid("ScopeId", "invalid hex"))?;
        Self::decode(bytes.as_ref())
    }
}

impl Write for ScopeId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for ScopeId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(Digest::read(buf)?))
    }
}

impl FixedSize for ScopeId {
    const SIZE: usize = Digest::SIZE;
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoleId(u16);

impl RoleId {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Write for RoleId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for RoleId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(u16::read(buf)?))
    }
}

impl FixedSize for RoleId {
    const SIZE: usize = u16::SIZE;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scope {
    pub id: ScopeId,
    pub owner: Address,
}

impl Scope {
    pub fn new(id: ScopeId, owner: Address) -> Self {
        Self { id, owner }
    }
}

impl Write for Scope {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.owner.write(buf);
    }
}

impl Read for Scope {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            id: ScopeId::read(buf)?,
            owner: Address::read(buf)?,
        })
    }
}

impl EncodeSize for Scope {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.owner.encode_size()
    }
}
