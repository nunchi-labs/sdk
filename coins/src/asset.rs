use super::Address;
use commonware_codec::{EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use std::ops::Deref;

pub const MAX_SYMBOL_BYTES: usize = 32;
pub const MAX_NAME_BYTES: usize = 128;

/// A deterministic identifier for a token managed by the coin ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CoinId(pub Digest);

impl CoinId {
    pub fn digest(self) -> Digest {
        self.0
    }
}

impl From<Digest> for CoinId {
    fn from(value: Digest) -> Self {
        Self(value)
    }
}

impl Write for CoinId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for CoinId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(Digest::read(buf)?))
    }
}

impl FixedSize for CoinId {
    const SIZE: usize = Digest::SIZE;
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TokenSymbol(pub String);

impl TokenSymbol {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl From<String> for TokenSymbol {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for TokenSymbol {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl AsRef<str> for TokenSymbol {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Write for TokenSymbol {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.as_bytes().write(buf);
    }
}

impl Read for TokenSymbol {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=MAX_SYMBOL_BYTES), ()))?;
        let value = String::from_utf8(bytes)
            .map_err(|error| Error::Wrapped("TokenSymbol", error.into()))?;
        Ok(Self(value))
    }
}

impl EncodeSize for TokenSymbol {
    fn encode_size(&self) -> usize {
        self.0.as_bytes().encode_size()
    }
}

impl From<TokenSymbol> for String {
    fn from(value: TokenSymbol) -> Self {
        value.0
    }
}

impl Deref for TokenSymbol {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TokenName(pub String);

impl TokenName {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl From<String> for TokenName {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for TokenName {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl AsRef<str> for TokenName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Write for TokenName {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.as_bytes().write(buf);
    }
}

impl Read for TokenName {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=MAX_NAME_BYTES), ()))?;
        let value =
            String::from_utf8(bytes).map_err(|error| Error::Wrapped("TokenName", error.into()))?;
        Ok(Self(value))
    }
}

impl EncodeSize for TokenName {
    fn encode_size(&self) -> usize {
        self.0.as_bytes().encode_size()
    }
}

impl From<TokenName> for String {
    fn from(value: TokenName) -> Self {
        value.0
    }
}

impl Deref for TokenName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Metadata and supply policy requested when creating a token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinSpec {
    pub symbol: TokenSymbol,
    pub name: TokenName,
    pub decimals: u8,
    pub initial_supply: u128,
    pub max_supply: Option<u128>,
}

impl CoinSpec {
    pub fn new(
        symbol: impl Into<TokenSymbol>,
        name: impl Into<TokenName>,
        decimals: u8,
        initial_supply: u128,
        max_supply: Option<u128>,
    ) -> Self {
        Self {
            symbol: symbol.into(),
            name: name.into(),
            decimals,
            initial_supply,
            max_supply,
        }
    }
}

impl Write for CoinSpec {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.symbol.write(buf);
        self.name.write(buf);
        self.decimals.write(buf);
        self.initial_supply.write(buf);
        self.max_supply.write(buf);
    }
}

impl Read for CoinSpec {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            symbol: TokenSymbol::read(buf)?,
            name: TokenName::read(buf)?,
            decimals: u8::read(buf)?,
            initial_supply: u128::read(buf)?,
            max_supply: Option::<u128>::read(buf)?,
        })
    }
}

impl EncodeSize for CoinSpec {
    fn encode_size(&self) -> usize {
        self.symbol.encode_size()
            + self.name.encode_size()
            + self.decimals.encode_size()
            + self.initial_supply.encode_size()
            + self.max_supply.encode_size()
    }
}

/// A token registered in the Nunchi coin ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenDefinition {
    pub id: CoinId,
    pub issuer: Address,
    pub symbol: TokenSymbol,
    pub name: TokenName,
    pub decimals: u8,
    pub total_supply: u128,
    pub max_supply: Option<u128>,
}

impl TokenDefinition {
    pub fn from_spec(id: CoinId, issuer: Address, spec: CoinSpec) -> Self {
        Self {
            id,
            issuer,
            symbol: spec.symbol,
            name: spec.name,
            decimals: spec.decimals,
            total_supply: spec.initial_supply,
            max_supply: spec.max_supply,
        }
    }
}

impl Write for TokenDefinition {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.issuer.write(buf);
        self.symbol.write(buf);
        self.name.write(buf);
        self.decimals.write(buf);
        self.total_supply.write(buf);
        self.max_supply.write(buf);
    }
}

impl Read for TokenDefinition {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            id: CoinId::read(buf)?,
            issuer: Address::read(buf)?,
            symbol: TokenSymbol::read(buf)?,
            name: TokenName::read(buf)?,
            decimals: u8::read(buf)?,
            total_supply: u128::read(buf)?,
            max_supply: Option::<u128>::read(buf)?,
        })
    }
}

impl EncodeSize for TokenDefinition {
    fn encode_size(&self) -> usize {
        self.id.encode_size()
            + self.issuer.encode_size()
            + self.symbol.encode_size()
            + self.name.encode_size()
            + self.decimals.encode_size()
            + self.total_supply.encode_size()
            + self.max_supply.encode_size()
    }
}
