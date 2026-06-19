use super::Address;
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::sha256::Digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

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

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(Digest::read(buf)?))
    }
}

impl FixedSize for CoinId {
    const SIZE: usize = Digest::SIZE;
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum TokenError {
    #[error("invalid token spec: {0}")]
    InvalidTokenSpec(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TokenSymbol(String);

impl TokenSymbol {
    pub fn new(value: impl Into<String>) -> Result<Self, TokenError> {
        let symbol = value.into();

        if symbol.is_empty() {
            return Err(TokenError::InvalidTokenSpec("token symbol cannot be empty"));
        }
        if symbol.len() > MAX_SYMBOL_BYTES {
            return Err(TokenError::InvalidTokenSpec("token symbol is too long"));
        }

        Ok(Self(symbol))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TokenSymbol {
    type Error = TokenError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for TokenSymbol {
    type Error = TokenError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Write for TokenSymbol {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.as_bytes().write(buf);
    }
}

impl Read for TokenSymbol {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=MAX_SYMBOL_BYTES), ()))?;
        let value = String::from_utf8(bytes).map_err(|_| {
            CodecError::Wrapped(
                "TokenSymbol",
                TokenError::InvalidTokenSpec("token symbol must be valid utf-8").into(),
            )
        })?;

        Self::new(value).map_err(|error| CodecError::Wrapped("TokenSymbol", error.into()))
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

impl Serialize for TokenSymbol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TokenSymbol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TokenName(String);

impl TokenName {
    pub fn new(value: impl Into<String>) -> Result<Self, TokenError> {
        let name = value.into();

        if name.is_empty() {
            return Err(TokenError::InvalidTokenSpec("token name cannot be empty"));
        }
        if name.len() > MAX_NAME_BYTES {
            return Err(TokenError::InvalidTokenSpec("token name is too long"));
        }

        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TokenName {
    type Error = TokenError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for TokenName {
    type Error = TokenError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Write for TokenName {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.as_bytes().write(buf);
    }
}

impl Read for TokenName {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=MAX_NAME_BYTES), ()))?;
        let value = String::from_utf8(bytes).map_err(|_| {
            CodecError::Wrapped(
                "TokenName",
                TokenError::InvalidTokenSpec("token name must be valid utf-8").into(),
            )
        })?;
        Self::new(value).map_err(|error| CodecError::Wrapped("TokenName", error.into()))
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

impl Serialize for TokenName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TokenName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Metadata and supply policy requested when creating a token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoinSpec {
    pub symbol: TokenSymbol,
    pub name: TokenName,
    pub decimals: u8,
    pub initial_supply: u128,
    pub max_supply: Option<u128>,
}

impl CoinSpec {
    pub fn new(
        symbol: TokenSymbol,
        name: TokenName,
        decimals: u8,
        initial_supply: u128,
        max_supply: Option<u128>,
    ) -> Self {
        Self {
            symbol,
            name,
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

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
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

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
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
