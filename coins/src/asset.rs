use super::codec::{read_string, string_encode_size, write_string};
use super::AccountId;
use commonware_codec::{EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;

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

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self(Digest::read(buf)?))
    }
}

impl FixedSize for CoinId {
    const SIZE: usize = Digest::SIZE;
}

/// Metadata and supply policy requested when creating a token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinSpec {
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub initial_supply: u128,
    pub max_supply: Option<u128>,
}

impl CoinSpec {
    pub fn new(
        symbol: impl Into<String>,
        name: impl Into<String>,
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
        write_string(&self.symbol, buf);
        write_string(&self.name, buf);
        self.decimals.write(buf);
        self.initial_supply.write(buf);
        self.max_supply.write(buf);
    }
}

impl Read for CoinSpec {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            symbol: read_string(buf, MAX_SYMBOL_BYTES, "CoinSpec::symbol")?,
            name: read_string(buf, MAX_NAME_BYTES, "CoinSpec::name")?,
            decimals: u8::read(buf)?,
            initial_supply: u128::read(buf)?,
            max_supply: Option::<u128>::read(buf)?,
        })
    }
}

impl EncodeSize for CoinSpec {
    fn encode_size(&self) -> usize {
        string_encode_size(&self.symbol)
            + string_encode_size(&self.name)
            + self.decimals.encode_size()
            + self.initial_supply.encode_size()
            + self.max_supply.encode_size()
    }
}

/// A token registered in the Nunchi coin ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenDefinition {
    pub id: CoinId,
    pub issuer: AccountId,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub total_supply: u128,
    pub max_supply: Option<u128>,
}

impl TokenDefinition {
    pub fn from_spec(id: CoinId, issuer: AccountId, spec: CoinSpec) -> Self {
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
        write_string(&self.symbol, buf);
        write_string(&self.name, buf);
        self.decimals.write(buf);
        self.total_supply.write(buf);
        self.max_supply.write(buf);
    }
}

impl Read for TokenDefinition {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            id: CoinId::read(buf)?,
            issuer: AccountId::read(buf)?,
            symbol: read_string(buf, MAX_SYMBOL_BYTES, "TokenDefinition::symbol")?,
            name: read_string(buf, MAX_NAME_BYTES, "TokenDefinition::name")?,
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
            + string_encode_size(&self.symbol)
            + string_encode_size(&self.name)
            + self.decimals.encode_size()
            + self.total_supply.encode_size()
            + self.max_supply.encode_size()
    }
}
