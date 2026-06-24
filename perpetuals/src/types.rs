use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_coins::CoinId;
use nunchi_common::Address;
use nunchi_oracle::NamespaceId;

/// Basis-point denominator used by leverage, funding, and margin fields.
pub const BPS_DENOMINATOR: u32 = 10_000;
/// Fixed-point scale used for position quantities and funding indices.
pub const PRICE_SCALE: u128 = 1_000_000_000;
/// Largest decimal precision accepted by the perps price decoder.
pub const MAX_PRICE_DECIMALS: u8 = 38;

/// Stable market identifier.
pub type MarketId = Digest;
/// Stable position identifier.
pub type PositionId = Digest;

/// Direction of a perpetual position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Long,
    Short,
}

/// Market-level state and configuration owned by the perps module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Market {
    pub id: MarketId,
    pub base_asset: CoinId,
    pub quote_asset: CoinId,
    pub collateral_asset: CoinId,
    pub oracle_namespace: NamespaceId,
    pub oracle_interval_ms: u64,
    pub max_oracle_staleness_ms: u64,
    pub price_decimals: u8,
    pub max_leverage_bps: u32,
    pub maintenance_margin_bps: u32,
    pub funding_interval_ms: u64,
    pub max_funding_rate_bps: u32,
    pub mark_price: u128,
    pub index_price: u128,
    pub open_interest: u128,
    pub last_oracle_interval: u64,
    pub last_oracle_update_ms: u64,
    pub last_funding_ms: u64,
    pub cumulative_funding_long: i128,
    pub cumulative_funding_short: i128,
}

/// Isolated-margin position state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Position {
    pub id: PositionId,
    pub market: MarketId,
    pub owner: Address,
    pub side: Side,
    pub quantity: u128,
    pub entry_price: u128,
    pub collateral: u128,
    pub entry_funding_index: i128,
}

/// Payload schema interpreted by this module from opaque Oracle records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OraclePricePayload {
    pub market: MarketId,
    pub price: u128,
    pub price_decimals: u8,
    pub source_timestamp_ms: u64,
}

/// Derive a market id from its configured assets and module-local nonce.
pub fn derive_market_id(
    base_asset: CoinId,
    quote_asset: CoinId,
    collateral_asset: CoinId,
    nonce: u64,
) -> MarketId {
    let mut hasher = Sha256::new();
    hasher.update(super::PERPETUALS_NAMESPACE);
    hasher.update(b"/market/");
    hasher.update(base_asset.encode().as_ref());
    hasher.update(quote_asset.encode().as_ref());
    hasher.update(collateral_asset.encode().as_ref());
    hasher.update(nonce.encode().as_ref());
    hasher.finalize()
}

/// Derive a position id from its owner, market, and module-local nonce.
pub fn derive_position_id(owner: &Address, market: &MarketId, nonce: u64) -> PositionId {
    let mut hasher = Sha256::new();
    hasher.update(super::PERPETUALS_NAMESPACE);
    hasher.update(b"/position/");
    hasher.update(owner.encode().as_ref());
    hasher.update(market.encode().as_ref());
    hasher.update(nonce.encode().as_ref());
    hasher.finalize()
}

impl Write for Side {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Long => 0u8.write(buf),
            Self::Short => 1u8.write(buf),
        }
    }
}

impl Read for Side {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Long),
            1 => Ok(Self::Short),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Side {
    fn encode_size(&self) -> usize {
        1
    }
}

impl Write for Market {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.base_asset.write(buf);
        self.quote_asset.write(buf);
        self.collateral_asset.write(buf);
        self.oracle_namespace.write(buf);
        self.oracle_interval_ms.write(buf);
        self.max_oracle_staleness_ms.write(buf);
        self.price_decimals.write(buf);
        self.max_leverage_bps.write(buf);
        self.maintenance_margin_bps.write(buf);
        self.funding_interval_ms.write(buf);
        self.max_funding_rate_bps.write(buf);
        self.mark_price.write(buf);
        self.index_price.write(buf);
        self.open_interest.write(buf);
        self.last_oracle_interval.write(buf);
        self.last_oracle_update_ms.write(buf);
        self.last_funding_ms.write(buf);
        self.cumulative_funding_long.write(buf);
        self.cumulative_funding_short.write(buf);
    }
}

impl Read for Market {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            id: MarketId::read(buf)?,
            base_asset: CoinId::read(buf)?,
            quote_asset: CoinId::read(buf)?,
            collateral_asset: CoinId::read(buf)?,
            oracle_namespace: NamespaceId::read(buf)?,
            oracle_interval_ms: u64::read(buf)?,
            max_oracle_staleness_ms: u64::read(buf)?,
            price_decimals: u8::read(buf)?,
            max_leverage_bps: u32::read(buf)?,
            maintenance_margin_bps: u32::read(buf)?,
            funding_interval_ms: u64::read(buf)?,
            max_funding_rate_bps: u32::read(buf)?,
            mark_price: u128::read(buf)?,
            index_price: u128::read(buf)?,
            open_interest: u128::read(buf)?,
            last_oracle_interval: u64::read(buf)?,
            last_oracle_update_ms: u64::read(buf)?,
            last_funding_ms: u64::read(buf)?,
            cumulative_funding_long: i128::read(buf)?,
            cumulative_funding_short: i128::read(buf)?,
        })
    }
}

impl EncodeSize for Market {
    fn encode_size(&self) -> usize {
        self.id.encode_size()
            + self.base_asset.encode_size()
            + self.quote_asset.encode_size()
            + self.collateral_asset.encode_size()
            + self.oracle_namespace.encode_size()
            + self.oracle_interval_ms.encode_size()
            + self.max_oracle_staleness_ms.encode_size()
            + self.price_decimals.encode_size()
            + self.max_leverage_bps.encode_size()
            + self.maintenance_margin_bps.encode_size()
            + self.funding_interval_ms.encode_size()
            + self.max_funding_rate_bps.encode_size()
            + self.mark_price.encode_size()
            + self.index_price.encode_size()
            + self.open_interest.encode_size()
            + self.last_oracle_interval.encode_size()
            + self.last_oracle_update_ms.encode_size()
            + self.last_funding_ms.encode_size()
            + self.cumulative_funding_long.encode_size()
            + self.cumulative_funding_short.encode_size()
    }
}

impl Write for Position {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.market.write(buf);
        self.owner.write(buf);
        self.side.write(buf);
        self.quantity.write(buf);
        self.entry_price.write(buf);
        self.collateral.write(buf);
        self.entry_funding_index.write(buf);
    }
}

impl Read for Position {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            id: PositionId::read(buf)?,
            market: MarketId::read(buf)?,
            owner: Address::read(buf)?,
            side: Side::read(buf)?,
            quantity: u128::read(buf)?,
            entry_price: u128::read(buf)?,
            collateral: u128::read(buf)?,
            entry_funding_index: i128::read(buf)?,
        })
    }
}

impl EncodeSize for Position {
    fn encode_size(&self) -> usize {
        self.id.encode_size()
            + self.market.encode_size()
            + self.owner.encode_size()
            + self.side.encode_size()
            + self.quantity.encode_size()
            + self.entry_price.encode_size()
            + self.collateral.encode_size()
            + self.entry_funding_index.encode_size()
    }
}

impl Write for OraclePricePayload {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.market.write(buf);
        self.price.write(buf);
        self.price_decimals.write(buf);
        self.source_timestamp_ms.write(buf);
    }
}

impl Read for OraclePricePayload {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            market: MarketId::read(buf)?,
            price: u128::read(buf)?,
            price_decimals: u8::read(buf)?,
            source_timestamp_ms: u64::read(buf)?,
        })
    }
}

impl EncodeSize for OraclePricePayload {
    fn encode_size(&self) -> usize {
        self.market.encode_size()
            + self.price.encode_size()
            + self.price_decimals.encode_size()
            + self.source_timestamp_ms.encode_size()
    }
}
