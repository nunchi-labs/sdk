use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_coins::CoinId;
use nunchi_common::Address;

/// Basis-point denominator used by leverage and maintenance margin fields.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// Fixed-point scale used for mark prices and position quantities.
pub const PRICE_SCALE: u128 = 1_000_000_000;

pub type MarketId = Digest;
pub type PositionId = Digest;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Long,
    Short,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Market {
    pub id: MarketId,
    pub base_asset: CoinId,
    pub quote_asset: CoinId,
    pub collateral_asset: CoinId,
    pub max_leverage_bps: u32,
    pub maintenance_margin_bps: u32,
    pub mark_price: u128,
    pub open_interest: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Position {
    pub id: PositionId,
    pub market: MarketId,
    pub owner: Address,
    pub side: Side,
    pub quantity: u128,
    pub entry_price: u128,
    pub collateral: u128,
}

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
        self.max_leverage_bps.write(buf);
        self.maintenance_margin_bps.write(buf);
        self.mark_price.write(buf);
        self.open_interest.write(buf);
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
            max_leverage_bps: u32::read(buf)?,
            maintenance_margin_bps: u32::read(buf)?,
            mark_price: u128::read(buf)?,
            open_interest: u128::read(buf)?,
        })
    }
}

impl EncodeSize for Market {
    fn encode_size(&self) -> usize {
        self.id.encode_size()
            + self.base_asset.encode_size()
            + self.quote_asset.encode_size()
            + self.collateral_asset.encode_size()
            + self.max_leverage_bps.encode_size()
            + self.maintenance_margin_bps.encode_size()
            + self.mark_price.encode_size()
            + self.open_interest.encode_size()
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
    }
}
