use crate::{MarketId, PositionId, Side};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_coins::CoinId;
use nunchi_common::Operation;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerpetualOperationId {
    CreateMarket = 0,
    UpdateMarketPrice = 1,
    OpenPosition = 2,
    AddCollateral = 3,
    ClosePosition = 4,
    Liquidate = 5,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid perpetual operation id: {0}")]
pub struct InvalidPerpetualOperationId(u8);

impl TryFrom<u8> for PerpetualOperationId {
    type Error = InvalidPerpetualOperationId;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CreateMarket),
            1 => Ok(Self::UpdateMarketPrice),
            2 => Ok(Self::OpenPosition),
            3 => Ok(Self::AddCollateral),
            4 => Ok(Self::ClosePosition),
            5 => Ok(Self::Liquidate),
            _ => Err(InvalidPerpetualOperationId(value)),
        }
    }
}

impl Write for PerpetualOperationId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_u8(*self as u8);
    }
}

impl Read for PerpetualOperationId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let value = u8::read(buf)?;
        Self::try_from(value)
            .map_err(|_| Error::Invalid("PerpetualOperationId", "invalid operation id"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PerpetualOperation {
    CreateMarket {
        base_asset: CoinId,
        quote_asset: CoinId,
        collateral_asset: CoinId,
        max_leverage_bps: u32,
        maintenance_margin_bps: u32,
        mark_price: u128,
    },
    UpdateMarketPrice {
        market: MarketId,
        mark_price: u128,
    },
    OpenPosition {
        market: MarketId,
        side: Side,
        collateral: u128,
        leverage_bps: u32,
    },
    AddCollateral {
        position: PositionId,
        amount: u128,
    },
    ClosePosition {
        position: PositionId,
    },
    Liquidate {
        position: PositionId,
    },
}

impl Write for PerpetualOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::CreateMarket {
                base_asset,
                quote_asset,
                collateral_asset,
                max_leverage_bps,
                maintenance_margin_bps,
                mark_price,
            } => {
                PerpetualOperationId::CreateMarket.write(buf);
                base_asset.write(buf);
                quote_asset.write(buf);
                collateral_asset.write(buf);
                max_leverage_bps.write(buf);
                maintenance_margin_bps.write(buf);
                mark_price.write(buf);
            }
            Self::UpdateMarketPrice { market, mark_price } => {
                PerpetualOperationId::UpdateMarketPrice.write(buf);
                market.write(buf);
                mark_price.write(buf);
            }
            Self::OpenPosition {
                market,
                side,
                collateral,
                leverage_bps,
            } => {
                PerpetualOperationId::OpenPosition.write(buf);
                market.write(buf);
                side.write(buf);
                collateral.write(buf);
                leverage_bps.write(buf);
            }
            Self::AddCollateral { position, amount } => {
                PerpetualOperationId::AddCollateral.write(buf);
                position.write(buf);
                amount.write(buf);
            }
            Self::ClosePosition { position } => {
                PerpetualOperationId::ClosePosition.write(buf);
                position.write(buf);
            }
            Self::Liquidate { position } => {
                PerpetualOperationId::Liquidate.write(buf);
                position.write(buf);
            }
        }
    }
}

impl Read for PerpetualOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match PerpetualOperationId::read(buf)? {
            PerpetualOperationId::CreateMarket => Ok(Self::CreateMarket {
                base_asset: CoinId::read(buf)?,
                quote_asset: CoinId::read(buf)?,
                collateral_asset: CoinId::read(buf)?,
                max_leverage_bps: u32::read(buf)?,
                maintenance_margin_bps: u32::read(buf)?,
                mark_price: u128::read(buf)?,
            }),
            PerpetualOperationId::UpdateMarketPrice => Ok(Self::UpdateMarketPrice {
                market: MarketId::read(buf)?,
                mark_price: u128::read(buf)?,
            }),
            PerpetualOperationId::OpenPosition => Ok(Self::OpenPosition {
                market: MarketId::read(buf)?,
                side: Side::read(buf)?,
                collateral: u128::read(buf)?,
                leverage_bps: u32::read(buf)?,
            }),
            PerpetualOperationId::AddCollateral => Ok(Self::AddCollateral {
                position: PositionId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            PerpetualOperationId::ClosePosition => Ok(Self::ClosePosition {
                position: PositionId::read(buf)?,
            }),
            PerpetualOperationId::Liquidate => Ok(Self::Liquidate {
                position: PositionId::read(buf)?,
            }),
        }
    }
}

impl EncodeSize for PerpetualOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::CreateMarket {
                base_asset,
                quote_asset,
                collateral_asset,
                max_leverage_bps,
                maintenance_margin_bps,
                mark_price,
            } => {
                base_asset.encode_size()
                    + quote_asset.encode_size()
                    + collateral_asset.encode_size()
                    + max_leverage_bps.encode_size()
                    + maintenance_margin_bps.encode_size()
                    + mark_price.encode_size()
            }
            Self::UpdateMarketPrice { market, mark_price } => {
                market.encode_size() + mark_price.encode_size()
            }
            Self::OpenPosition {
                market,
                side,
                collateral,
                leverage_bps,
            } => {
                market.encode_size()
                    + side.encode_size()
                    + collateral.encode_size()
                    + leverage_bps.encode_size()
            }
            Self::AddCollateral { position, amount } => {
                position.encode_size() + amount.encode_size()
            }
            Self::ClosePosition { position } | Self::Liquidate { position } => {
                position.encode_size()
            }
        }
    }
}

impl Operation for PerpetualOperation {
    const NAMESPACE: &'static [u8] = super::PERPETUALS_NAMESPACE;
}

pub type Transaction = nunchi_common::Transaction<PerpetualOperation>;
pub type TransactionPayload = nunchi_common::TransactionPayload<PerpetualOperation>;
