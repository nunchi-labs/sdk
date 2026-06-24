use crate::{MarketId, PositionId, Side, PERPETUALS_NAMESPACE};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_coins::CoinId;
use nunchi_common::Operation;
use nunchi_oracle::NamespaceId;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationTag {
    CreateMarket = 0,
    RefreshMarketFromOracle = 1,
    SettleFunding = 2,
    OpenPosition = 3,
    AddCollateral = 4,
    ReduceCollateral = 5,
    ClosePosition = 6,
    Liquidate = 7,
}

impl TryFrom<u8> for OperationTag {
    type Error = Error;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            0 => Ok(Self::CreateMarket),
            1 => Ok(Self::RefreshMarketFromOracle),
            2 => Ok(Self::SettleFunding),
            3 => Ok(Self::OpenPosition),
            4 => Ok(Self::AddCollateral),
            5 => Ok(Self::ReduceCollateral),
            6 => Ok(Self::ClosePosition),
            7 => Ok(Self::Liquidate),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

/// Perpetuals state-machine operation carried by a signed Nunchi transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PerpetualOperation {
    CreateMarket {
        base_asset: CoinId,
        quote_asset: CoinId,
        collateral_asset: CoinId,
        oracle_namespace: NamespaceId,
        oracle_interval_ms: u64,
        max_oracle_staleness_ms: u64,
        price_decimals: u8,
        max_leverage_bps: u32,
        maintenance_margin_bps: u32,
        funding_interval_ms: u64,
        max_funding_rate_bps: u32,
    },
    RefreshMarketFromOracle {
        market: MarketId,
    },
    SettleFunding {
        market: MarketId,
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
    ReduceCollateral {
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
                oracle_namespace,
                oracle_interval_ms,
                max_oracle_staleness_ms,
                price_decimals,
                max_leverage_bps,
                maintenance_margin_bps,
                funding_interval_ms,
                max_funding_rate_bps,
            } => {
                (OperationTag::CreateMarket as u8).write(buf);
                base_asset.write(buf);
                quote_asset.write(buf);
                collateral_asset.write(buf);
                oracle_namespace.write(buf);
                oracle_interval_ms.write(buf);
                max_oracle_staleness_ms.write(buf);
                price_decimals.write(buf);
                max_leverage_bps.write(buf);
                maintenance_margin_bps.write(buf);
                funding_interval_ms.write(buf);
                max_funding_rate_bps.write(buf);
            }
            Self::RefreshMarketFromOracle { market } => {
                (OperationTag::RefreshMarketFromOracle as u8).write(buf);
                market.write(buf);
            }
            Self::SettleFunding { market } => {
                (OperationTag::SettleFunding as u8).write(buf);
                market.write(buf);
            }
            Self::OpenPosition {
                market,
                side,
                collateral,
                leverage_bps,
            } => {
                (OperationTag::OpenPosition as u8).write(buf);
                market.write(buf);
                side.write(buf);
                collateral.write(buf);
                leverage_bps.write(buf);
            }
            Self::AddCollateral { position, amount } => {
                (OperationTag::AddCollateral as u8).write(buf);
                position.write(buf);
                amount.write(buf);
            }
            Self::ReduceCollateral { position, amount } => {
                (OperationTag::ReduceCollateral as u8).write(buf);
                position.write(buf);
                amount.write(buf);
            }
            Self::ClosePosition { position } => {
                (OperationTag::ClosePosition as u8).write(buf);
                position.write(buf);
            }
            Self::Liquidate { position } => {
                (OperationTag::Liquidate as u8).write(buf);
                position.write(buf);
            }
        }
    }
}

impl Read for PerpetualOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match OperationTag::try_from(u8::read(buf)?)? {
            OperationTag::CreateMarket => Ok(Self::CreateMarket {
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
            }),
            OperationTag::RefreshMarketFromOracle => Ok(Self::RefreshMarketFromOracle {
                market: MarketId::read(buf)?,
            }),
            OperationTag::SettleFunding => Ok(Self::SettleFunding {
                market: MarketId::read(buf)?,
            }),
            OperationTag::OpenPosition => Ok(Self::OpenPosition {
                market: MarketId::read(buf)?,
                side: Side::read(buf)?,
                collateral: u128::read(buf)?,
                leverage_bps: u32::read(buf)?,
            }),
            OperationTag::AddCollateral => Ok(Self::AddCollateral {
                position: PositionId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            OperationTag::ReduceCollateral => Ok(Self::ReduceCollateral {
                position: PositionId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            OperationTag::ClosePosition => Ok(Self::ClosePosition {
                position: PositionId::read(buf)?,
            }),
            OperationTag::Liquidate => Ok(Self::Liquidate {
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
                oracle_namespace,
                oracle_interval_ms,
                max_oracle_staleness_ms,
                price_decimals,
                max_leverage_bps,
                maintenance_margin_bps,
                funding_interval_ms,
                max_funding_rate_bps,
            } => {
                base_asset.encode_size()
                    + quote_asset.encode_size()
                    + collateral_asset.encode_size()
                    + oracle_namespace.encode_size()
                    + oracle_interval_ms.encode_size()
                    + max_oracle_staleness_ms.encode_size()
                    + price_decimals.encode_size()
                    + max_leverage_bps.encode_size()
                    + maintenance_margin_bps.encode_size()
                    + funding_interval_ms.encode_size()
                    + max_funding_rate_bps.encode_size()
            }
            Self::RefreshMarketFromOracle { market } | Self::SettleFunding { market } => {
                market.encode_size()
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
            Self::AddCollateral { position, amount }
            | Self::ReduceCollateral { position, amount } => {
                position.encode_size() + amount.encode_size()
            }
            Self::ClosePosition { position } | Self::Liquidate { position } => {
                position.encode_size()
            }
        }
    }
}

impl Operation for PerpetualOperation {
    const NAMESPACE: &'static [u8] = PERPETUALS_NAMESPACE;
}

/// Signed perpetuals transaction payload.
pub type TransactionPayload = nunchi_common::TransactionPayload<PerpetualOperation>;
/// Signed perpetuals transaction.
pub type Transaction = nunchi_common::Transaction<PerpetualOperation>;
