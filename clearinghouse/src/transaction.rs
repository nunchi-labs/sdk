use crate::CLEARINGHOUSE_NAMESPACE;
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_clob::{Fill, FillId, MarketId as ClobMarketId};
use nunchi_common::Operation as CommonOperation;
use nunchi_perpetuals::MarketId as PerpsMarketId;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationTag {
    RegisterPerpsMarket = 0,
    SettleFill = 1,
    CommitAndSettleFill = 2,
}

impl TryFrom<u8> for OperationTag {
    type Error = Error;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            0 => Ok(Self::RegisterPerpsMarket),
            1 => Ok(Self::SettleFill),
            2 => Ok(Self::CommitAndSettleFill),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

/// Clearinghouse state-machine operation carried by a signed Nunchi transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClearinghouseOperation {
    /// Link a CLOB market to a perpetuals market for fill settlement.
    RegisterPerpsMarket {
        clob_market: ClobMarketId,
        perps_market: PerpsMarketId,
    },
    /// Apply a previously matched CLOB fill to registered settlement consumers.
    SettleFill { fill: FillId },
    /// Commit an off-chain fill to CLOB state and settle it into perpetuals in one step.
    CommitAndSettleFill { fill: Box<Fill> },
}

impl Write for ClearinghouseOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::RegisterPerpsMarket {
                clob_market,
                perps_market,
            } => {
                (OperationTag::RegisterPerpsMarket as u8).write(buf);
                clob_market.write(buf);
                perps_market.write(buf);
            }
            Self::SettleFill { fill } => {
                (OperationTag::SettleFill as u8).write(buf);
                fill.write(buf);
            }
            Self::CommitAndSettleFill { fill } => {
                (OperationTag::CommitAndSettleFill as u8).write(buf);
                fill.write(buf);
            }
        }
    }
}

impl Read for ClearinghouseOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match OperationTag::try_from(u8::read(buf)?)? {
            OperationTag::RegisterPerpsMarket => Ok(Self::RegisterPerpsMarket {
                clob_market: ClobMarketId::read(buf)?,
                perps_market: PerpsMarketId::read(buf)?,
            }),
            OperationTag::SettleFill => Ok(Self::SettleFill {
                fill: FillId::read(buf)?,
            }),
            OperationTag::CommitAndSettleFill => Ok(Self::CommitAndSettleFill {
                fill: Box::new(Fill::read(buf)?),
            }),
        }
    }
}

impl EncodeSize for ClearinghouseOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::RegisterPerpsMarket {
                clob_market,
                perps_market,
            } => clob_market.encode_size() + perps_market.encode_size(),
            Self::SettleFill { fill } => fill.encode_size(),
            Self::CommitAndSettleFill { fill } => fill.encode_size(),
        }
    }
}

impl CommonOperation for ClearinghouseOperation {
    const NAMESPACE: &'static [u8] = CLEARINGHOUSE_NAMESPACE;
}

/// Signed clearinghouse transaction payload.
pub type TransactionPayload = nunchi_common::TransactionPayload<ClearinghouseOperation>;
/// Signed clearinghouse transaction.
pub type Transaction = nunchi_common::Transaction<ClearinghouseOperation>;
