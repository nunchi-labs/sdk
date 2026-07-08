use crate::{BatchParams, IntentId, CBC_NAMESPACE};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_clob::{MarketId, Side};
use nunchi_common::Operation as CommonOperation;
use nunchi_house::{Mode, VaultId};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationTag {
    RegisterMarket = 0,
    SetClearingMode = 1,
    SubmitIntent = 2,
    CancelIntent = 3,
    CloseAndClearBatch = 4,
}

impl TryFrom<u8> for OperationTag {
    type Error = Error;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            0 => Ok(Self::RegisterMarket),
            1 => Ok(Self::SetClearingMode),
            2 => Ok(Self::SubmitIntent),
            3 => Ok(Self::CancelIntent),
            4 => Ok(Self::CloseAndClearBatch),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

/// CBC state-machine operation carried by a signed Nunchi transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CbcOperation {
    /// Register a market for batch clearing. The signer must be the admin
    /// named in the parameters.
    RegisterMarket {
        market: MarketId,
        params: BatchParams,
    },
    /// Change the clearing mode of a registered market.
    SetClearingMode { market: MarketId, mode: Mode },
    /// Submit a liquidity-management intent into the market's open batch.
    SubmitIntent {
        market: MarketId,
        vault: VaultId,
        side: Side,
        limit_price: u128,
        base_quantity: u128,
        reduce_only: bool,
        expiry_height: u64,
    },
    /// Cancel one open intent.
    CancelIntent { intent: IntentId },
    /// Close the open batch and clear it at one uniform price.
    ///
    /// The keeper posts the registry-approved oracle price; this is a
    /// documented trust seam until chain-level oracle wiring lands.
    CloseAndClearBatch { market: MarketId, oracle_price: u128 },
}

impl Write for CbcOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::RegisterMarket { market, params } => {
                (OperationTag::RegisterMarket as u8).write(buf);
                market.write(buf);
                params.write(buf);
            }
            Self::SetClearingMode { market, mode } => {
                (OperationTag::SetClearingMode as u8).write(buf);
                market.write(buf);
                mode.write(buf);
            }
            Self::SubmitIntent {
                market,
                vault,
                side,
                limit_price,
                base_quantity,
                reduce_only,
                expiry_height,
            } => {
                (OperationTag::SubmitIntent as u8).write(buf);
                market.write(buf);
                vault.write(buf);
                side.write(buf);
                limit_price.write(buf);
                base_quantity.write(buf);
                reduce_only.write(buf);
                expiry_height.write(buf);
            }
            Self::CancelIntent { intent } => {
                (OperationTag::CancelIntent as u8).write(buf);
                intent.write(buf);
            }
            Self::CloseAndClearBatch {
                market,
                oracle_price,
            } => {
                (OperationTag::CloseAndClearBatch as u8).write(buf);
                market.write(buf);
                oracle_price.write(buf);
            }
        }
    }
}

impl Read for CbcOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match OperationTag::try_from(u8::read(buf)?)? {
            OperationTag::RegisterMarket => Ok(Self::RegisterMarket {
                market: MarketId::read(buf)?,
                params: BatchParams::read(buf)?,
            }),
            OperationTag::SetClearingMode => Ok(Self::SetClearingMode {
                market: MarketId::read(buf)?,
                mode: Mode::read(buf)?,
            }),
            OperationTag::SubmitIntent => Ok(Self::SubmitIntent {
                market: MarketId::read(buf)?,
                vault: VaultId::read(buf)?,
                side: Side::read(buf)?,
                limit_price: u128::read(buf)?,
                base_quantity: u128::read(buf)?,
                reduce_only: bool::read(buf)?,
                expiry_height: u64::read(buf)?,
            }),
            OperationTag::CancelIntent => Ok(Self::CancelIntent {
                intent: IntentId::read(buf)?,
            }),
            OperationTag::CloseAndClearBatch => Ok(Self::CloseAndClearBatch {
                market: MarketId::read(buf)?,
                oracle_price: u128::read(buf)?,
            }),
        }
    }
}

impl EncodeSize for CbcOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::RegisterMarket { market, params } => market.encode_size() + params.encode_size(),
            Self::SetClearingMode { market, mode } => market.encode_size() + mode.encode_size(),
            Self::SubmitIntent {
                market,
                vault,
                side,
                limit_price,
                base_quantity,
                reduce_only,
                expiry_height,
            } => {
                market.encode_size()
                    + vault.encode_size()
                    + side.encode_size()
                    + limit_price.encode_size()
                    + base_quantity.encode_size()
                    + reduce_only.encode_size()
                    + expiry_height.encode_size()
            }
            Self::CancelIntent { intent } => intent.encode_size(),
            Self::CloseAndClearBatch {
                market,
                oracle_price,
            } => market.encode_size() + oracle_price.encode_size(),
        }
    }
}

impl CommonOperation for CbcOperation {
    const NAMESPACE: &'static [u8] = CBC_NAMESPACE;
}

/// Signed CBC transaction payload.
pub type TransactionPayload = nunchi_common::TransactionPayload<CbcOperation>;
/// Signed CBC transaction.
pub type Transaction = nunchi_common::Transaction<CbcOperation>;
