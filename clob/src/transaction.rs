use crate::{AssetId, Fill, MarketId, OrderId, Side, TimeInForce, CLOB_NAMESPACE};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::Operation as CommonOperation;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationTag {
    CreateMarket = 0,
    PlaceOrder = 1,
    CancelOrder = 2,
    CommitFill = 3,
}

impl TryFrom<u8> for OperationTag {
    type Error = Error;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            0 => Ok(Self::CreateMarket),
            1 => Ok(Self::PlaceOrder),
            2 => Ok(Self::CancelOrder),
            3 => Ok(Self::CommitFill),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

/// CLOB state-machine operation carried by a signed Nunchi transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClobOperation {
    /// Create a permissionless spot market for a base/quote pair.
    CreateMarket {
        base_asset: AssetId,
        quote_asset: AssetId,
        tick_size: u128,
        lot_size: u128,
    },
    /// Place a limit order and match it against the opposite side if possible.
    PlaceOrder {
        market: MarketId,
        side: Side,
        price: u128,
        base_quantity: u128,
        time_in_force: TimeInForce,
    },
    /// Cancel one open order owned by the signer.
    CancelOrder { order: OrderId },
    /// Commit a match produced by an in-memory book for on-chain settlement.
    CommitFill { fill: Fill },
}

impl Write for ClobOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::CreateMarket {
                base_asset,
                quote_asset,
                tick_size,
                lot_size,
            } => {
                (OperationTag::CreateMarket as u8).write(buf);
                base_asset.write(buf);
                quote_asset.write(buf);
                tick_size.write(buf);
                lot_size.write(buf);
            }
            Self::PlaceOrder {
                market,
                side,
                price,
                base_quantity,
                time_in_force,
            } => {
                (OperationTag::PlaceOrder as u8).write(buf);
                market.write(buf);
                side.write(buf);
                price.write(buf);
                base_quantity.write(buf);
                time_in_force.write(buf);
            }
            Self::CancelOrder { order } => {
                (OperationTag::CancelOrder as u8).write(buf);
                order.write(buf);
            }
            Self::CommitFill { fill } => {
                (OperationTag::CommitFill as u8).write(buf);
                fill.write(buf);
            }
        }
    }
}

impl Read for ClobOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match OperationTag::try_from(u8::read(buf)?)? {
            OperationTag::CreateMarket => Ok(Self::CreateMarket {
                base_asset: AssetId::read(buf)?,
                quote_asset: AssetId::read(buf)?,
                tick_size: u128::read(buf)?,
                lot_size: u128::read(buf)?,
            }),
            OperationTag::PlaceOrder => Ok(Self::PlaceOrder {
                market: MarketId::read(buf)?,
                side: Side::read(buf)?,
                price: u128::read(buf)?,
                base_quantity: u128::read(buf)?,
                time_in_force: TimeInForce::read(buf)?,
            }),
            OperationTag::CancelOrder => Ok(Self::CancelOrder {
                order: OrderId::read(buf)?,
            }),
            OperationTag::CommitFill => Ok(Self::CommitFill {
                fill: Fill::read(buf)?,
            }),
        }
    }
}

impl EncodeSize for ClobOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::CreateMarket {
                base_asset,
                quote_asset,
                tick_size,
                lot_size,
            } => {
                base_asset.encode_size()
                    + quote_asset.encode_size()
                    + tick_size.encode_size()
                    + lot_size.encode_size()
            }
            Self::PlaceOrder {
                market,
                side,
                price,
                base_quantity,
                time_in_force,
            } => {
                market.encode_size()
                    + side.encode_size()
                    + price.encode_size()
                    + base_quantity.encode_size()
                    + time_in_force.encode_size()
            }
            Self::CancelOrder { order } => order.encode_size(),
            Self::CommitFill { fill } => fill.encode_size(),
        }
    }
}

impl CommonOperation for ClobOperation {
    const NAMESPACE: &'static [u8] = CLOB_NAMESPACE;
}

/// Signed CLOB transaction payload.
pub type TransactionPayload = nunchi_common::TransactionPayload<ClobOperation>;
/// Signed CLOB transaction.
pub type Transaction = nunchi_common::Transaction<ClobOperation>;
