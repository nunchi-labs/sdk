use crate::{
    AssetId, Fill, MarketId, OrderId, Side, TimeInForce, MAX_MATCH_BATCH_FILLS,
    MAX_MATCH_BATCH_ORDERS, CLOB_NAMESPACE,
};
use commonware_codec::{EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use nunchi_common::Operation as CommonOperation;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationTag {
    CreateMarket = 0,
    PlaceOrder = 1,
    CancelOrder = 2,
    ApplyMatchBatch = 3,
}

impl TryFrom<u8> for OperationTag {
    type Error = Error;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            0 => Ok(Self::CreateMarket),
            1 => Ok(Self::PlaceOrder),
            2 => Ok(Self::CancelOrder),
            3 => Ok(Self::ApplyMatchBatch),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

/// Proposer-supplied CLOB match batch carried in a block extension.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MatchBatch {
    /// Signed owner order intents used as matcher input.
    pub orders: Vec<Transaction>,
    /// Fills derived from replaying `orders` with deterministic price-time priority.
    pub fills: Vec<Fill>,
}

impl MatchBatch {
    pub fn is_empty(&self) -> bool {
        self.orders.is_empty() && self.fills.is_empty()
    }
}

impl Write for MatchBatch {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.orders.write(buf);
        self.fills.write(buf);
    }
}

impl Read for MatchBatch {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            orders: Vec::read_cfg(buf, &(RangeCfg::new(0..=MAX_MATCH_BATCH_ORDERS), ()))?,
            fills: Vec::read_cfg(buf, &(RangeCfg::new(0..=MAX_MATCH_BATCH_FILLS), ()))?,
        })
    }
}

impl EncodeSize for MatchBatch {
    fn encode_size(&self) -> usize {
        self.orders.encode_size() + self.fills.encode_size()
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
    /// Signed limit-order intent for the off-chain matcher.
    PlaceOrder {
        market: MarketId,
        side: Side,
        price: u128,
        base_quantity: u128,
        time_in_force: TimeInForce,
    },
    /// Signed cancellation intent for validator-local books.
    CancelOrder { order: OrderId },
    /// Apply one proposer match batch after validators replay signed orders.
    ApplyMatchBatch { batch: MatchBatch },
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
            Self::ApplyMatchBatch { batch } => {
                (OperationTag::ApplyMatchBatch as u8).write(buf);
                batch.write(buf);
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
            OperationTag::ApplyMatchBatch => Ok(Self::ApplyMatchBatch {
                batch: MatchBatch::read(buf)?,
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
            Self::ApplyMatchBatch { batch } => batch.encode_size(),
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
