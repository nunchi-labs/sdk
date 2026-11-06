use crate::{
    AssetId, Fill, MarketId, OrderId, Side, TimeInForce, MAX_MATCH_BATCH_FILLS,
    MAX_MATCH_BATCH_ORDERS, CLOB_NAMESPACE,
};
use commonware_codec::{EncodeSize, Error, FixedSize, MaxEncodeSize, RangeCfg, Read, ReadExt, Write};
use nunchi_common::{items_bound, Address, Authorization};
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

/// Widest CLOB operation that can appear as a signed order inside a match batch.
///
/// `ApplyMatchBatch` is not included. A batch carries order intents, and nesting another batch
/// would make the encoded size unbounded.
const MAX_ORDER_OPERATION_ENCODE_SIZE: usize = {
    let create = 1 + AssetId::SIZE + AssetId::SIZE + u128::SIZE + u128::SIZE;
    let place = 1 + MarketId::SIZE + u8::SIZE + u128::SIZE + u128::SIZE + u8::SIZE;
    let cancel = 1 + OrderId::SIZE;
    let mut max = create;
    if place > max {
        max = place;
    }
    if cancel > max {
        max = cancel;
    }
    max
};

/// Widest signed order a match batch will accept.
pub(crate) const MAX_SIGNED_ORDER_ENCODE_SIZE: usize = Address::SIZE
    + u64::SIZE
    + MAX_ORDER_OPERATION_ENCODE_SIZE
    + Authorization::MAX_ENCODE_SIZE;

fn bounded_order(order: &Transaction) -> bool {
    order.encode_size() <= MAX_SIGNED_ORDER_ENCODE_SIZE
        && !matches!(order.payload.operation, ClobOperation::ApplyMatchBatch { .. })
}

fn order_encode_bound_error() -> Error {
    Error::Invalid(
        "nunchi_clob::MatchBatch",
        "order exceeds the signed-order encode bound",
    )
}

/// Proposer-supplied CLOB match batch carried in a block extension.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MatchBatch {
    /// Fresh signed owner order intents whose nonces should advance if replay succeeds.
    pub orders: Vec<Transaction>,
    /// Fills derived from committed resting orders and replaying `orders`.
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

    fn read_cfg(buf: &mut impl commonware_codec::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            orders: read_bounded_orders(buf)?,
            fills: Vec::read_cfg(buf, &(RangeCfg::new(0..=MAX_MATCH_BATCH_FILLS), ()))?,
        })
    }
}

// Orders inside a batch stay within `MAX_SIGNED_ORDER_ENCODE_SIZE`.
// A nested `ApplyMatchBatch` is rejected from its tag, before the nested batch body is read.
// Reading that body first would parse another full batch, so the encode bound would not hold
// during decode.
fn read_bounded_orders(buf: &mut impl commonware_codec::Buf) -> Result<Vec<Transaction>, Error> {
    let len = usize::read_cfg(buf, &RangeCfg::new(0..=MAX_MATCH_BATCH_ORDERS))?;
    let mut orders = Vec::with_capacity(len);
    for _ in 0..len {
        orders.push(read_bounded_order(buf)?);
    }
    Ok(orders)
}

fn read_bounded_order(buf: &mut impl commonware_codec::Buf) -> Result<Transaction, Error> {
    let account_id = Address::read(buf)?;
    let nonce = u64::read(buf)?;
    let operation = match OperationTag::try_from(u8::read(buf)?)? {
        OperationTag::ApplyMatchBatch => return Err(order_encode_bound_error()),
        tag => read_operation(buf, tag)?,
    };
    let authorization = Authorization::read(buf)?;
    if let Authorization::Single { signer, signature } = &authorization {
        if signer.curve() != signature.curve() {
            return Err(Error::Invalid(
                "transaction",
                "signature curve does not match signer curve",
            ));
        }
    }
    let order = Transaction {
        account_id,
        payload: TransactionPayload::new(nonce, operation),
        authorization,
    };
    if !bounded_order(&order) {
        return Err(order_encode_bound_error());
    }
    Ok(order)
}

impl MaxEncodeSize for MatchBatch {
    const MAX_ENCODE_SIZE: usize = items_bound(MAX_MATCH_BATCH_ORDERS, MAX_SIGNED_ORDER_ENCODE_SIZE)
        + items_bound(MAX_MATCH_BATCH_FILLS, Fill::MAX_ENCODE_SIZE);
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
    /// Proposer match batch payload. The transaction runtime rejects this; it is
    /// only applied through the consensus extension after validator replay.
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

    fn read_cfg(buf: &mut impl commonware_codec::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let tag = OperationTag::try_from(u8::read(buf)?)?;
        read_operation(buf, tag)
    }
}

fn read_operation(
    buf: &mut impl commonware_codec::Buf,
    tag: OperationTag,
) -> Result<ClobOperation, Error> {
    match tag {
        OperationTag::CreateMarket => Ok(ClobOperation::CreateMarket {
            base_asset: AssetId::read(buf)?,
            quote_asset: AssetId::read(buf)?,
            tick_size: u128::read(buf)?,
            lot_size: u128::read(buf)?,
        }),
        OperationTag::PlaceOrder => Ok(ClobOperation::PlaceOrder {
            market: MarketId::read(buf)?,
            side: Side::read(buf)?,
            price: u128::read(buf)?,
            base_quantity: u128::read(buf)?,
            time_in_force: TimeInForce::read(buf)?,
        }),
        OperationTag::CancelOrder => Ok(ClobOperation::CancelOrder {
            order: OrderId::read(buf)?,
        }),
        OperationTag::ApplyMatchBatch => Ok(ClobOperation::ApplyMatchBatch {
            batch: MatchBatch::read(buf)?,
        }),
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

impl MaxEncodeSize for ClobOperation {
    const MAX_ENCODE_SIZE: usize = {
        let batch = 1 + MatchBatch::MAX_ENCODE_SIZE;
        if batch > MAX_ORDER_OPERATION_ENCODE_SIZE {
            batch
        } else {
            MAX_ORDER_OPERATION_ENCODE_SIZE
        }
    };
}

/// Signed CLOB transaction payload.
pub type TransactionPayload = nunchi_common::TransactionPayload<ClobOperation>;
/// Signed CLOB transaction.
pub type Transaction = nunchi_common::Transaction<ClobOperation>;
