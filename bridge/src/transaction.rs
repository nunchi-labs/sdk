//! Signed bridge operations.

use crate::record::{ChainId, BRIDGE_NAMESPACE};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Operation};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeOperationId {
    Lock = 0,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid bridge operation id: {0}")]
pub struct InvalidBridgeOperationId(u8);

impl TryFrom<u8> for BridgeOperationId {
    type Error = InvalidBridgeOperationId;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Lock),
            _ => Err(InvalidBridgeOperationId(value)),
        }
    }
}

impl Write for BridgeOperationId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_u8(*self as u8);
    }
}

impl Read for BridgeOperationId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let value = u8::read(buf)?;
        Self::try_from(value)
            .map_err(|_| Error::Invalid("BridgeOperationId", "invalid operation id"))
    }
}

/// A bridge operation authorized by a signed transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeOperation {
    /// Lock a source-chain asset and record a cross-chain transfer for a destination claim.
    Lock {
        /// Chain the asset is claimed/minted on.
        destination_chain_id: ChainId,
        /// Chain-local asset identity (for example a coins `CoinId` digest). Folded into the
        /// record's globally-unique `source_asset` via [`crate::record::AssetId::derive`], so the
        /// bridge operation stays decoupled from any concrete asset module.
        local_asset: Digest,
        /// Amount to transfer.
        amount: u128,
        /// Destination-chain account to credit.
        recipient: Address,
    },
}

impl Write for BridgeOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Lock {
                destination_chain_id,
                local_asset,
                amount,
                recipient,
            } => {
                BridgeOperationId::Lock.write(buf);
                destination_chain_id.write(buf);
                local_asset.write(buf);
                amount.write(buf);
                recipient.write(buf);
            }
        }
    }
}

impl Read for BridgeOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match BridgeOperationId::read(buf)? {
            BridgeOperationId::Lock => Ok(Self::Lock {
                destination_chain_id: ChainId::read(buf)?,
                local_asset: Digest::read(buf)?,
                amount: u128::read(buf)?,
                recipient: Address::read(buf)?,
            }),
        }
    }
}

impl EncodeSize for BridgeOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Lock {
                destination_chain_id,
                local_asset,
                amount,
                recipient,
            } => {
                destination_chain_id.encode_size()
                    + local_asset.encode_size()
                    + amount.encode_size()
                    + recipient.encode_size()
            }
        }
    }
}

impl Operation for BridgeOperation {
    const NAMESPACE: &'static [u8] = BRIDGE_NAMESPACE;
}

/// A signed bridge transaction.
pub type Transaction = nunchi_common::Transaction<BridgeOperation>;
/// The payload of a signed bridge transaction.
pub type TransactionPayload = nunchi_common::TransactionPayload<BridgeOperation>;
