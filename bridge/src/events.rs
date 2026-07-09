//! Bridge module events.

use crate::record::{AssetId, ChainId, TransferRecordId};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::{Address, Event};

/// Topic for the event emitted when a source-chain lock records a transfer.
pub const TRANSFER_LOCKED_EVENT: &[u8] = b"bridge.transfer_locked.v1";

/// Emitted when a source-chain lock writes a [`crate::record::BridgeTransferRecord`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferLocked {
    pub record_id: TransferRecordId,
    pub source_chain_id: ChainId,
    pub destination_chain_id: ChainId,
    pub source_asset: AssetId,
    pub amount: u128,
    pub sender: Address,
    pub recipient: Address,
    pub nonce: u64,
}

impl Write for TransferLocked {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.record_id.write(buf);
        self.source_chain_id.write(buf);
        self.destination_chain_id.write(buf);
        self.source_asset.write(buf);
        self.amount.write(buf);
        self.sender.write(buf);
        self.recipient.write(buf);
        self.nonce.write(buf);
    }
}

impl Read for TransferLocked {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            record_id: TransferRecordId::read(buf)?,
            source_chain_id: ChainId::read(buf)?,
            destination_chain_id: ChainId::read(buf)?,
            source_asset: AssetId::read(buf)?,
            amount: u128::read(buf)?,
            sender: Address::read(buf)?,
            recipient: Address::read(buf)?,
            nonce: u64::read(buf)?,
        })
    }
}

impl EncodeSize for TransferLocked {
    fn encode_size(&self) -> usize {
        self.record_id.encode_size()
            + self.source_chain_id.encode_size()
            + self.destination_chain_id.encode_size()
            + self.source_asset.encode_size()
            + self.amount.encode_size()
            + self.sender.encode_size()
            + self.recipient.encode_size()
            + self.nonce.encode_size()
    }
}

/// Build the [`Event`] for a recorded lock.
pub fn transfer_locked_event(value: TransferLocked) -> Event {
    Event::new(
        bytes::Bytes::from_static(TRANSFER_LOCKED_EVENT),
        value.encode(),
    )
}
