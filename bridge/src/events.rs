//! Bridge module events.

use crate::record::{AssetId, ChainId, TransferRecordId};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Event};

/// Topic for the event emitted when a source-chain lock records a transfer.
pub const TRANSFER_LOCKED_EVENT: &[u8] = b"bridge.transfer_locked.v1";
/// Topic for the event emitted when an attested foreign root is anchored.
pub const FOREIGN_ROOT_ANCHORED_EVENT: &[u8] = b"bridge.foreign_root_anchored.v1";
/// Topic for the event emitted when a transfer is claimed on the destination chain.
pub const TRANSFER_CLAIMED_EVENT: &[u8] = b"bridge.transfer_claimed.v1";

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

/// Emitted when the attestor anchors a foreign state root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForeignRootAnchored {
    pub source_chain_id: ChainId,
    pub view: u64,
    pub state_root: Digest,
}

impl Write for ForeignRootAnchored {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.source_chain_id.write(buf);
        self.view.write(buf);
        self.state_root.write(buf);
    }
}

impl Read for ForeignRootAnchored {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            source_chain_id: ChainId::read(buf)?,
            view: u64::read(buf)?,
            state_root: Digest::read(buf)?,
        })
    }
}

impl EncodeSize for ForeignRootAnchored {
    fn encode_size(&self) -> usize {
        self.source_chain_id.encode_size() + self.view.encode_size() + self.state_root.encode_size()
    }
}

/// Build the [`Event`] for an anchored foreign root.
pub fn foreign_root_anchored_event(value: ForeignRootAnchored) -> Event {
    Event::new(
        bytes::Bytes::from_static(FOREIGN_ROOT_ANCHORED_EVENT),
        value.encode(),
    )
}

/// Emitted when a transfer is claimed (proven and marked consumed) on the destination chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferClaimed {
    pub record_id: TransferRecordId,
    pub source_chain_id: ChainId,
    pub source_view: u64,
    pub source_asset: AssetId,
    pub recipient: Address,
    pub amount: u128,
}

impl Write for TransferClaimed {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.record_id.write(buf);
        self.source_chain_id.write(buf);
        self.source_view.write(buf);
        self.source_asset.write(buf);
        self.recipient.write(buf);
        self.amount.write(buf);
    }
}

impl Read for TransferClaimed {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            record_id: TransferRecordId::read(buf)?,
            source_chain_id: ChainId::read(buf)?,
            source_view: u64::read(buf)?,
            source_asset: AssetId::read(buf)?,
            recipient: Address::read(buf)?,
            amount: u128::read(buf)?,
        })
    }
}

impl EncodeSize for TransferClaimed {
    fn encode_size(&self) -> usize {
        self.record_id.encode_size()
            + self.source_chain_id.encode_size()
            + self.source_view.encode_size()
            + self.source_asset.encode_size()
            + self.recipient.encode_size()
            + self.amount.encode_size()
    }
}

/// Build the [`Event`] for a claimed transfer.
pub fn transfer_claimed_event(value: TransferClaimed) -> Event {
    Event::new(
        bytes::Bytes::from_static(TRANSFER_CLAIMED_EVENT),
        value.encode(),
    )
}
