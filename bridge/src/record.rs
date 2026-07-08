//! Bridge asset transfer records: the authenticated state a claim proves against.
//!
//! A source-chain lock writes a [`BridgeTransferRecord`] into authenticated state under a
//! deterministic, domain-separated key; a destination-chain claim proves that record and marks it
//! consumed exactly once. This module defines the record schema, its content-addressed id, the
//! state keys, and minimal read/write accessors.
//!
//! Deliberately out of scope here: proof generation/verification, the source-side lock operation,
//! the destination claim operation, the escrow balance table, and coins integration. Those build on
//! this schema in later PRs.

use bytes::{Buf, BufMut};
use commonware_codec::{
    DecodeExt, Encode, Error as CodecError, FixedSize, Read, ReadExt, Write,
};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_common::{
    state_db::{Namespace, StateError, StateStore},
    Address,
};

/// Domain separator for the bridge module's namespaced authenticated state.
pub const BRIDGE_NAMESPACE: &[u8] = b"_NUNCHI_BRIDGE";

/// Versioned domain tag for transfer-record id derivation, so the derivation can evolve safely.
const TRANSFER_ID_DOMAIN: &[u8] = b"nunchi/bridge/transfer/v1";

/// Versioned domain tag for asset-id derivation.
const ASSET_ID_DOMAIN: &[u8] = b"nunchi/bridge/asset/v1";

const NS: Namespace = Namespace::new(BRIDGE_NAMESPACE);

/// Logical maps the bridge module keeps inside its namespace.
#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    /// Append-only transfer records written on the source chain.
    TransferRecord = 0,
    /// Consumed-record markers written on the destination chain (replay guard).
    ConsumedRecord = 1,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

/// Non-empty marker value stored for a consumed record (presence = consumed).
const CONSUMED_MARKER: &[u8] = &[1];

/// Opaque, fixed-width identifier of a chain participating in a bridge.
///
/// The derivation policy (for example a genesis/config hash) is deferred; this is just the stable
/// identifier carried in bridge records.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChainId(pub Digest);

/// Globally-unique, fixed-width identifier of the asset being bridged.
///
/// In the Nunchi<->Nunchi MVP the chain-local asset is a coins `CoinId`, but the bridge crate stays
/// decoupled from the coins module; mapping to a concrete coin lives at the integration layer.
///
/// Constructed only via [`AssetId::derive`], which folds the source chain into the digest so the
/// same local asset on two different chains never yields the same id.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssetId(Digest);

impl AssetId {
    /// Derive a globally-unique asset id from its source chain and chain-local asset identity.
    ///
    /// The source chain is folded into the digest, so two chains can never produce the same asset
    /// id for the same (or any) local asset.
    pub fn derive(source_chain_id: &ChainId, local_asset: &Digest) -> Self {
        let mut bytes = Vec::with_capacity(4 + ASSET_ID_DOMAIN.len() + 2 * Digest::SIZE);
        bytes.extend_from_slice(&(ASSET_ID_DOMAIN.len() as u32).to_be_bytes());
        bytes.extend_from_slice(ASSET_ID_DOMAIN);
        bytes.extend_from_slice(source_chain_id.encode().as_ref());
        bytes.extend_from_slice(local_asset.encode().as_ref());
        Self(Sha256::hash(&bytes))
    }

    /// The underlying digest.
    pub fn digest(&self) -> Digest {
        self.0
    }
}

/// Content-addressed identity of a [`BridgeTransferRecord`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransferRecordId(pub Digest);

macro_rules! digest_newtype_codec {
    ($ty:ty) => {
        impl Write for $ty {
            fn write(&self, buf: &mut impl BufMut) {
                self.0.write(buf);
            }
        }

        impl Read for $ty {
            type Cfg = ();

            fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
                Ok(Self(Digest::read(buf)?))
            }
        }

        impl FixedSize for $ty {
            const SIZE: usize = Digest::SIZE;
        }
    };
}

digest_newtype_codec!(ChainId);
digest_newtype_codec!(AssetId);
digest_newtype_codec!(TransferRecordId);

/// A cross-chain asset transfer, written to authenticated state on the source chain and proven by a
/// destination-chain claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeTransferRecord {
    /// Chain the asset is locked/burned on.
    pub source_chain_id: ChainId,
    /// Chain the asset is minted/released on.
    pub destination_chain_id: ChainId,
    /// Opaque source-chain asset identifier.
    pub source_asset: AssetId,
    /// Amount transferred.
    pub amount: u128,
    /// Source-chain account that locked/burned the asset.
    pub sender: Address,
    /// Destination-chain account to credit.
    pub recipient: Address,
    /// Source-side record nonce. The assignment policy (per-sender vs. global) is defined by the
    /// source lock operation, not here.
    pub nonce: u64,
}

impl BridgeTransferRecord {
    /// Deterministic, domain-separated content id over the canonical encoding of every field.
    pub fn record_id(&self) -> TransferRecordId {
        let mut bytes = Vec::with_capacity(4 + TRANSFER_ID_DOMAIN.len() + Self::SIZE);
        bytes.extend_from_slice(&(TRANSFER_ID_DOMAIN.len() as u32).to_be_bytes());
        bytes.extend_from_slice(TRANSFER_ID_DOMAIN);
        bytes.extend_from_slice(self.encode().as_ref());
        TransferRecordId(Sha256::hash(&bytes))
    }
}

impl Write for BridgeTransferRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.source_chain_id.write(buf);
        self.destination_chain_id.write(buf);
        self.source_asset.write(buf);
        self.amount.write(buf);
        self.sender.write(buf);
        self.recipient.write(buf);
        self.nonce.write(buf);
    }
}

impl Read for BridgeTransferRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
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

impl FixedSize for BridgeTransferRecord {
    const SIZE: usize = ChainId::SIZE
        + ChainId::SIZE
        + AssetId::SIZE
        + u128::SIZE
        + Address::SIZE
        + Address::SIZE
        + u64::SIZE;
}

/// Authenticated-state key for the transfer record `id`.
pub fn transfer_record_key(id: &TransferRecordId) -> Digest {
    NS.key(Table::TransferRecord, id.encode().as_ref())
}

/// Authenticated-state key for the consumed marker of `id`, scoped by its source chain.
pub fn consumed_record_key(source_chain_id: &ChainId, id: &TransferRecordId) -> Digest {
    let mut logical = source_chain_id.encode().as_ref().to_vec();
    logical.extend_from_slice(id.encode().as_ref());
    NS.key(Table::ConsumedRecord, &logical)
}

/// Stage a transfer record at its deterministic key. Records are append-only: a given `record_id`
/// maps to exactly one record and must not be rewritten.
pub fn put_transfer_record<S: StateStore>(store: &mut S, record: &BridgeTransferRecord) {
    let key = transfer_record_key(&record.record_id());
    store.set(key, record.encode().as_ref().to_vec());
}

/// Read the transfer record with `id`, if present.
pub async fn transfer_record<S: StateStore>(
    store: &S,
    id: &TransferRecordId,
) -> Result<Option<BridgeTransferRecord>, StateError> {
    match store.get(&transfer_record_key(id)).await? {
        Some(bytes) => BridgeTransferRecord::decode(bytes.as_ref())
            .map(Some)
            .map_err(|err| StateError::Backend(err.to_string())),
        None => Ok(None),
    }
}

/// Mark the transfer record `id` consumed (claimed). Scoped by source chain so ids from different
/// source chains never alias.
pub fn mark_consumed<S: StateStore>(
    store: &mut S,
    source_chain_id: &ChainId,
    id: &TransferRecordId,
) {
    store.set(consumed_record_key(source_chain_id, id), CONSUMED_MARKER.to_vec());
}

/// Whether the transfer record `id` from `source_chain_id` has already been consumed.
pub async fn is_consumed<S: StateStore>(
    store: &S,
    source_chain_id: &ChainId,
    id: &TransferRecordId,
) -> Result<bool, StateError> {
    Ok(store
        .get(&consumed_record_key(source_chain_id, id))
        .await?
        .is_some())
}
