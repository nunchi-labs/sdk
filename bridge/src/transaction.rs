//! Signed bridge operations.

use crate::record::{BridgeTransferRecord, ChainId, BRIDGE_NAMESPACE};
use commonware_codec::{EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{
    state_db::{StateProof, StateProofCfg},
    Address, Operation,
};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeOperationId {
    Lock = 0,
    AnchorForeignRoot = 1,
    Claim = 2,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid bridge operation id: {0}")]
pub struct InvalidBridgeOperationId(u8);

impl TryFrom<u8> for BridgeOperationId {
    type Error = InvalidBridgeOperationId;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Lock),
            1 => Ok(Self::AnchorForeignRoot),
            2 => Ok(Self::Claim),
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

/// Fixed decoding limits for a claim's embedded [`StateProof`].
///
/// A `BridgeOperation` must decode with `Cfg = ()` (the [`Operation`] contract), but a `StateProof`
/// needs explicit allocation bounds. These bridge-internal bounds are applied when reading a claim's
/// proof, so the operation stays self-contained while still capping attacker-controlled allocation.
fn claim_proof_cfg() -> StateProofCfg {
    StateProofCfg {
        max_proof_digests: 4096,
        operations: RangeCfg::new(0..=4096usize),
        value_len: RangeCfg::new(0..=65536usize),
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
    /// Anchor an attested foreign state root that destination claims verify against.
    ///
    /// Only the genesis-configured attestor may submit this, and the view must be strictly monotonic
    /// per source chain. This is a trusted/authority-attested anchor for the MVP, not a cryptographic
    /// finalization proof.
    AnchorForeignRoot {
        /// The foreign source chain this root belongs to.
        source_chain_id: ChainId,
        /// Monotonic view/height selecting this root among the source chain's history.
        view: u64,
        /// The foreign chain's authenticated state root at `view`.
        state_root: Digest,
    },
    /// Claim a transfer on the destination chain by proving its record against an anchored foreign
    /// root; settlement to the recipient happens in the integration layer.
    Claim {
        /// The source chain the transfer originated on.
        source_chain_id: ChainId,
        /// The anchored view whose root `proof` verifies against.
        source_view: u64,
        /// The transfer record being claimed. It is content-addressed, so `proof` authenticates
        /// exactly this record and no substitute.
        record: BridgeTransferRecord,
        /// Inclusion proof that `record` is committed under the anchored foreign root.
        proof: StateProof,
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
            Self::AnchorForeignRoot {
                source_chain_id,
                view,
                state_root,
            } => {
                BridgeOperationId::AnchorForeignRoot.write(buf);
                source_chain_id.write(buf);
                view.write(buf);
                state_root.write(buf);
            }
            Self::Claim {
                source_chain_id,
                source_view,
                record,
                proof,
            } => {
                BridgeOperationId::Claim.write(buf);
                source_chain_id.write(buf);
                source_view.write(buf);
                record.write(buf);
                proof.write(buf);
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
            BridgeOperationId::AnchorForeignRoot => Ok(Self::AnchorForeignRoot {
                source_chain_id: ChainId::read(buf)?,
                view: u64::read(buf)?,
                state_root: Digest::read(buf)?,
            }),
            BridgeOperationId::Claim => Ok(Self::Claim {
                source_chain_id: ChainId::read(buf)?,
                source_view: u64::read(buf)?,
                record: BridgeTransferRecord::read(buf)?,
                // Decode the embedded proof with fixed bridge-internal bounds so the operation's
                // own `Read` stays `Cfg = ()`.
                proof: StateProof::read_cfg(buf, &claim_proof_cfg())?,
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
            Self::AnchorForeignRoot {
                source_chain_id,
                view,
                state_root,
            } => source_chain_id.encode_size() + view.encode_size() + state_root.encode_size(),
            Self::Claim {
                source_chain_id,
                source_view,
                record,
                proof,
            } => {
                source_chain_id.encode_size()
                    + source_view.encode_size()
                    + record.encode_size()
                    + proof.encode_size()
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
