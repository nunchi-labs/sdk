use std::num::NonZeroU32;

use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{types::Height, CertifiableBlock, Heightable};
use commonware_cryptography::{sha256::Digest, Committable, Digestible, Hasher, Sha256};
use commonware_parallel::Strategy;
use commonware_storage::mmr::Location;
use commonware_utils::range::NonEmptyRange;
use nunchi_dkg::{Context, DealerLog, Finalization, Notarization, ReshareBlock, Scheme};
use commonware_utils::sys_rng;

use crate::{BlockExtension, NoConsensusExtension};

/// Upper bound on the number of runtime transactions a single block may carry.
///
/// Bounds the work a peer can force us to do when decoding an untrusted block.
pub const MAX_TRANSACTIONS: u64 = 4_096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateCommitment {
    /// Authenticated state root after executing the block's transactions.
    pub root: Digest,

    /// QMDB operation range that supports state sync to `root`.
    pub range: NonEmptyRange<Location>,
}

#[derive(Debug)]
pub struct Block<Tx, Ext = NoConsensusExtension>
where
    Ext: BlockExtension,
{
    /// The consensus context when this block was proposed.
    pub context: Context,

    /// The parent block's digest.
    pub parent: Digest,

    /// The height of the block in the blockchain.
    pub height: Height,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    pub timestamp: u64,

    /// Runtime transactions to execute when this block is finalized.
    pub transactions: Vec<Tx>,

    /// Optional DKG resharing payload included outside ordinary runtime transactions.
    pub reshare_log: Option<DealerLog>,

    /// Additional consensus-side payload included outside ordinary runtime transactions.
    pub extension: Ext::Payload,

    /// Authenticated state root after executing `transactions`.
    pub state_root: Digest,

    /// QMDB operation range that supports state sync to `state_root`.
    pub state_range: NonEmptyRange<Location>,

    /// Pre-computed digest of the block.
    digest: Digest,
}

struct DigestInput<'a, Payload> {
    context: &'a Context,
    parent: &'a Digest,
    height: Height,
    timestamp: u64,
    transaction_root: &'a Digest,
    reshare_log: &'a Option<DealerLog>,
    extension: &'a Payload,
    state: &'a StateCommitment,
}

/// Domain separator for a block's transaction commitment.
const TRANSACTION_ROOT_DOMAIN: &[u8] = b"nunchi/chain/transaction_root/v1";

/// A domain-separated commitment over a block's ordered transaction list.
///
/// This is a sequential-hash *commitment*, not a Merkle tree: it authenticates the exact ordered
/// set of transactions (count, order, and encoded bytes all matter), but it supports only equality
/// checks, not per-transaction inclusion proofs. Committing the block digest over this root instead
/// of inlining every transaction lets a compact [`BlockHeader`] reproduce the digest without
/// carrying the transactions.
fn transaction_root<Tx>(transactions: &[Tx]) -> Digest
where
    Tx: EncodeSize + Write,
{
    let mut hasher = Sha256::new();
    hasher.update(TRANSACTION_ROOT_DOMAIN);
    hasher.update(&(transactions.len() as u64).to_be_bytes());
    for transaction in transactions {
        hasher.update(&transaction.encode());
    }
    hasher.finalize()
}

/// Compute a block digest from its non-transaction fields and the transaction root.
///
/// Shared by [`Block`] (which folds its transactions into the root) and [`BlockHeader`] (which
/// carries the root directly), so both produce identical digests for the same block.
fn block_digest<Payload>(input: DigestInput<'_, Payload>) -> Digest
where
    Payload: EncodeSize + Write,
{
    let mut hasher = Sha256::new();
    hasher.update(&input.context.encode());
    hasher.update(input.parent);
    hasher.update(&input.height.get().to_be_bytes());
    hasher.update(&input.timestamp.to_be_bytes());
    hasher.update(input.transaction_root);
    hasher.update(&input.reshare_log.encode());
    hasher.update(&input.extension.encode());
    hasher.update(&input.state.root);
    hasher.update(&input.state.range.encode());
    hasher.finalize()
}

impl<Tx, Ext> Clone for Block<Tx, Ext>
where
    Tx: Clone,
    Ext: BlockExtension,
{
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            parent: self.parent,
            height: self.height,
            timestamp: self.timestamp,
            transactions: self.transactions.clone(),
            reshare_log: self.reshare_log.clone(),
            extension: self.extension.clone(),
            state_root: self.state_root,
            state_range: self.state_range.clone(),
            digest: self.digest,
        }
    }
}

impl<Tx, Ext> PartialEq for Block<Tx, Ext>
where
    Tx: PartialEq,
    Ext: BlockExtension,
{
    fn eq(&self, other: &Self) -> bool {
        self.context == other.context
            && self.parent == other.parent
            && self.height == other.height
            && self.timestamp == other.timestamp
            && self.transactions == other.transactions
            && self.reshare_log.encode() == other.reshare_log.encode()
            && self.extension.encode() == other.extension.encode()
            && self.state_root == other.state_root
            && self.state_range == other.state_range
            && self.digest == other.digest
    }
}

impl<Tx, Ext> Eq for Block<Tx, Ext>
where
    Tx: Eq,
    Ext: BlockExtension,
{
}

impl<Tx, Ext> Block<Tx, Ext>
where
    Tx: EncodeSize + Write,
    Ext: BlockExtension,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: Context,
        parent: Digest,
        height: Height,
        timestamp: u64,
        transactions: Vec<Tx>,
        reshare_log: Option<DealerLog>,
        extension: Ext::Payload,
        state: StateCommitment,
    ) -> Self {
        let digest = block_digest(DigestInput {
            context: &context,
            parent: &parent,
            height,
            timestamp,
            transaction_root: &transaction_root(&transactions),
            reshare_log: &reshare_log,
            extension: &extension,
            state: &state,
        });
        Self {
            context,
            parent,
            height,
            timestamp,
            transactions,
            reshare_log,
            extension,
            state_root: state.root,
            state_range: state.range,
            digest,
        }
    }

    /// The compact, digest-authenticated header of this block: every field that contributes to the
    /// block digest except the transactions, which are folded into [`BlockHeader::transaction_root`].
    /// [`BlockHeader::digest`] reproduces this block's digest exactly.
    pub fn header(&self) -> BlockHeader<Ext> {
        BlockHeader {
            context: self.context.clone(),
            parent: self.parent,
            height: self.height,
            timestamp: self.timestamp,
            transaction_root: transaction_root(&self.transactions),
            reshare_log: self.reshare_log.clone(),
            extension: self.extension.clone(),
            state_root: self.state_root,
            state_range: self.state_range.clone(),
        }
    }
}

impl<Tx, Ext> Write for Block<Tx, Ext>
where
    Tx: Write,
    Ext: BlockExtension,
{
    fn write(&self, writer: &mut impl BufMut) {
        self.context.write(writer);
        self.parent.write(writer);
        self.height.write(writer);
        UInt(self.timestamp).write(writer);
        UInt(self.transactions.len() as u64).write(writer);
        for transaction in &self.transactions {
            transaction.write(writer);
        }
        self.reshare_log.write(writer);
        self.extension.write(writer);
        self.state_root.write(writer);
        self.state_range.write(writer);
    }
}

impl<Tx, Ext> Read for Block<Tx, Ext>
where
    Tx: EncodeSize + Read<Cfg = ()> + Write,
    Ext: BlockExtension,
{
    type Cfg = (NonZeroU32, Ext::ReadCfg);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let context = Context::read(reader)?;
        let parent = Digest::read(reader)?;
        let height = Height::read(reader)?;
        let timestamp = UInt::read(reader)?.0;
        let count = UInt::read(reader)?.0;
        if count > MAX_TRANSACTIONS {
            return Err(Error::Invalid(
                "nunchi_chain::Block",
                "transaction count exceeds maximum",
            ));
        }
        let mut transactions = Vec::with_capacity(count as usize);
        for _ in 0..count {
            transactions.push(Tx::read(reader)?);
        }
        let reshare_log = Option::<DealerLog>::read_cfg(reader, &cfg.0)?;
        let extension = Ext::Payload::read_cfg(reader, &cfg.1)?;
        let state_root = Digest::read(reader)?;
        let state_range = NonEmptyRange::read(reader)?;
        let state = StateCommitment {
            root: state_root,
            range: state_range,
        };

        let digest = block_digest(DigestInput {
            context: &context,
            parent: &parent,
            height,
            timestamp,
            transaction_root: &transaction_root(&transactions),
            reshare_log: &reshare_log,
            extension: &extension,
            state: &state,
        });
        Ok(Self {
            context,
            parent,
            height,
            timestamp,
            transactions,
            reshare_log,
            extension,
            state_root: state.root,
            state_range: state.range,
            digest,
        })
    }
}

impl<Tx, Ext> EncodeSize for Block<Tx, Ext>
where
    Tx: EncodeSize,
    Ext: BlockExtension,
{
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + UInt(self.timestamp).encode_size()
            + UInt(self.transactions.len() as u64).encode_size()
            + self
                .transactions
                .iter()
                .map(EncodeSize::encode_size)
                .sum::<usize>()
            + self.reshare_log.encode_size()
            + self.extension.encode_size()
            + self.state_root.encode_size()
            + self.state_range.encode_size()
    }
}

impl<Tx, Ext> Digestible for Block<Tx, Ext>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension,
{
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.digest
    }
}

impl<Tx, Ext> Committable for Block<Tx, Ext>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension,
{
    type Commitment = Digest;

    fn commitment(&self) -> Digest {
        self.digest()
    }
}

/// The compact, digest-authenticated header of a [`Block`].
///
/// It carries every field that contributes to a block's digest except the transaction list, which
/// is folded into [`BlockHeader::transaction_root`]. This lets a verifier reproduce and check the
/// block digest (for example against a finalization certificate) without the full block, then read
/// the authenticated `state_root`/`state_range` out of it. See [`BlockHeader::digest`] and
/// [`Block::header`].
#[derive(Debug)]
pub struct BlockHeader<Ext: BlockExtension> {
    /// The consensus context when the block was proposed.
    pub context: Context,

    /// The parent block's digest.
    pub parent: Digest,

    /// The height of the block in the blockchain.
    pub height: Height,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    pub timestamp: u64,

    /// Commitment over the block's ordered transaction list (count, order, and encoded bytes all
    /// matter). A sequential-hash commitment, not a Merkle tree, so it supports equality checks but
    /// not per-transaction inclusion proofs.
    pub transaction_root: Digest,

    /// Optional DKG resharing payload included outside ordinary runtime transactions.
    pub reshare_log: Option<DealerLog>,

    /// Additional consensus-side payload included outside ordinary runtime transactions.
    pub extension: Ext::Payload,

    /// Authenticated state root after executing the block's transactions.
    pub state_root: Digest,

    /// QMDB operation range that supports state sync to `state_root`.
    pub state_range: NonEmptyRange<Location>,
}

impl<Ext: BlockExtension> BlockHeader<Ext> {
    /// The block digest this header authenticates. Equal to the digest of the block it was taken
    /// from (see [`Block::header`]).
    pub fn digest(&self) -> Digest {
        block_digest(DigestInput {
            context: &self.context,
            parent: &self.parent,
            height: self.height,
            timestamp: self.timestamp,
            transaction_root: &self.transaction_root,
            reshare_log: &self.reshare_log,
            extension: &self.extension,
            state: &StateCommitment {
                root: self.state_root,
                range: self.state_range.clone(),
            },
        })
    }
}

impl<Ext: BlockExtension> Clone for BlockHeader<Ext> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            parent: self.parent,
            height: self.height,
            timestamp: self.timestamp,
            transaction_root: self.transaction_root,
            reshare_log: self.reshare_log.clone(),
            extension: self.extension.clone(),
            state_root: self.state_root,
            state_range: self.state_range.clone(),
        }
    }
}

impl<Ext: BlockExtension> PartialEq for BlockHeader<Ext> {
    fn eq(&self, other: &Self) -> bool {
        self.context == other.context
            && self.parent == other.parent
            && self.height == other.height
            && self.timestamp == other.timestamp
            && self.transaction_root == other.transaction_root
            && self.reshare_log.encode() == other.reshare_log.encode()
            && self.extension.encode() == other.extension.encode()
            && self.state_root == other.state_root
            && self.state_range == other.state_range
    }
}

impl<Ext: BlockExtension> Eq for BlockHeader<Ext> {}

impl<Ext: BlockExtension> Write for BlockHeader<Ext> {
    fn write(&self, writer: &mut impl BufMut) {
        self.context.write(writer);
        self.parent.write(writer);
        self.height.write(writer);
        UInt(self.timestamp).write(writer);
        self.transaction_root.write(writer);
        self.reshare_log.write(writer);
        self.extension.write(writer);
        self.state_root.write(writer);
        self.state_range.write(writer);
    }
}

impl<Ext: BlockExtension> Read for BlockHeader<Ext> {
    type Cfg = (NonZeroU32, Ext::ReadCfg);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let context = Context::read(reader)?;
        let parent = Digest::read(reader)?;
        let height = Height::read(reader)?;
        let timestamp = UInt::read(reader)?.0;
        let transaction_root = Digest::read(reader)?;
        let reshare_log = Option::<DealerLog>::read_cfg(reader, &cfg.0)?;
        let extension = Ext::Payload::read_cfg(reader, &cfg.1)?;
        let state_root = Digest::read(reader)?;
        let state_range = NonEmptyRange::read(reader)?;
        Ok(Self {
            context,
            parent,
            height,
            timestamp,
            transaction_root,
            reshare_log,
            extension,
            state_root,
            state_range,
        })
    }
}

impl<Ext: BlockExtension> EncodeSize for BlockHeader<Ext> {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + UInt(self.timestamp).encode_size()
            + self.transaction_root.encode_size()
            + self.reshare_log.encode_size()
            + self.extension.encode_size()
            + self.state_root.encode_size()
            + self.state_range.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notarized<Tx, Ext = NoConsensusExtension>
where
    Ext: BlockExtension,
{
    pub proof: Notarization,
    pub block: Block<Tx, Ext>,
}

impl<Tx, Ext> Notarized<Tx, Ext>
where
    Ext: BlockExtension,
{
    pub fn new(proof: Notarization, block: Block<Tx, Ext>) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, scheme: &Scheme, strategy: &impl Strategy) -> bool {
        self.proof.verify(&mut sys_rng(), scheme, strategy)
    }
}

impl<Tx, Ext> Write for Notarized<Tx, Ext>
where
    Tx: Write,
    Ext: BlockExtension,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<Tx, Ext> Read for Notarized<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension,
{
    type Cfg = (NonZeroU32, Ext::ReadCfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proof = Notarization::read(buf)?;
        let block = Block::read_cfg(buf, cfg)?;

        if proof.proposal.payload != block.digest() {
            return Err(Error::Invalid(
                "nunchi_chain::Notarized",
                "proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl<Tx, Ext> EncodeSize for Notarized<Tx, Ext>
where
    Tx: EncodeSize,
    Ext: BlockExtension,
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finalized<Tx, Ext = NoConsensusExtension>
where
    Ext: BlockExtension,
{
    pub proof: Finalization,
    pub block: Block<Tx, Ext>,
}

impl<Tx, Ext> Finalized<Tx, Ext>
where
    Ext: BlockExtension,
{
    pub fn new(proof: Finalization, block: Block<Tx, Ext>) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, scheme: &Scheme, strategy: &impl Strategy) -> bool {
        self.proof.verify(&mut sys_rng(), scheme, strategy)
    }
}

impl<Tx, Ext> Write for Finalized<Tx, Ext>
where
    Tx: Write,
    Ext: BlockExtension,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<Tx, Ext> Read for Finalized<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension,
{
    type Cfg = (NonZeroU32, Ext::ReadCfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proof = Finalization::read(buf)?;
        let block = Block::read_cfg(buf, cfg)?;

        if proof.proposal.payload != block.digest() {
            return Err(Error::Invalid(
                "nunchi_chain::Finalized",
                "proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl<Tx, Ext> EncodeSize for Finalized<Tx, Ext>
where
    Tx: EncodeSize,
    Ext: BlockExtension,
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

impl<Tx, Ext> commonware_consensus::Block for Block<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension,
{
    fn parent(&self) -> Digest {
        self.parent
    }
}

impl<Tx, Ext> Heightable for Block<Tx, Ext>
where
    Ext: BlockExtension,
{
    fn height(&self) -> Height {
        self.height
    }
}

impl<Tx, Ext> CertifiableBlock for Block<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension,
{
    type Context = Context;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl<Tx, Ext> ReshareBlock for Block<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension,
{
    fn reshare_log(&self) -> Option<&DealerLog> {
        self.reshare_log.as_ref()
    }
}
