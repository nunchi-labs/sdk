use std::num::NonZeroU32;

use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_coding::ReedSolomon;
use commonware_consensus::{
    marshal::coding::types::coding_config_for_participants,
    types::{coding::Commitment, Height},
    CertifiableBlock, Heightable,
};
use commonware_cryptography::{
    sha256::Digest, Committable, Digest as DigestTrait, Digestible, Hasher, Sha256,
};
use commonware_parallel::Strategy;
use commonware_storage::mmr::Location;
use commonware_utils::range::NonEmptyRange;
use commonware_utils::sys_rng;
use nunchi_dkg::{Context, DealerLog, Finalization, Notarization, ReshareBlock, Scheme};

use crate::{BlockExtension, NoConsensusExtension};

/// Upper bound on the number of runtime transactions a single block may carry.
///
/// Bounds the work a peer can force us to do when decoding an untrusted block.
pub const MAX_TRANSACTIONS: u64 = 4_096;

/// Consensus commitment over a [`CodingBlock`].
pub type BlockCommitment<Tx, Ext = NoConsensusExtension> =
    Commitment<CodingBlock<Tx, Ext>, ReedSolomon<Sha256>, Sha256>;

/// Simplex context whose parent digest is a coding commitment.
pub type CodingContext<Tx, Ext = NoConsensusExtension> = Context<BlockCommitment<Tx, Ext>>;

/// Dummy genesis parent used by tests and constructor helpers.
///
/// Production engines replace this with a commitment derived from the live
/// participant count before the first proposal.
pub fn dummy_genesis_parent<Tx, Ext>() -> BlockCommitment<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    genesis_parent(4)
}

/// Genesis parent commitment for a coding marshal with `n` participants.
pub fn genesis_parent<Tx, Ext>(n_participants: u16) -> BlockCommitment<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    Commitment::from((
        Digest::EMPTY,
        Digest::EMPTY,
        Digest::EMPTY,
        coding_config_for_participants(n_participants),
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateCommitment {
    /// Authenticated state root after executing the block's transactions.
    pub root: Digest,

    /// QMDB operation range that supports state sync to `root`.
    pub range: NonEmptyRange<Location>,
}

/// Domain separator for a block's transaction commitment.
const TRANSACTION_ROOT_DOMAIN: &[u8] = b"nunchi/chain/transaction_root/v1";

/// Domain-separated commitment over the ordered transaction list.
///
/// A sequential hash, not a Merkle tree: it supports equality checks but not per-transaction
/// inclusion proofs.
fn transaction_root<Tx>(transactions: &[Tx]) -> Digest
where
    Tx: EncodeSize + Write,
{
    let mut hasher = Sha256::default();
    hasher.update(TRANSACTION_ROOT_DOMAIN);
    hasher.update(&(transactions.len() as u64).to_be_bytes());
    for transaction in transactions {
        hasher.update(&transaction.encode());
    }
    hasher.finalize().1
}

/// A [`Block`]'s header: every field the block digest commits to, with the transactions folded
/// into [`BlockHeader::transaction_root`], so the digest can be recomputed without them.
#[derive(Debug)]
pub struct BlockHeader<Ext: BlockExtension, D: DigestTrait = Digest> {
    /// The consensus context when the block was proposed.
    pub context: Context<D>,

    /// The parent block's digest.
    pub parent: Digest,

    /// The height of the block in the blockchain.
    pub height: Height,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    pub timestamp: u64,

    /// Commitment over the block's ordered transaction list.
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

impl<Ext: BlockExtension, D: DigestTrait> BlockHeader<Ext, D> {
    /// The block digest this header commits to.
    pub fn digest(&self) -> Digest {
        let mut hasher = Sha256::default();
        hasher.update(&self.context.encode());
        hasher.update(self.parent.as_ref());
        hasher.update(&self.height.get().to_be_bytes());
        hasher.update(&self.timestamp.to_be_bytes());
        hasher.update(self.transaction_root.as_ref());
        hasher.update(&self.reshare_log.encode());
        hasher.update(&self.extension.encode());
        hasher.update(self.state_root.as_ref());
        hasher.update(&self.state_range.encode());
        hasher.finalize().1
    }
}

impl<Ext: BlockExtension, D: DigestTrait> Clone for BlockHeader<Ext, D> {
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

impl<Ext: BlockExtension, D: DigestTrait> PartialEq for BlockHeader<Ext, D> {
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

impl<Ext: BlockExtension, D: DigestTrait> Eq for BlockHeader<Ext, D> {}

impl<Ext: BlockExtension, D: DigestTrait> Write for BlockHeader<Ext, D> {
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

impl<Ext: BlockExtension, D: DigestTrait> Read for BlockHeader<Ext, D> {
    type Cfg = (NonZeroU32, Ext::ReadCfg);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let context = Context::<D>::read(reader)?;
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

impl<Ext: BlockExtension, D: DigestTrait> EncodeSize for BlockHeader<Ext, D> {
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

#[derive(Debug)]
pub struct Block<Tx, Ext = NoConsensusExtension, D: DigestTrait = Digest>
where
    Ext: BlockExtension,
{
    /// Header committing to this block's contents.
    pub header: BlockHeader<Ext, D>,

    /// Runtime transactions to execute when this block is finalized.
    pub transactions: Vec<Tx>,

    /// Pre-computed digest of the block.
    digest: Digest,
}

impl<Tx, Ext, D> Clone for Block<Tx, Ext, D>
where
    Tx: Clone,
    Ext: BlockExtension,
    D: DigestTrait,
{
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            transactions: self.transactions.clone(),
            digest: self.digest,
        }
    }
}

impl<Tx, Ext, D> PartialEq for Block<Tx, Ext, D>
where
    Tx: PartialEq,
    Ext: BlockExtension,
    D: DigestTrait,
{
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && self.transactions == other.transactions
            && self.digest == other.digest
    }
}

impl<Tx, Ext, D> Eq for Block<Tx, Ext, D>
where
    Tx: Eq,
    Ext: BlockExtension,
    D: DigestTrait,
{
}

impl<Tx, Ext, D> Block<Tx, Ext, D>
where
    Tx: EncodeSize + Write,
    Ext: BlockExtension,
    D: DigestTrait,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: Context<D>,
        parent: Digest,
        height: Height,
        timestamp: u64,
        transactions: Vec<Tx>,
        reshare_log: Option<DealerLog>,
        extension: Ext::Payload,
        state: StateCommitment,
    ) -> Self {
        let header = BlockHeader {
            context,
            parent,
            height,
            timestamp,
            transaction_root: transaction_root(&transactions),
            reshare_log,
            extension,
            state_root: state.root,
            state_range: state.range,
        };
        let digest = header.digest();
        Self {
            header,
            transactions,
            digest,
        }
    }
}

impl<Tx, Ext, D> Write for Block<Tx, Ext, D>
where
    Tx: Write,
    Ext: BlockExtension,
    D: DigestTrait,
{
    fn write(&self, writer: &mut impl BufMut) {
        self.header.write(writer);
        UInt(self.transactions.len() as u64).write(writer);
        for transaction in &self.transactions {
            transaction.write(writer);
        }
    }
}

impl<Tx, Ext, D> Read for Block<Tx, Ext, D>
where
    Tx: EncodeSize + Read<Cfg = ()> + Write,
    Ext: BlockExtension,
    D: DigestTrait,
{
    type Cfg = (NonZeroU32, Ext::ReadCfg);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let header = BlockHeader::<Ext, D>::read_cfg(reader, cfg)?;
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
        if transaction_root(&transactions) != header.transaction_root {
            return Err(Error::Invalid(
                "nunchi_chain::Block",
                "transaction root does not match transactions",
            ));
        }
        let digest = header.digest();
        Ok(Self {
            header,
            transactions,
            digest,
        })
    }
}

impl<Tx, Ext, D> EncodeSize for Block<Tx, Ext, D>
where
    Tx: EncodeSize,
    Ext: BlockExtension,
    D: DigestTrait,
{
    fn encode_size(&self) -> usize {
        self.header.encode_size()
            + UInt(self.transactions.len() as u64).encode_size()
            + self
                .transactions
                .iter()
                .map(EncodeSize::encode_size)
                .sum::<usize>()
    }
}

impl<Tx, Ext, D> Digestible for Block<Tx, Ext, D>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension,
    D: DigestTrait,
{
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.digest
    }
}

impl<Tx, Ext, D> Committable for Block<Tx, Ext, D>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension,
    D: DigestTrait,
{
    type Commitment = Digest;

    fn commitment(&self) -> Digest {
        self.digest()
    }
}

/// Application block whose simplex context is a coding commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodingBlock<Tx, Ext = NoConsensusExtension>(
    pub Block<Tx, Ext, BlockCommitment<Tx, Ext>>,
)
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync;

impl<Tx, Ext> CodingBlock<Tx, Ext>
where
    Tx: Clone + EncodeSize + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: CodingContext<Tx, Ext>,
        parent: Digest,
        height: Height,
        timestamp: u64,
        transactions: Vec<Tx>,
        reshare_log: Option<DealerLog>,
        extension: Ext::Payload,
        state: StateCommitment,
    ) -> Self
    where
        Tx: Clone + Read<Cfg = ()> + Send + Sync + 'static,
    {
        Self(Block::new(
            context,
            parent,
            height,
            timestamp,
            transactions,
            reshare_log,
            extension,
            state,
        ))
    }
}

impl<Tx, Ext> std::ops::Deref for CodingBlock<Tx, Ext>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    type Target = Block<Tx, Ext, BlockCommitment<Tx, Ext>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Tx, Ext> std::ops::DerefMut for CodingBlock<Tx, Ext>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<Tx, Ext> Write for CodingBlock<Tx, Ext>
where
    Tx: Clone + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    fn write(&self, writer: &mut impl BufMut) {
        self.0.write(writer);
    }
}

impl<Tx, Ext> Read for CodingBlock<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    type Cfg = (NonZeroU32, Ext::ReadCfg);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        Block::read_cfg(reader, cfg).map(Self)
    }
}

impl<Tx, Ext> EncodeSize for CodingBlock<Tx, Ext>
where
    Tx: Clone + EncodeSize + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl<Tx, Ext> Digestible for CodingBlock<Tx, Ext>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.0.digest()
    }
}

impl<Tx, Ext> Committable for CodingBlock<Tx, Ext>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    type Commitment = Digest;

    fn commitment(&self) -> Digest {
        self.0.digest()
    }
}

impl<Tx, Ext> commonware_consensus::Block for CodingBlock<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    fn parent(&self) -> Digest {
        self.0.header.parent
    }
}

impl<Tx, Ext> Heightable for CodingBlock<Tx, Ext>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    fn height(&self) -> Height {
        self.0.header.height
    }
}

impl<Tx, Ext> CertifiableBlock for CodingBlock<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    type Context = CodingContext<Tx, Ext>;

    fn context(&self) -> Self::Context {
        self.0.header.context.clone()
    }
}

impl<Tx, Ext> ReshareBlock for CodingBlock<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    fn reshare_log(&self) -> Option<&DealerLog> {
        self.0.header.reshare_log.as_ref()
    }
}

impl<Tx, Ext, D> commonware_consensus::Block for Block<Tx, Ext, D>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension,
    D: DigestTrait,
{
    fn parent(&self) -> Digest {
        self.header.parent
    }
}

impl<Tx, Ext, D> Heightable for Block<Tx, Ext, D>
where
    Ext: BlockExtension,
    D: DigestTrait,
{
    fn height(&self) -> Height {
        self.header.height
    }
}

impl<Tx, Ext, D> CertifiableBlock for Block<Tx, Ext, D>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension,
    D: DigestTrait,
{
    type Context = Context<D>;

    fn context(&self) -> Self::Context {
        self.header.context.clone()
    }
}

impl<Tx, Ext, D> ReshareBlock for Block<Tx, Ext, D>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension,
    D: DigestTrait,
{
    fn reshare_log(&self) -> Option<&DealerLog> {
        self.header.reshare_log.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notarized<Tx, Ext = NoConsensusExtension>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    pub proof: Notarization<BlockCommitment<Tx, Ext>>,
    pub block: CodingBlock<Tx, Ext>,
}

impl<Tx, Ext> Notarized<Tx, Ext>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    pub fn new(proof: Notarization<BlockCommitment<Tx, Ext>>, block: CodingBlock<Tx, Ext>) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, scheme: &Scheme, strategy: &impl Strategy) -> bool {
        self.proof.verify(&mut sys_rng(), scheme, strategy)
    }
}

impl<Tx, Ext> Write for Notarized<Tx, Ext>
where
    Tx: Clone + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<Tx, Ext> Read for Notarized<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    type Cfg = (NonZeroU32, Ext::ReadCfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proof = Notarization::<BlockCommitment<Tx, Ext>>::read(buf)?;
        let block = CodingBlock::read_cfg(buf, cfg)?;

        if proof.proposal.payload.block() != block.digest() {
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
    Tx: Clone + EncodeSize + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finalized<Tx, Ext = NoConsensusExtension>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    pub proof: Finalization<BlockCommitment<Tx, Ext>>,
    pub block: CodingBlock<Tx, Ext>,
}

impl<Tx, Ext> Finalized<Tx, Ext>
where
    Tx: Clone + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    pub fn new(proof: Finalization<BlockCommitment<Tx, Ext>>, block: CodingBlock<Tx, Ext>) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, scheme: &Scheme, strategy: &impl Strategy) -> bool {
        self.proof.verify(&mut sys_rng(), scheme, strategy)
    }
}

impl<Tx, Ext> Write for Finalized<Tx, Ext>
where
    Tx: Clone + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<Tx, Ext> Read for Finalized<Tx, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    type Cfg = (NonZeroU32, Ext::ReadCfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proof = Finalization::<BlockCommitment<Tx, Ext>>::read(buf)?;
        let block = CodingBlock::read_cfg(buf, cfg)?;

        if proof.proposal.payload.block() != block.digest() {
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
    Tx: Clone + EncodeSize + Send + Sync + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}
