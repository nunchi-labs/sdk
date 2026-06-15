use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{types::Height, CertifiableBlock, Heightable};
use commonware_cryptography::{sha256::Digest, Committable, Digestible, Hasher, Sha256};
use commonware_parallel::Strategy;
use commonware_storage::mmr::Location;
use commonware_utils::range::NonEmptyRange;
use nunchi_common::{BlockExtension, NoConsensusExtension};
use nunchi_dkg::{Context, Finalization, Notarization, Scheme};
use rand::rngs::OsRng;

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

    /// Consensus-side payload included outside ordinary runtime transactions.
    pub extension: Ext::Payload,

    /// Authenticated state root after executing `transactions`.
    pub state_root: Digest,

    /// QMDB operation range that supports state sync to `state_root`.
    pub state_range: NonEmptyRange<Location>,

    /// Pre-computed digest of the block.
    digest: Digest,
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
    fn compute_digest(
        context: &Context,
        parent: &Digest,
        height: Height,
        timestamp: u64,
        transactions: &[Tx],
        extension: &Ext::Payload,
        state: &StateCommitment,
    ) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(&context.encode());
        hasher.update(parent);
        hasher.update(&height.get().to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&(transactions.len() as u64).to_be_bytes());
        for transaction in transactions {
            hasher.update(&transaction.encode());
        }
        hasher.update(&extension.encode());
        hasher.update(&state.root);
        hasher.update(&state.range.encode());
        hasher.finalize()
    }

    pub fn new(
        context: Context,
        parent: Digest,
        height: Height,
        timestamp: u64,
        transactions: Vec<Tx>,
        extension: Ext::Payload,
        state: StateCommitment,
    ) -> Self {
        let digest = Self::compute_digest(
            &context,
            &parent,
            height,
            timestamp,
            &transactions,
            &extension,
            &state,
        );
        Self {
            context,
            parent,
            height,
            timestamp,
            transactions,
            extension,
            state_root: state.root,
            state_range: state.range,
            digest,
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
    type Cfg = Ext::ReadCfg;

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
        let extension = Ext::Payload::read_cfg(reader, cfg)?;
        let state_root = Digest::read(reader)?;
        let state_range = NonEmptyRange::read(reader)?;
        let state = StateCommitment {
            root: state_root,
            range: state_range,
        };

        let digest = Self::compute_digest(
            &context,
            &parent,
            height,
            timestamp,
            &transactions,
            &extension,
            &state,
        );
        Ok(Self {
            context,
            parent,
            height,
            timestamp,
            transactions,
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
        self.proof.verify(&mut OsRng, scheme, strategy)
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
    type Cfg = Ext::ReadCfg;

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
        self.proof.verify(&mut OsRng, scheme, strategy)
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
    type Cfg = Ext::ReadCfg;

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
