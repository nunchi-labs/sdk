use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{types::Height, CertifiableBlock, Heightable};
use commonware_cryptography::{sha256::Digest, Committable, Digestible, Hasher, Sha256};
use commonware_parallel::Strategy;
use commonware_storage::mmr::Location;
use commonware_utils::range::NonEmptyRange;
use nunchi_dkg::{Context, DealerLog, Finalization, Notarization, ReshareBlock, Scheme};
use rand::rngs::OsRng;
use std::num::NonZeroU32;

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

#[derive(Clone, Debug)]
pub struct Block<Tx> {
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

    /// Optional DKG/reshare dealer log included for epoch transitions.
    pub reshare_log: Option<DealerLog>,

    /// Authenticated state root after executing `transactions`.
    pub state_root: Digest,

    /// QMDB operation range that supports state sync to `state_root`.
    pub state_range: NonEmptyRange<Location>,

    /// Pre-computed digest of the block.
    digest: Digest,
}

impl<Tx> PartialEq for Block<Tx>
where
    Tx: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.context == other.context
            && self.parent == other.parent
            && self.height == other.height
            && self.timestamp == other.timestamp
            && self.transactions == other.transactions
            && self.reshare_log.encode() == other.reshare_log.encode()
            && self.state_root == other.state_root
            && self.state_range == other.state_range
            && self.digest == other.digest
    }
}

impl<Tx: Eq> Eq for Block<Tx> {}

impl<Tx> Block<Tx>
where
    Tx: EncodeSize + Write,
{
    fn compute_digest(
        context: &Context,
        parent: &Digest,
        height: Height,
        timestamp: u64,
        transactions: &[Tx],
        reshare_log: &Option<DealerLog>,
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
        hasher.update(&reshare_log.encode());
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
        reshare_log: Option<DealerLog>,
        state: StateCommitment,
    ) -> Self {
        let digest = Self::compute_digest(
            &context,
            &parent,
            height,
            timestamp,
            &transactions,
            &reshare_log,
            &state,
        );
        Self {
            context,
            parent,
            height,
            timestamp,
            transactions,
            reshare_log,
            state_root: state.root,
            state_range: state.range,
            digest,
        }
    }
}

impl<Tx> Write for Block<Tx>
where
    Tx: Write,
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
        self.state_root.write(writer);
        self.state_range.write(writer);
    }
}

impl<Tx> Read for Block<Tx>
where
    Tx: EncodeSize + Read<Cfg = ()> + Write,
{
    type Cfg = NonZeroU32;

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
        let reshare_log = Read::read_cfg(reader, cfg)?;
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
            &reshare_log,
            &state,
        );
        Ok(Self {
            context,
            parent,
            height,
            timestamp,
            transactions,
            reshare_log,
            state_root: state.root,
            state_range: state.range,
            digest,
        })
    }
}

impl<Tx> EncodeSize for Block<Tx>
where
    Tx: EncodeSize,
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
            + self.state_root.encode_size()
            + self.state_range.encode_size()
    }
}

impl<Tx> Digestible for Block<Tx>
where
    Tx: Clone + Send + Sync + 'static,
{
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.digest
    }
}

impl<Tx> Committable for Block<Tx>
where
    Tx: Clone + Send + Sync + 'static,
{
    type Commitment = Digest;

    fn commitment(&self) -> Digest {
        self.digest()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notarized<Tx> {
    pub proof: Notarization,
    pub block: Block<Tx>,
}

impl<Tx> Notarized<Tx> {
    pub fn new(proof: Notarization, block: Block<Tx>) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, scheme: &Scheme, strategy: &impl Strategy) -> bool {
        self.proof.verify(&mut OsRng, scheme, strategy)
    }
}

impl<Tx> Write for Notarized<Tx>
where
    Tx: Write,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<Tx> Read for Notarized<Tx>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
{
    type Cfg = NonZeroU32;

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

impl<Tx> EncodeSize for Notarized<Tx>
where
    Tx: EncodeSize,
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finalized<Tx> {
    pub proof: Finalization,
    pub block: Block<Tx>,
}

impl<Tx> Finalized<Tx> {
    pub fn new(proof: Finalization, block: Block<Tx>) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, scheme: &Scheme, strategy: &impl Strategy) -> bool {
        self.proof.verify(&mut OsRng, scheme, strategy)
    }
}

impl<Tx> Write for Finalized<Tx>
where
    Tx: Write,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<Tx> Read for Finalized<Tx>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
{
    type Cfg = NonZeroU32;

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

impl<Tx> EncodeSize for Finalized<Tx>
where
    Tx: EncodeSize,
{
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

impl<Tx> commonware_consensus::Block for Block<Tx>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
{
    fn parent(&self) -> Digest {
        self.parent
    }
}

impl<Tx> Heightable for Block<Tx> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<Tx> CertifiableBlock for Block<Tx>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
{
    type Context = Context;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl<Tx> ReshareBlock for Block<Tx>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
{
    fn reshare_log(&self) -> Option<&DealerLog> {
        self.reshare_log.as_ref()
    }
}
