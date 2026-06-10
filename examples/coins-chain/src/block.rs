use crate::consensus::{Context, Finalization, Notarization, Scheme};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{types::Height, CertifiableBlock, Heightable};
use commonware_cryptography::{sha256::Digest, Committable, Digestible, Hasher, Sha256};
use commonware_parallel::Strategy;
use nunchi_coins::Transaction;
use nunchi_dkg::{DealerLog, ReshareBlock};
use rand::rngs::OsRng;
use std::num::NonZeroU32;

/// Upper bound on the number of coin transactions a single block may carry.
///
/// Bounds the work a peer can force us to do when decoding an untrusted block.
pub const MAX_TRANSACTIONS: u64 = 4_096;

#[derive(Clone, Debug)]
pub struct Block {
    /// The consensus context when this block was proposed.
    pub context: Context,

    /// The parent block's digest.
    pub parent: Digest,

    /// The height of the block in the blockchain.
    pub height: Height,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    pub timestamp: u64,

    /// The coin transactions to execute when this block is finalized.
    pub transactions: Vec<Transaction>,

    /// Optional DKG/reshare dealer log included for epoch transitions.
    pub reshare_log: Option<DealerLog>,

    /// Pre-computed digest of the block.
    digest: Digest,
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.context == other.context
            && self.parent == other.parent
            && self.height == other.height
            && self.timestamp == other.timestamp
            && self.transactions == other.transactions
            && self.digest == other.digest
            && self.reshare_log.encode() == other.reshare_log.encode()
    }
}

impl Eq for Block {}

impl Block {
    fn compute_digest(
        context: &Context,
        parent: &Digest,
        height: Height,
        timestamp: u64,
        transactions: &[Transaction],
        reshare_log: &Option<DealerLog>,
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
        hasher.finalize()
    }

    pub fn new(
        context: Context,
        parent: Digest,
        height: Height,
        timestamp: u64,
        transactions: Vec<Transaction>,
        reshare_log: Option<DealerLog>,
    ) -> Self {
        let digest = Self::compute_digest(
            &context,
            &parent,
            height,
            timestamp,
            &transactions,
            &reshare_log,
        );
        Self {
            context,
            parent,
            height,
            timestamp,
            transactions,
            reshare_log,
            digest,
        }
    }
}

impl Write for Block {
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
    }
}

impl Read for Block {
    type Cfg = NonZeroU32;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let context = Context::read(reader)?;
        let parent = Digest::read(reader)?;
        let height = Height::read(reader)?;
        let timestamp = UInt::read(reader)?.0;
        let count = UInt::read(reader)?.0;
        if count > MAX_TRANSACTIONS {
            return Err(Error::Invalid(
                "coins_chain::Block",
                "transaction count exceeds maximum",
            ));
        }
        let mut transactions = Vec::with_capacity(count as usize);
        for _ in 0..count {
            transactions.push(Transaction::read(reader)?);
        }
        let reshare_log = Read::read_cfg(reader, cfg)?;

        let digest = Self::compute_digest(
            &context,
            &parent,
            height,
            timestamp,
            &transactions,
            &reshare_log,
        );
        Ok(Self {
            context,
            parent,
            height,
            timestamp,
            transactions,
            reshare_log,
            digest,
        })
    }
}

impl EncodeSize for Block {
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
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.digest
    }
}

impl Committable for Block {
    type Commitment = Digest;

    fn commitment(&self) -> Digest {
        self.digest()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notarized {
    pub proof: Notarization,
    pub block: Block,
}

impl Notarized {
    pub fn new(proof: Notarization, block: Block) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, scheme: &Scheme, strategy: &impl Strategy) -> bool {
        self.proof.verify(&mut OsRng, scheme, strategy)
    }
}

impl Write for Notarized {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl Read for Notarized {
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proof = Notarization::read(buf)?;
        let block = Block::read_cfg(buf, cfg)?;

        // Ensure the proof is for the block
        if proof.proposal.payload != block.digest() {
            return Err(Error::Invalid(
                "types::Notarized",
                "Proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl EncodeSize for Notarized {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finalized {
    pub proof: Finalization,
    pub block: Block,
}

impl Finalized {
    pub fn new(proof: Finalization, block: Block) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, scheme: &Scheme, strategy: &impl Strategy) -> bool {
        self.proof.verify(&mut OsRng, scheme, strategy)
    }
}

impl Write for Finalized {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl Read for Finalized {
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proof = Finalization::read(buf)?;
        let block = Block::read_cfg(buf, cfg)?;

        // Ensure the proof is for the block
        if proof.proposal.payload != block.digest() {
            return Err(Error::Invalid(
                "types::Finalized",
                "Proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl EncodeSize for Finalized {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

impl commonware_consensus::Block for Block {
    fn parent(&self) -> Digest {
        self.parent
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl CertifiableBlock for Block {
    type Context = Context;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl ReshareBlock for Block {
    fn reshare_log(&self) -> Option<&DealerLog> {
        self.reshare_log.as_ref()
    }
}
