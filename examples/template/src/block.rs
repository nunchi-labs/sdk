use crate::consensus::{Finalization, Notarization, Scheme};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{
    simplex::types::Context as SimplexContext,
    types::{Epoch, Height, Round, View},
    CertifiableBlock, Heightable,
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::SignedDealerLog,
        primitives::variant::{MinSig, Variant},
    },
    ed25519,
    sha256::Sha256,
    Committable, Digest as EmptyDigest, Digestible, Hasher, Signer,
};
use commonware_parallel::Strategy;
use rand::rngs::OsRng;
use std::num::NonZeroU32;

#[derive(Clone, Debug)]
pub struct Block<H = Sha256, C = ed25519::PrivateKey, V = MinSig>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// The consensus context when this block was proposed.
    pub context: SimplexContext<H::Digest, C::PublicKey>,

    /// The parent block's digest.
    pub parent: H::Digest,

    /// The height of the block in the blockchain.
    pub height: Height,

    /// An optional outcome of a dealing operation.
    pub log: Option<SignedDealerLog<V, C>>,
}

impl<H, C, V> PartialEq for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn eq(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

impl<H, C, V> Eq for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
}

impl<H, C, V> Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    pub const fn new(
        context: SimplexContext<H::Digest, C::PublicKey>,
        parent: H::Digest,
        height: Height,
        log: Option<SignedDealerLog<V, C>>,
    ) -> Self {
        Self {
            context,
            parent,
            height,
            log,
        }
    }
}

impl<H, C, V> Write for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn write(&self, writer: &mut impl BufMut) {
        self.context.write(writer);
        self.parent.write(writer);
        self.height.write(writer);
        self.log.write(writer);
    }
}

impl<H, C, V> Read for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Cfg = NonZeroU32;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            context: SimplexContext::read(reader)?,
            parent: H::Digest::read(reader)?,
            height: Height::read(reader)?,
            log: Read::read_cfg(reader, cfg)?,
        })
    }
}

impl<H, C, V> EncodeSize for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.log.encode_size()
    }
}

impl<H, C, V> Digestible for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Digest = H::Digest;

    fn digest(&self) -> H::Digest {
        H::hash(&self.encode())
    }
}

impl<H, C, V> Committable for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Commitment = H::Digest;

    fn commitment(&self) -> H::Digest {
        self.digest()
    }
}

impl<H, C, V> commonware_consensus::Block for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl<H, C, V> Heightable for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    fn height(&self) -> Height {
        self.height
    }
}

impl<H, C, V> CertifiableBlock for Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Context = SimplexContext<H::Digest, C::PublicKey>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

pub const fn genesis_block<H, C, V>(
    context: SimplexContext<H::Digest, C::PublicKey>,
) -> Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    Block::new(
        context,
        <<H as Hasher>::Digest as EmptyDigest>::EMPTY,
        Height::zero(),
        None,
    )
}

pub fn genesis<H, C, V>() -> Block<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    let context = SimplexContext {
        round: Round::new(Epoch::zero(), View::zero()),
        leader: C::from_seed(0).public_key(),
        parent: (View::zero(), <H::Digest as EmptyDigest>::EMPTY),
    };
    genesis_block(context)
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
