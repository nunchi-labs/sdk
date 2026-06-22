use bytes::{Buf, BufMut};
use commonware_codec::{Decode, Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::types::{Epoch, Height, Round, View};
use commonware_cryptography::{ed25519, sha256, Digest as _, Digestible as _, Signer};
use commonware_storage::mmr::Location;
use commonware_utils::{non_empty_range, NZU32};
use nunchi_chain::{Block, BlockExtension, StateCommitment};
use nunchi_dkg::{Context, ReshareBlock};

#[derive(Clone, Debug, Eq, PartialEq)]
struct TestExtension;

#[derive(Clone, Debug, Eq, PartialEq)]
struct TestPayload(u8);

impl Write for TestPayload {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for TestPayload {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(u8::read(buf)?))
    }
}

impl EncodeSize for TestPayload {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl BlockExtension for TestExtension {
    type Payload = TestPayload;
    type ReadCfg = ();

    fn genesis_payload() -> Self::Payload {
        TestPayload(0)
    }
}

fn context() -> Context {
    Context {
        round: Round::new(Epoch::zero(), View::zero()),
        leader: ed25519::PrivateKey::from_seed(0).public_key(),
        parent: (View::zero(), sha256::Digest::EMPTY),
    }
}

fn state() -> StateCommitment {
    StateCommitment {
        root: sha256::Digest::EMPTY,
        range: non_empty_range!(Location::new(0), Location::new(1)),
    }
}

fn block_cfg() -> (std::num::NonZeroU32, ()) {
    (NZU32!(1), ())
}

#[test]
fn default_block_extension_is_empty_payload() {
    let block: Block<u8> = Block::new(
        context(),
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![7],
        None,
        (),
        state(),
    );

    assert_eq!(block.extension, ());
    assert_eq!(
        Block::<u8>::decode_cfg(block.encode().as_ref(), &block_cfg()).unwrap(),
        block
    );
}

#[test]
fn custom_extension_payload_is_encoded_and_committed() {
    let left = Block::<u8, TestExtension>::new(
        context(),
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![7],
        None,
        TestPayload(1),
        state(),
    );
    let right = Block::<u8, TestExtension>::new(
        context(),
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![7],
        None,
        TestPayload(2),
        state(),
    );

    assert_ne!(left.encode(), right.encode());
    assert_ne!(left.digest(), right.digest());
    assert_eq!(
        Block::<u8, TestExtension>::decode_cfg(left.encode().as_ref(), &block_cfg()).unwrap(),
        left,
    );
}

#[test]
fn dkg_reshare_log_is_core_block_field() {
    let block = Block::<u8>::new(
        context(),
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![7],
        None,
        (),
        state(),
    );

    assert!(block.reshare_log.is_none());
    assert_eq!(block.extension, ());
    assert!(ReshareBlock::reshare_log(&block).is_none());
}
