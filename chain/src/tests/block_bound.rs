//! `BoundedBlock::max_encode_size` covers blocks the codec accepts.

use bytes::BufMut;
use commonware_codec::Buf;
use commonware_codec::{
    Decode, Encode, EncodeSize, Error as CodecError, FixedSize, MaxEncodeSize, RangeCfg, Read,
    Write,
};
use commonware_consensus::{types::{Epoch, Height, Round, View}, BoundedBlock};
use commonware_cryptography::{ed25519, sha256, Digest as _, Signer};
use commonware_storage::mmr::Location;
use commonware_utils::{non_empty_range, NZU32};
use nunchi_mempool::DEFAULT_MAX_TX_BYTES;

use crate::{
    dummy_genesis_parent, CodingBlock, CodingContext, EmptyPayload, NoConsensusExtension,
    StateCommitment, MAX_TRANSACTIONS,
};

/// Stand-in for a mempool transaction at the default admission cap.
#[derive(Clone)]
struct WideTx {
    bytes: Vec<u8>,
}

impl Write for WideTx {
    fn write(&self, buf: &mut impl BufMut) {
        self.bytes.write(buf);
    }
}

impl Read for WideTx {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            bytes: Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=DEFAULT_MAX_TX_BYTES), ()))?,
        })
    }
}

impl EncodeSize for WideTx {
    fn encode_size(&self) -> usize {
        self.bytes.encode_size()
    }
}

impl MaxEncodeSize for WideTx {
    const MAX_ENCODE_SIZE: usize = nunchi_common::items_bound(DEFAULT_MAX_TX_BYTES, u8::SIZE);
}

/// A transaction whose reader accepts more bytes than its declared block maximum.
#[derive(Clone, Debug)]
struct LooseTx {
    bytes: Vec<u8>,
}

impl Write for LooseTx {
    fn write(&self, buf: &mut impl BufMut) {
        self.bytes.write(buf);
    }
}

impl Read for LooseTx {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            bytes: Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=64), ()))?,
        })
    }
}

impl EncodeSize for LooseTx {
    fn encode_size(&self) -> usize {
        self.bytes.encode_size()
    }
}

impl MaxEncodeSize for LooseTx {
    const MAX_ENCODE_SIZE: usize = 32;
}

fn context<Tx>() -> CodingContext<Tx>
where
    Tx: Clone + EncodeSize + MaxEncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
{
    CodingContext {
        round: Round::new(Epoch::zero(), View::zero()),
        leader: ed25519::PrivateKey::from_seed(0).public_key(),
        parent: (View::zero(), dummy_genesis_parent()),
    }
}

fn state() -> StateCommitment {
    StateCommitment {
        root: sha256::Digest::EMPTY,
        range: non_empty_range!(Location::new(0), Location::new(1)),
    }
}

fn cfg() -> (std::num::NonZeroU32, ()) {
    (NZU32!(4), ())
}

#[test]
fn max_encode_size_covers_mempool_width_transaction() {
    let block = CodingBlock::<WideTx>::new(
        context(),
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![WideTx {
            bytes: vec![0xab; DEFAULT_MAX_TX_BYTES],
        }],
        None,
        EmptyPayload,
        state(),
    );
    let bound = CodingBlock::<WideTx, NoConsensusExtension>::max_encode_size(&cfg());
    let encoded = block.encode();
    assert!(encoded.len() > 8 * 1024);
    assert!(encoded.len() <= bound);

    let decoded = CodingBlock::<WideTx>::decode_cfg(encoded, &cfg()).expect("wide transaction decodes");
    assert_eq!(decoded.transactions[0].bytes.len(), DEFAULT_MAX_TX_BYTES);
    assert!(decoded.encode_size() <= bound);

    // The previous constant, 8 KiB of header plus 8 KiB per transaction slot, is smaller
    // than a block of mempool-max transactions. The derived bound is not.
    let mempool_block = (MAX_TRANSACTIONS as usize) * DEFAULT_MAX_TX_BYTES;
    const {
        let previous = 8 * 1024 + (MAX_TRANSACTIONS as usize) * 8 * 1024;
        assert!((MAX_TRANSACTIONS as usize) * DEFAULT_MAX_TX_BYTES > previous);
    }
    assert!(bound >= mempool_block);
}

#[test]
fn decode_rejects_transaction_wider_than_declared_maximum() {
    let block = CodingBlock::<LooseTx>::new(
        context(),
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![LooseTx {
            bytes: vec![1; 40],
        }],
        None,
        EmptyPayload,
        state(),
    );
    assert!(block.encode_size() > LooseTx::MAX_ENCODE_SIZE);
    let error = CodingBlock::<LooseTx>::decode_cfg(block.encode(), &cfg()).unwrap_err();
    assert!(
        matches!(error, CodecError::Invalid(context, _) if context.contains("Block")),
        "{error:?}"
    );
}
