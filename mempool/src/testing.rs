//! Test-only helpers shared by the pool and actor unit tests.

use crate::tx::PoolTransaction;
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestTx {
    pub account: u8,
    pub nonce: u64,
    pub id: u64,
    pub size: usize,
    pub valid: bool,
}

#[derive(Debug, Error)]
#[error("bad signature")]
pub struct BadSignature;

impl PoolTransaction for TestTx {
    type Digest = u64;
    type NonceKey = u8;
    type VerifyError = BadSignature;

    fn digest(&self) -> u64 {
        self.id
    }

    fn nonce_key(&self) -> u8 {
        self.account
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn encoded_size(&self) -> usize {
        self.size
    }

    fn verify(&self) -> Result<(), BadSignature> {
        if self.valid {
            Ok(())
        } else {
            Err(BadSignature)
        }
    }
}

impl Write for TestTx {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.account.write(buf);
        self.nonce.write(buf);
        self.id.write(buf);
        (self.size as u64).write(buf);
        self.valid.write(buf);
    }
}

impl Read for TestTx {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            account: u8::read(buf)?,
            nonce: u64::read(buf)?,
            id: u64::read(buf)?,
            size: u64::read(buf)? as usize,
            valid: bool::read(buf)?,
        })
    }
}

impl EncodeSize for TestTx {
    fn encode_size(&self) -> usize {
        self.account.encode_size()
            + self.nonce.encode_size()
            + self.id.encode_size()
            + (self.size as u64).encode_size()
            + self.valid.encode_size()
    }
}

pub fn tx(account: u8, nonce: u64, id: u64) -> TestTx {
    TestTx {
        account,
        nonce,
        id,
        size: 100,
        valid: true,
    }
}
