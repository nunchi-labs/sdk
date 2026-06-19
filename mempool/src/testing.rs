//! Test-only helpers shared by the pool and actor unit tests.

use crate::tx::PoolTransaction;
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

pub fn tx(account: u8, nonce: u64, id: u64) -> TestTx {
    TestTx {
        account,
        nonce,
        id,
        size: 100,
        valid: true,
    }
}
