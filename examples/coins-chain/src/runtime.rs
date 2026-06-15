//! Hand-written runtime shape for the coins-chain example.
//!
//! This is the concrete pattern a future `nunchi_runtime!` macro should generate: one tagged
//! transaction enum, codec implementations, txpool traits, and dispatch into selected modules.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_coins::{Coins, LedgerError};
use nunchi_common::{ChainModule, PoolTransaction, StateStore};
use thiserror::Error;

const TX_COINS: u8 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeTransaction {
    Coins(<Coins as ChainModule>::Transaction),
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("coins module error: {0}")]
    Coins(#[from] LedgerError),
}

impl RuntimeError {
    pub fn is_storage(&self) -> bool {
        matches!(self, Self::Coins(LedgerError::Storage(_)))
    }
}

impl RuntimeTransaction {
    pub async fn validate<S>(&self, state: &mut S) -> Result<(), RuntimeError>
    where
        S: StateStore + Send + Sync,
    {
        match self {
            Self::Coins(transaction) => Coins::validate(state, transaction).await?,
        }
        Ok(())
    }

    pub async fn apply<S>(&self, state: &mut S) -> Result<(), RuntimeError>
    where
        S: StateStore + Send + Sync,
    {
        match self {
            Self::Coins(transaction) => Coins::apply(state, transaction.clone()).await?,
        };
        Ok(())
    }
}

impl From<nunchi_coins::Transaction> for RuntimeTransaction {
    fn from(transaction: nunchi_coins::Transaction) -> Self {
        Self::Coins(transaction)
    }
}

impl PoolTransaction for RuntimeTransaction {
    type VerificationError = String;

    fn digest(&self) -> Digest {
        match self {
            Self::Coins(transaction) => transaction.digest(),
        }
    }

    fn verify(&self) -> Result<(), Self::VerificationError> {
        match self {
            Self::Coins(transaction) => transaction.verify().map_err(|error| error.to_string()),
        }
    }

    fn account_id(&self) -> &nunchi_common::Address {
        match self {
            Self::Coins(transaction) => &transaction.account_id,
        }
    }

    fn nonce(&self) -> u64 {
        match self {
            Self::Coins(transaction) => transaction.payload.nonce,
        }
    }
}

impl Write for RuntimeTransaction {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Coins(transaction) => {
                TX_COINS.write(buf);
                transaction.write(buf);
            }
        }
    }
}

impl Read for RuntimeTransaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            TX_COINS => Ok(Self::Coins(nunchi_coins::Transaction::read(buf)?)),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for RuntimeTransaction {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Coins(transaction) => transaction.encode_size(),
        }
    }
}
