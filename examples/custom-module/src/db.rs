//! Persistence layer for the custom module.

use crate::{CustomError, CUSTOM_NAMESPACE};
use async_trait::async_trait;
use commonware_codec::{Encode, Read, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Namespace, StateStore};

const NS: Namespace = Namespace::new(CUSTOM_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    Nonce = 0,
    Value = 1,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, CustomError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| CustomError::Storage(err.to_string()))
}

fn nonce_key(account: &Address) -> Digest {
    NS.key(Table::Nonce, account.encode().as_ref())
}

fn value_key(account: &Address) -> Digest {
    NS.key(Table::Value, account.encode().as_ref())
}

/// Typed state access required by [`crate::CustomLedger`].
#[async_trait]
pub trait CustomDB {
    async fn nonce(&self, account: &Address) -> Result<u64, CustomError>;

    fn set_nonce(&mut self, account: &Address, nonce: u64);

    async fn value(&self, account: &Address) -> Result<Option<u64>, CustomError>;

    fn set_value(&mut self, account: &Address, value: u64);

    fn remove_value(&mut self, account: &Address);
}

#[async_trait]
impl<S: StateStore + Send + Sync> CustomDB for S {
    async fn nonce(&self, account: &Address) -> Result<u64, CustomError> {
        match StateStore::get(self, &nonce_key(account))
            .await
            .map_err(|err| CustomError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_nonce(&mut self, account: &Address, nonce: u64) {
        StateStore::set(self, nonce_key(account), encoded(&nonce));
    }

    async fn value(&self, account: &Address) -> Result<Option<u64>, CustomError> {
        match StateStore::get(self, &value_key(account))
            .await
            .map_err(|err| CustomError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_value(&mut self, account: &Address, value: u64) {
        StateStore::set(self, value_key(account), encoded(&value));
    }

    fn remove_value(&mut self, account: &Address) {
        StateStore::remove(self, value_key(account));
    }
}
