//! Counter-owned persistence.

use crate::{CounterError, COUNTER_NAMESPACE};
use async_trait::async_trait;
use commonware_codec::{Encode, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Namespace, StateStore};

const NS: Namespace = Namespace::new(COUNTER_NAMESPACE);

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

fn nonce_key(account: &Address) -> Digest {
    NS.key(Table::Nonce, account.encode().as_ref())
}

fn value_key() -> Digest {
    NS.key(Table::Value, &[])
}

fn decode_u64(bytes: &[u8]) -> Result<u64, CounterError> {
    let mut bytes = bytes;
    u64::read(&mut bytes).map_err(|error| CounterError::Storage(error.to_string()))
}

#[async_trait]
pub trait CounterDB {
    async fn nonce(&self, account: &Address) -> Result<u64, CounterError>;

    fn set_nonce(&mut self, account: &Address, nonce: u64);

    async fn value(&self) -> Result<u64, CounterError>;

    fn set_value(&mut self, value: u64);
}

#[async_trait]
impl<S: StateStore + Send + Sync> CounterDB for S {
    async fn nonce(&self, account: &Address) -> Result<u64, CounterError> {
        let Some(bytes) = StateStore::get(self, &nonce_key(account))
            .await
            .map_err(|error| CounterError::Storage(error.to_string()))?
        else {
            return Ok(0);
        };
        decode_u64(&bytes)
    }

    fn set_nonce(&mut self, account: &Address, nonce: u64) {
        StateStore::set(self, nonce_key(account), nonce.encode().to_vec());
    }

    async fn value(&self) -> Result<u64, CounterError> {
        let Some(bytes) = StateStore::get(self, &value_key())
            .await
            .map_err(|error| CounterError::Storage(error.to_string()))?
        else {
            return Ok(0);
        };
        decode_u64(&bytes)
    }

    fn set_value(&mut self, value: u64) {
        StateStore::set(self, value_key(), value.encode().to_vec());
    }
}
