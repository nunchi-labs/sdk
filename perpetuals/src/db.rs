//! Persistence layer for the perpetuals module.

use crate::{Market, MarketId, PerpetualError, Position, PositionId, PERPETUALS_NAMESPACE};
use async_trait::async_trait;
use commonware_codec::{Encode, Read, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Namespace, StateStore};

const NS: Namespace = Namespace::new(PERPETUALS_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    Account = 0,
    MarketNonce = 1,
    PositionNonce = 2,
    Market = 3,
    Position = 4,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, PerpetualError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| PerpetualError::Storage(err.to_string()))
}

/// State access required by the perps ledger.
#[async_trait]
pub trait PerpetualDB {
    async fn nonce(&self, id: &Address) -> Result<u64, PerpetualError>;

    fn set_nonce(&mut self, id: &Address, nonce: u64);

    async fn market_nonce(&self) -> Result<u64, PerpetualError>;

    fn set_market_nonce(&mut self, nonce: u64);

    async fn position_nonce(&self) -> Result<u64, PerpetualError>;

    fn set_position_nonce(&mut self, nonce: u64);

    async fn market(&self, market: &MarketId) -> Result<Option<Market>, PerpetualError>;

    fn set_market(&mut self, market: &Market);

    async fn position(&self, position: &PositionId) -> Result<Option<Position>, PerpetualError>;

    fn set_position(&mut self, position: &Position);

    fn remove_position(&mut self, position: &PositionId);
}

#[async_trait]
impl<S: StateStore + Send + Sync> PerpetualDB for S {
    async fn nonce(&self, id: &Address) -> Result<u64, PerpetualError> {
        let key = NS.key(Table::Account, &encoded(id));
        match StateStore::get(self, &key)
            .await
            .map_err(|err| PerpetualError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<u64>(&bytes),
            None => Ok(0),
        }
    }

    fn set_nonce(&mut self, id: &Address, nonce: u64) {
        let key = NS.key(Table::Account, &encoded(id));
        StateStore::set(self, key, encoded(&nonce));
    }

    async fn market_nonce(&self) -> Result<u64, PerpetualError> {
        let key = NS.key(Table::MarketNonce, &[]);
        match StateStore::get(self, &key)
            .await
            .map_err(|err| PerpetualError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<u64>(&bytes),
            None => Ok(0),
        }
    }

    fn set_market_nonce(&mut self, nonce: u64) {
        let key = NS.key(Table::MarketNonce, &[]);
        StateStore::set(self, key, encoded(&nonce));
    }

    async fn position_nonce(&self) -> Result<u64, PerpetualError> {
        let key = NS.key(Table::PositionNonce, &[]);
        match StateStore::get(self, &key)
            .await
            .map_err(|err| PerpetualError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<u64>(&bytes),
            None => Ok(0),
        }
    }

    fn set_position_nonce(&mut self, nonce: u64) {
        let key = NS.key(Table::PositionNonce, &[]);
        StateStore::set(self, key, encoded(&nonce));
    }

    async fn market(&self, market: &MarketId) -> Result<Option<Market>, PerpetualError> {
        let key = NS.key(Table::Market, &encoded(market));
        match StateStore::get(self, &key)
            .await
            .map_err(|err| PerpetualError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded::<Market>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_market(&mut self, market: &Market) {
        let key = NS.key(Table::Market, &encoded(&market.id));
        StateStore::set(self, key, encoded(market));
    }

    async fn position(&self, position: &PositionId) -> Result<Option<Position>, PerpetualError> {
        let key = NS.key(Table::Position, &encoded(position));
        match StateStore::get(self, &key)
            .await
            .map_err(|err| PerpetualError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded::<Position>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_position(&mut self, position: &Position) {
        let key = NS.key(Table::Position, &encoded(&position.id));
        StateStore::set(self, key, encoded(position));
    }

    fn remove_position(&mut self, position: &PositionId) {
        let key: Digest = NS.key(Table::Position, &encoded(position));
        StateStore::remove(self, key);
    }
}
