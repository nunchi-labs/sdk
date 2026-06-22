//! Persistence layer for the oracle module.

use crate::{
    DivergenceState, FeedState, MarkInputs, MarketId, OracleConfig, OracleError, OracleState,
    SourceId, UpdaterPolicy, ORACLE_NAMESPACE,
};
use async_trait::async_trait;
use commonware_codec::{Encode, Read, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Namespace, StateStore};

const NS: Namespace = Namespace::new(ORACLE_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    Nonce = 0,
    Config = 1,
    Updater = 2,
    Feed = 3,
    Oracle = 4,
    Mark = 5,
    Divergence = 6,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, OracleError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| OracleError::Storage(err.to_string()))
}

fn updater_key(market: &MarketId, source: &SourceId, updater: &Address) -> Digest {
    let mut logical = encoded(market);
    logical.extend_from_slice(source.encode().as_ref());
    logical.extend_from_slice(updater.encode().as_ref());
    NS.key(Table::Updater, &logical)
}

fn feed_key(market: &MarketId, source: &SourceId) -> Digest {
    let mut logical = encoded(market);
    logical.extend_from_slice(source.encode().as_ref());
    NS.key(Table::Feed, &logical)
}

#[async_trait]
pub trait OracleDB {
    async fn nonce(&self, account: &Address) -> Result<u64, OracleError>;

    fn set_nonce(&mut self, account: &Address, nonce: u64);

    async fn config(&self, market: &MarketId) -> Result<Option<OracleConfig>, OracleError>;

    fn set_config(&mut self, market: &MarketId, config: &OracleConfig);

    async fn updater(
        &self,
        market: &MarketId,
        source: &SourceId,
        updater: &Address,
    ) -> Result<Option<UpdaterPolicy>, OracleError>;

    fn set_updater(
        &mut self,
        market: &MarketId,
        source: &SourceId,
        updater: &Address,
        policy: &UpdaterPolicy,
    );

    async fn feed(
        &self,
        market: &MarketId,
        source: &SourceId,
    ) -> Result<Option<FeedState>, OracleError>;

    fn set_feed(&mut self, market: &MarketId, source: &SourceId, feed: &FeedState);

    async fn oracle(&self, market: &MarketId) -> Result<Option<OracleState>, OracleError>;

    fn set_oracle(&mut self, market: &MarketId, oracle: &OracleState);

    async fn mark(&self, market: &MarketId) -> Result<Option<MarkInputs>, OracleError>;

    fn set_mark(&mut self, market: &MarketId, mark: &MarkInputs);

    async fn divergence(&self, market: &MarketId) -> Result<Option<DivergenceState>, OracleError>;

    fn set_divergence(&mut self, market: &MarketId, divergence: &DivergenceState);
}

#[async_trait]
impl<S: StateStore + Send + Sync> OracleDB for S {
    async fn nonce(&self, account: &Address) -> Result<u64, OracleError> {
        let key = NS.key(Table::Nonce, account.encode().as_ref());
        match StateStore::get(self, &key)
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_nonce(&mut self, account: &Address, nonce: u64) {
        let key = NS.key(Table::Nonce, account.encode().as_ref());
        StateStore::set(self, key, encoded(&nonce));
    }

    async fn config(&self, market: &MarketId) -> Result<Option<OracleConfig>, OracleError> {
        let key = NS.key(Table::Config, market.encode().as_ref());
        match StateStore::get(self, &key)
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_config(&mut self, market: &MarketId, config: &OracleConfig) {
        let key = NS.key(Table::Config, market.encode().as_ref());
        StateStore::set(self, key, encoded(config));
    }

    async fn updater(
        &self,
        market: &MarketId,
        source: &SourceId,
        updater: &Address,
    ) -> Result<Option<UpdaterPolicy>, OracleError> {
        match StateStore::get(self, &updater_key(market, source, updater))
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_updater(
        &mut self,
        market: &MarketId,
        source: &SourceId,
        updater: &Address,
        policy: &UpdaterPolicy,
    ) {
        StateStore::set(self, updater_key(market, source, updater), encoded(policy));
    }

    async fn feed(
        &self,
        market: &MarketId,
        source: &SourceId,
    ) -> Result<Option<FeedState>, OracleError> {
        match StateStore::get(self, &feed_key(market, source))
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_feed(&mut self, market: &MarketId, source: &SourceId, feed: &FeedState) {
        StateStore::set(self, feed_key(market, source), encoded(feed));
    }

    async fn oracle(&self, market: &MarketId) -> Result<Option<OracleState>, OracleError> {
        let key = NS.key(Table::Oracle, market.encode().as_ref());
        match StateStore::get(self, &key)
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_oracle(&mut self, market: &MarketId, oracle: &OracleState) {
        let key = NS.key(Table::Oracle, market.encode().as_ref());
        StateStore::set(self, key, encoded(oracle));
    }

    async fn mark(&self, market: &MarketId) -> Result<Option<MarkInputs>, OracleError> {
        let key = NS.key(Table::Mark, market.encode().as_ref());
        match StateStore::get(self, &key)
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_mark(&mut self, market: &MarketId, mark: &MarkInputs) {
        let key = NS.key(Table::Mark, market.encode().as_ref());
        StateStore::set(self, key, encoded(mark));
    }

    async fn divergence(&self, market: &MarketId) -> Result<Option<DivergenceState>, OracleError> {
        let key = NS.key(Table::Divergence, market.encode().as_ref());
        match StateStore::get(self, &key)
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_divergence(&mut self, market: &MarketId, divergence: &DivergenceState) {
        let key = NS.key(Table::Divergence, market.encode().as_ref());
        StateStore::set(self, key, encoded(divergence));
    }
}
