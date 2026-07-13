//! Persistence layer for the clearinghouse module.

use crate::{
    ClearinghouseError, SettlementMarket, SettlementMarketId, CLEARINGHOUSE_NAMESPACE,
};
use async_trait::async_trait;
use commonware_codec::{Encode, Read, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_clob::{FillId, MarketId as ClobMarketId};
use nunchi_common::{Address, Namespace, StateStore};

const NS: Namespace = Namespace::new(CLEARINGHOUSE_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    Nonce = 0,
    SettlementMarket = 1,
    ClobMarketIndex = 2,
    SettledFill = 3,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, ClearinghouseError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| ClearinghouseError::Storage(err.to_string()))
}

fn nonce_key(account: &Address) -> Digest {
    NS.key(Table::Nonce, account.encode().as_ref())
}

fn settlement_market_key(id: &SettlementMarketId) -> Digest {
    NS.key(Table::SettlementMarket, id.encode().as_ref())
}

fn clob_market_index_key(clob_market: &ClobMarketId) -> Digest {
    NS.key(Table::ClobMarketIndex, clob_market.encode().as_ref())
}

fn settled_fill_key(fill: &FillId) -> Digest {
    NS.key(Table::SettledFill, fill.encode().as_ref())
}

/// Typed state access required by [`crate::ClearinghouseLedger`].
#[async_trait]
pub trait ClearinghouseDB {
    async fn nonce(&self, account: &Address) -> Result<u64, ClearinghouseError>;

    fn set_nonce(&mut self, account: &Address, nonce: u64);

    async fn settlement_market(
        &self,
        id: &SettlementMarketId,
    ) -> Result<Option<SettlementMarket>, ClearinghouseError>;

    fn set_settlement_market(&mut self, market: &SettlementMarket);

    async fn settlement_market_for_clob(
        &self,
        clob_market: &ClobMarketId,
    ) -> Result<Option<SettlementMarket>, ClearinghouseError>;

    fn set_clob_market_index(&mut self, clob_market: &ClobMarketId, id: &SettlementMarketId);

    async fn is_fill_settled(&self, fill: &FillId) -> Result<bool, ClearinghouseError>;

    fn mark_fill_settled(&mut self, fill: &FillId);
}

#[async_trait]
impl<S: StateStore + Send + Sync> ClearinghouseDB for S {
    async fn nonce(&self, account: &Address) -> Result<u64, ClearinghouseError> {
        match StateStore::get(self, &nonce_key(account))
            .await
            .map_err(|err| ClearinghouseError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_nonce(&mut self, account: &Address, nonce: u64) {
        StateStore::set(self, nonce_key(account), encoded(&nonce));
    }

    async fn settlement_market(
        &self,
        id: &SettlementMarketId,
    ) -> Result<Option<SettlementMarket>, ClearinghouseError> {
        match StateStore::get(self, &settlement_market_key(id))
            .await
            .map_err(|err| ClearinghouseError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_settlement_market(&mut self, market: &SettlementMarket) {
        StateStore::set(self, settlement_market_key(&market.id), encoded(market));
    }

    async fn settlement_market_for_clob(
        &self,
        clob_market: &ClobMarketId,
    ) -> Result<Option<SettlementMarket>, ClearinghouseError> {
        let key = clob_market_index_key(clob_market);
        let id = match StateStore::get(self, &key)
            .await
            .map_err(|err| ClearinghouseError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<SettlementMarketId>(&bytes)?,
            None => return Ok(None),
        };
        self.settlement_market(&id).await
    }

    fn set_clob_market_index(&mut self, clob_market: &ClobMarketId, id: &SettlementMarketId) {
        StateStore::set(self, clob_market_index_key(clob_market), encoded(id));
    }

    async fn is_fill_settled(&self, fill: &FillId) -> Result<bool, ClearinghouseError> {
        Ok(
            StateStore::get(self, &settled_fill_key(fill))
                .await
                .map_err(|err| ClearinghouseError::Storage(err.to_string()))?
                .is_some(),
        )
    }

    fn mark_fill_settled(&mut self, fill: &FillId) {
        StateStore::set(self, settled_fill_key(fill), vec![1]);
    }
}
