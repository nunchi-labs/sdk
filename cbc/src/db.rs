//! Persistence layer for the CBC module.

use crate::{
    BatchIntent, BatchParams, BatchResult, CbcError, IntentId, MarketClearingState, CBC_NAMESPACE,
    MAX_CLEARING_MARKETS, MAX_PENDING_INTENTS,
};
use async_trait::async_trait;
use commonware_codec::{Encode, RangeCfg, Read, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_clob::MarketId;
use nunchi_common::{Address, Namespace, StateStore};
use nunchi_house::VaultId;

const NS: Namespace = Namespace::new(CBC_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    Nonce = 0,
    Params = 1,
    MarketIndex = 2,
    ClearingState = 3,
    Intent = 4,
    PendingIntents = 5,
    Result = 6,
    VaultNotional = 7,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, CbcError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| CbcError::Storage(err.to_string()))
}

fn nonce_key(account: &Address) -> Digest {
    NS.key(Table::Nonce, account.encode().as_ref())
}

fn params_key(market: &MarketId) -> Digest {
    NS.key(Table::Params, market.encode().as_ref())
}

fn market_index_key() -> Digest {
    NS.key(Table::MarketIndex, b"all")
}

fn clearing_state_key(market: &MarketId) -> Digest {
    NS.key(Table::ClearingState, market.encode().as_ref())
}

fn intent_key(intent: &IntentId) -> Digest {
    NS.key(Table::Intent, intent.encode().as_ref())
}

fn pending_intents_key(market: &MarketId) -> Digest {
    NS.key(Table::PendingIntents, market.encode().as_ref())
}

fn result_key(market: &MarketId, batch_number: u64) -> Digest {
    let mut logical = market.encode().as_ref().to_vec();
    logical.extend_from_slice(batch_number.encode().as_ref());
    NS.key(Table::Result, &logical)
}

fn vault_notional_key(vault: &VaultId, market: &MarketId) -> Digest {
    let mut logical = vault.encode().as_ref().to_vec();
    logical.extend_from_slice(market.encode().as_ref());
    NS.key(Table::VaultNotional, &logical)
}

/// Typed state access required by [`crate::CbcLedger`].
#[async_trait]
pub trait CbcDB {
    async fn cbc_nonce(&self, account: &Address) -> Result<u64, CbcError>;

    fn set_cbc_nonce(&mut self, account: &Address, nonce: u64);

    async fn params(&self, market: &MarketId) -> Result<Option<BatchParams>, CbcError>;

    fn set_params(&mut self, market: &MarketId, params: &BatchParams);

    async fn market_index(&self) -> Result<Vec<MarketId>, CbcError>;

    fn set_market_index(&mut self, markets: &[MarketId]);

    async fn clearing_state(&self, market: &MarketId) -> Result<MarketClearingState, CbcError>;

    fn set_clearing_state(&mut self, market: &MarketId, state: &MarketClearingState);

    async fn intent(&self, id: &IntentId) -> Result<Option<BatchIntent>, CbcError>;

    fn set_intent(&mut self, intent: &BatchIntent);

    async fn pending_intents(&self, market: &MarketId) -> Result<Vec<IntentId>, CbcError>;

    fn set_pending_intents(&mut self, market: &MarketId, intents: &[IntentId]);

    async fn batch_result(
        &self,
        market: &MarketId,
        batch_number: u64,
    ) -> Result<Option<BatchResult>, CbcError>;

    fn set_batch_result(&mut self, result: &BatchResult);

    async fn vault_notional(&self, vault: &VaultId, market: &MarketId)
        -> Result<u128, CbcError>;

    fn set_vault_notional(&mut self, vault: &VaultId, market: &MarketId, notional: u128);
}

#[async_trait]
impl<S: StateStore + Send + Sync> CbcDB for S {
    async fn cbc_nonce(&self, account: &Address) -> Result<u64, CbcError> {
        match StateStore::get(self, &nonce_key(account))
            .await
            .map_err(|err| CbcError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_cbc_nonce(&mut self, account: &Address, nonce: u64) {
        StateStore::set(self, nonce_key(account), encoded(&nonce));
    }

    async fn params(&self, market: &MarketId) -> Result<Option<BatchParams>, CbcError> {
        match StateStore::get(self, &params_key(market))
            .await
            .map_err(|err| CbcError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_params(&mut self, market: &MarketId, params: &BatchParams) {
        StateStore::set(self, params_key(market), encoded(params));
    }

    async fn market_index(&self) -> Result<Vec<MarketId>, CbcError> {
        match StateStore::get(self, &market_index_key())
            .await
            .map_err(|err| CbcError::Storage(err.to_string()))?
        {
            Some(bytes) => {
                let mut buf = bytes.as_ref();
                Vec::read_cfg(&mut buf, &(RangeCfg::new(0..=MAX_CLEARING_MARKETS), ()))
                    .map_err(|err| CbcError::Storage(err.to_string()))
            }
            None => Ok(Vec::new()),
        }
    }

    fn set_market_index(&mut self, markets: &[MarketId]) {
        StateStore::set(self, market_index_key(), encoded(&markets.to_vec()));
    }

    async fn clearing_state(&self, market: &MarketId) -> Result<MarketClearingState, CbcError> {
        match StateStore::get(self, &clearing_state_key(market))
            .await
            .map_err(|err| CbcError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(MarketClearingState::new()),
        }
    }

    fn set_clearing_state(&mut self, market: &MarketId, state: &MarketClearingState) {
        StateStore::set(self, clearing_state_key(market), encoded(state));
    }

    async fn intent(&self, id: &IntentId) -> Result<Option<BatchIntent>, CbcError> {
        match StateStore::get(self, &intent_key(id))
            .await
            .map_err(|err| CbcError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_intent(&mut self, intent: &BatchIntent) {
        StateStore::set(self, intent_key(&intent.id), encoded(intent));
    }

    async fn pending_intents(&self, market: &MarketId) -> Result<Vec<IntentId>, CbcError> {
        match StateStore::get(self, &pending_intents_key(market))
            .await
            .map_err(|err| CbcError::Storage(err.to_string()))?
        {
            Some(bytes) => {
                let mut buf = bytes.as_ref();
                Vec::read_cfg(&mut buf, &(RangeCfg::new(0..=MAX_PENDING_INTENTS), ()))
                    .map_err(|err| CbcError::Storage(err.to_string()))
            }
            None => Ok(Vec::new()),
        }
    }

    fn set_pending_intents(&mut self, market: &MarketId, intents: &[IntentId]) {
        StateStore::set(self, pending_intents_key(market), encoded(&intents.to_vec()));
    }

    async fn batch_result(
        &self,
        market: &MarketId,
        batch_number: u64,
    ) -> Result<Option<BatchResult>, CbcError> {
        match StateStore::get(self, &result_key(market, batch_number))
            .await
            .map_err(|err| CbcError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_batch_result(&mut self, result: &BatchResult) {
        StateStore::set(
            self,
            result_key(&result.market, result.batch_number),
            encoded(result),
        );
    }

    async fn vault_notional(
        &self,
        vault: &VaultId,
        market: &MarketId,
    ) -> Result<u128, CbcError> {
        match StateStore::get(self, &vault_notional_key(vault, market))
            .await
            .map_err(|err| CbcError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_vault_notional(&mut self, vault: &VaultId, market: &MarketId, notional: u128) {
        StateStore::set(self, vault_notional_key(vault, market), encoded(&notional));
    }
}
