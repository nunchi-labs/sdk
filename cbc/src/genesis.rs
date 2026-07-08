use crate::{
    ledger::validate_params, BatchParams, CbcDB, CbcError, CbcLedger, MarketClearingState,
    MAX_CLEARING_MARKETS,
};
use commonware_codec::DecodeExt;
use commonware_formatting::from_hex;
use nunchi_clob::MarketId;
use nunchi_common::Address;
use nunchi_house::HouseDB;
use serde::{Deserialize, Serialize};

/// JSON-facing CBC genesis state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CbcGenesis {
    #[serde(default)]
    pub markets: Vec<CbcMarketGenesis>,
}

/// Initial batch clearing market configured at genesis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CbcMarketGenesis {
    /// Hex-encoded market id.
    pub market: String,
    /// Bech32 account allowed to update parameters and mode.
    pub admin: String,
    /// Bech32 account allowed to close and clear batches.
    pub keeper: String,
    pub cadence_blocks: u64,
    pub oracle_band_bps: u32,
    pub max_batch_notional: u128,
    pub max_submitter_notional: u128,
    pub min_clearing_qty: u128,
    pub price_tick: u128,
    pub size_tick: u128,
}

impl<D: CbcDB + HouseDB> CbcLedger<D> {
    /// Seed CBC state from genesis.
    pub async fn apply_genesis(&mut self, genesis: &CbcGenesis) -> Result<(), CbcError> {
        let mut market_index = self.db.market_index().await?;
        for market in &genesis.markets {
            let id = decode_hex::<MarketId>(&market.market, "market")?;
            let params = BatchParams {
                admin: Address::from_bech32(&market.admin)
                    .map_err(|err| CbcError::Storage(format!("invalid admin: {err}")))?,
                keeper: Address::from_bech32(&market.keeper)
                    .map_err(|err| CbcError::Storage(format!("invalid keeper: {err}")))?,
                cadence_blocks: market.cadence_blocks,
                oracle_band_bps: market.oracle_band_bps,
                max_batch_notional: market.max_batch_notional,
                max_submitter_notional: market.max_submitter_notional,
                min_clearing_qty: market.min_clearing_qty,
                price_tick: market.price_tick,
                size_tick: market.size_tick,
            };
            validate_params(&params)?;
            if self.db.params(&id).await?.is_some() {
                return Err(CbcError::MarketAlreadyRegistered);
            }
            if market_index.len() == MAX_CLEARING_MARKETS {
                return Err(CbcError::MarketIndexFull);
            }
            self.db.set_params(&id, &params);
            self.db.set_clearing_state(&id, &MarketClearingState::new());
            market_index.push(id);
        }
        self.db.set_market_index(&market_index);
        Ok(())
    }
}

fn decode_hex<T>(value: &str, what: &'static str) -> Result<T, CbcError>
where
    T: DecodeExt<()>,
{
    let bytes = from_hex(value).ok_or_else(|| CbcError::Storage(format!("invalid {what}")))?;
    T::decode(bytes.as_ref()).map_err(|err| CbcError::Storage(format!("invalid {what}: {err}")))
}
