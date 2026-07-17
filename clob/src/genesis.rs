use crate::{
    ledger::{canonical_asset_pair, validate_market},
    market_id, AssetId, ClobDB, ClobError, ClobLedger, Market,
};
use commonware_codec::DecodeExt;
use commonware_formatting::from_hex;
use nunchi_common::Address;
use serde::{Deserialize, Serialize};

/// JSON-facing CLOB genesis state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClobGenesis {
    #[serde(default)]
    pub markets: Vec<ClobMarketGenesis>,
}

/// Initial spot market configured at genesis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClobMarketGenesis {
    /// Hex-encoded base asset id.
    pub base_asset: String,
    /// Hex-encoded quote asset id.
    pub quote_asset: String,
    pub tick_size: u128,
    pub lot_size: u128,
    /// Bech32 account recorded as the market creator.
    pub created_by: String,
}

impl ClobMarketGenesis {
    /// Convert this JSON-facing market into the canonical ledger record.
    pub fn market(&self) -> Result<Market, ClobError> {
        let base_asset = decode_hex::<AssetId>(&self.base_asset, "base_asset")?;
        let quote_asset = decode_hex::<AssetId>(&self.quote_asset, "quote_asset")?;
        validate_market(base_asset, quote_asset, self.tick_size, self.lot_size)?;
        let (base_asset, quote_asset) = canonical_asset_pair(base_asset, quote_asset);
        let id = market_id(&base_asset, &quote_asset, self.tick_size, self.lot_size);
        let created_by = Address::from_bech32(&self.created_by)
            .map_err(|err| ClobError::Storage(format!("invalid created_by: {err}")))?;
        Ok(Market {
            id,
            base_asset,
            quote_asset,
            tick_size: self.tick_size,
            lot_size: self.lot_size,
            created_by,
            created_at_height: 0,
            created_at_ms: 0,
        })
    }
}

impl<D: ClobDB> ClobLedger<D> {
    /// Seed CLOB state from genesis.
    pub async fn apply_genesis(&mut self, genesis: &ClobGenesis) -> Result<(), ClobError> {
        let mut market_index = self.db.market_index().await?;
        for market in &genesis.markets {
            let definition = market.market()?;
            if self.db.market(&definition.id).await?.is_some() {
                return Err(ClobError::MarketAlreadyExists);
            }
            if market_index.len() == crate::MAX_MARKETS {
                return Err(ClobError::MarketIndexFull);
            }
            self.db.set_market(&definition);
            self.db.set_market_sequence(&definition.id, 0);
            market_index.push(definition.id);
        }
        self.db.set_market_index(&market_index);
        Ok(())
    }
}

fn decode_hex<T>(value: &str, what: &'static str) -> Result<T, ClobError>
where
    T: DecodeExt<()>,
{
    let bytes = from_hex(value).ok_or_else(|| ClobError::Storage(format!("invalid {what}")))?;
    T::decode(bytes.as_ref()).map_err(|err| ClobError::Storage(format!("invalid {what}: {err}")))
}
