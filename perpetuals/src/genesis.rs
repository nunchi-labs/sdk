use crate::{
    derive_market_id, LedgerError, Market, MarketId, PerpetualDB, PerpetualLedger, PRICE_SCALE,
};
use commonware_codec::DecodeExt;
use commonware_formatting::from_hex;
use nunchi_coins::CoinId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PerpetualsGenesis {
    #[serde(default)]
    pub markets: Vec<MarketGenesis>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MarketGenesis {
    pub base_asset: String,
    pub quote_asset: String,
    pub collateral_asset: String,
    pub max_leverage_bps: u32,
    pub maintenance_margin_bps: u32,
    pub mark_price: u128,
}

impl MarketGenesis {
    fn base_asset(&self) -> Result<CoinId, LedgerError> {
        decode_hex(&self.base_asset, "base asset")
    }

    fn quote_asset(&self) -> Result<CoinId, LedgerError> {
        decode_hex(&self.quote_asset, "quote asset")
    }

    fn collateral_asset(&self) -> Result<CoinId, LedgerError> {
        decode_hex(&self.collateral_asset, "collateral asset")
    }

    pub fn derived_market_id(&self, nonce: u64) -> Result<MarketId, LedgerError> {
        Ok(derive_market_id(
            self.base_asset()?,
            self.quote_asset()?,
            self.collateral_asset()?,
            nonce,
        ))
    }

    pub fn market(&self, nonce: u64) -> Result<Market, LedgerError> {
        let id = self.derived_market_id(nonce)?;
        if self.mark_price == 0 || self.mark_price > PRICE_SCALE * u64::MAX as u128 {
            return Err(LedgerError::InvalidPrice);
        }
        Ok(Market {
            id,
            base_asset: self.base_asset()?,
            quote_asset: self.quote_asset()?,
            collateral_asset: self.collateral_asset()?,
            max_leverage_bps: self.max_leverage_bps,
            maintenance_margin_bps: self.maintenance_margin_bps,
            mark_price: self.mark_price,
            open_interest: 0,
        })
    }
}

impl<D: PerpetualDB> PerpetualLedger<D> {
    pub async fn apply_genesis(&mut self, genesis: &PerpetualsGenesis) -> Result<(), LedgerError> {
        for market in &genesis.markets {
            self.create_market(
                market.base_asset()?,
                market.quote_asset()?,
                market.collateral_asset()?,
                market.max_leverage_bps,
                market.maintenance_margin_bps,
                market.mark_price,
            )
            .await?;
        }
        Ok(())
    }
}

fn decode_hex<T>(value: &str, what: &'static str) -> Result<T, LedgerError>
where
    T: DecodeExt<()>,
{
    let bytes = from_hex(value).ok_or_else(|| LedgerError::Storage(format!("invalid {what}")))?;
    T::decode(bytes.as_ref()).map_err(|err| LedgerError::Storage(err.to_string()))
}
