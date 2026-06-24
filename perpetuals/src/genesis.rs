use crate::{MarketId, PerpetualDB, PerpetualError, PerpetualLedger};
use commonware_codec::{DecodeExt, Encode};
use commonware_formatting::{from_hex, hex};
use nunchi_coins::CoinId;
use nunchi_oracle::NamespaceId;
use serde::{Deserialize, Serialize};

/// JSON-facing perpetuals module genesis state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PerpetualsGenesis {
    #[serde(default)]
    pub markets: Vec<MarketGenesis>,
}

/// JSON-facing market configuration seeded at genesis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MarketGenesis {
    #[serde(with = "serde_hex")]
    pub base_asset: CoinId,
    #[serde(with = "serde_hex")]
    pub quote_asset: CoinId,
    #[serde(with = "serde_hex")]
    pub collateral_asset: CoinId,
    #[serde(with = "serde_hex")]
    pub oracle_namespace: NamespaceId,
    pub oracle_interval_ms: u64,
    pub max_oracle_staleness_ms: u64,
    pub price_decimals: u8,
    pub max_leverage_bps: u32,
    pub maintenance_margin_bps: u32,
    pub funding_interval_ms: u64,
    pub max_funding_rate_bps: u32,
}

impl<D: PerpetualDB + nunchi_coins::CoinDB + nunchi_common::StateStore + Send + Sync>
    PerpetualLedger<D>
{
    /// Seed perpetuals state from genesis without transaction authorization.
    pub async fn apply_genesis(
        &mut self,
        genesis: &PerpetualsGenesis,
    ) -> Result<Vec<MarketId>, PerpetualError> {
        let mut ids = Vec::with_capacity(genesis.markets.len());
        for market in &genesis.markets {
            ids.push(
                self.create_market(
                    market.base_asset,
                    market.quote_asset,
                    market.collateral_asset,
                    market.oracle_namespace,
                    market.oracle_interval_ms,
                    market.max_oracle_staleness_ms,
                    market.price_decimals,
                    market.max_leverage_bps,
                    market.maintenance_margin_bps,
                    market.funding_interval_ms,
                    market.max_funding_rate_bps,
                )
                .await?,
            );
        }
        Ok(ids)
    }
}

mod serde_hex {
    use super::*;
    use serde::{de::Error as _, Deserializer, Serializer};

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Encode,
        S: Serializer,
    {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: DecodeExt<()>,
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes =
            from_hex(&value).ok_or_else(|| D::Error::custom("expected hex-encoded codec bytes"))?;
        T::decode(bytes.as_ref()).map_err(D::Error::custom)
    }
}
