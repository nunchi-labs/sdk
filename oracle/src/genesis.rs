use crate::{
    ledger::validate_config, MarketId, OracleConfig, OracleDB, OracleError, OracleLedger,
    OracleState, OracleStatus, SourceId, UpdaterPolicy,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_formatting::{from_hex, hex};
use nunchi_common::Address;
use serde::{Deserialize, Serialize};

/// JSON-facing oracle module genesis state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleGenesis {
    /// Markets to configure at genesis.
    #[serde(default)]
    pub markets: Vec<OracleMarketGenesis>,
}

/// JSON-facing oracle market genesis entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleMarketGenesis {
    /// Market to configure at genesis.
    #[serde(with = "serde_hex")]
    pub market: MarketId,
    /// Oracle policy to seed for `market`.
    pub config: OracleConfigGenesis,
    /// Updater policies to seed for configured sources.
    #[serde(default)]
    pub updaters: Vec<OracleUpdaterGenesis>,
}

/// JSON-facing [`OracleConfig`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleConfigGenesis {
    /// Admin account allowed to configure the market after genesis.
    #[serde(with = "serde_hex")]
    pub admin: Address,
    /// Canonical decimals used for stored oracle prices.
    pub price_decimals: u8,
    /// Maximum accepted age of a feed update at deterministic block execution time.
    pub max_staleness_ms: u64,
    /// Maximum confidence band, in basis points of price, before status becomes high volatility.
    pub max_confidence_bps: u32,
    /// Maximum price jump versus the previous oracle price before status becomes high volatility.
    pub high_volatility_bps: u32,
    /// Mark/oracle divergence threshold, in basis points, for warning status.
    pub divergence_warn_bps: u32,
    /// Mark/oracle divergence threshold, in basis points, for halt-level divergence.
    pub divergence_halt_bps: u32,
    /// Ordered source fallback list.
    #[serde(default, with = "serde_hex_vec")]
    pub source_priority: Vec<SourceId>,
    /// Whether negative prices are valid for this market.
    #[serde(default)]
    pub allow_negative: bool,
}

/// JSON-facing updater policy for one source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleUpdaterGenesis {
    /// Source the updater may submit for.
    #[serde(with = "serde_hex")]
    pub source: SourceId,
    /// Updater account.
    #[serde(with = "serde_hex")]
    pub updater: Address,
    /// Whether the updater may submit feed updates.
    pub enabled: bool,
}

impl OracleConfigGenesis {
    pub fn config(&self) -> Result<OracleConfig, OracleError> {
        let config = OracleConfig {
            admin: self.admin.clone(),
            price_decimals: self.price_decimals,
            max_staleness_ms: self.max_staleness_ms,
            max_confidence_bps: self.max_confidence_bps,
            high_volatility_bps: self.high_volatility_bps,
            divergence_warn_bps: self.divergence_warn_bps,
            divergence_halt_bps: self.divergence_halt_bps,
            source_priority: self.source_priority.clone(),
            allow_negative: self.allow_negative,
        };
        validate_config(&config)?;
        Ok(config)
    }
}

impl<D: OracleDB> OracleLedger<D> {
    /// Seed oracle state from genesis without transaction authorization.
    pub async fn apply_genesis(&mut self, genesis: &OracleGenesis) -> Result<(), OracleError> {
        for market in &genesis.markets {
            let config = market.config.config()?;
            if self.db().config(&market.market).await?.is_some() {
                return Err(OracleError::InvalidGenesis(format!(
                    "duplicate oracle market {:?}",
                    market.market
                )));
            }

            self.db_mut().set_config(&market.market, &config);
            self.db_mut().set_oracle(
                &market.market,
                &OracleState {
                    external_observed_price: None,
                    external_reference_price: None,
                    oracle_price: None,
                    source_id: None,
                    publish_time_ms: 0,
                    status: OracleStatus::Unavailable,
                },
            );

            for updater in &market.updaters {
                if !config
                    .source_priority
                    .iter()
                    .any(|candidate| candidate == &updater.source)
                {
                    return Err(OracleError::UnknownSource);
                }
                self.db_mut().set_updater(
                    &market.market,
                    &updater.source,
                    &updater.updater,
                    &UpdaterPolicy {
                        enabled: updater.enabled,
                    },
                );
            }
        }
        Ok(())
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

mod serde_hex_vec {
    use super::*;
    use serde::{de::Error as _, Deserializer, Serializer};

    pub fn serialize<T, S>(value: &[T], serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Encode,
        S: Serializer,
    {
        serializer.collect_seq(value.iter().map(|item| hex(&item.encode())))
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        T: DecodeExt<()>,
        D: Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        values
            .into_iter()
            .map(|value| {
                let bytes = from_hex(&value)
                    .ok_or_else(|| D::Error::custom("expected hex-encoded codec bytes"))?;
                T::decode(bytes.as_ref()).map_err(D::Error::custom)
            })
            .collect()
    }
}
