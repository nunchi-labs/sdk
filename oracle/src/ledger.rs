use crate::{
    DivergenceLevel, DivergenceState, FeedId, FeedState, MarkInputs, MarketId, OracleConfig,
    OracleDB, OracleOperation, OracleState, OracleStatus, Price, SourceId, Transaction,
    UpdaterPolicy,
};
use nunchi_common::{Address, RuntimeContext};
use nunchi_crypto::SignatureError;
use std::collections::BTreeSet;
use thiserror::Error;

const BPS_DENOMINATOR: u128 = 10_000;
const MAX_DECIMALS: u8 = 38;

/// Deterministic oracle state-machine errors.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum OracleError {
    #[error("bad oracle transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("oracle market is not configured")]
    MarketNotConfigured,
    #[error("invalid oracle config: {0}")]
    InvalidConfig(&'static str),
    #[error("invalid oracle genesis: {0}")]
    InvalidGenesis(String),
    #[error("unauthorized oracle operation")]
    Unauthorized,
    #[error("unknown oracle source")]
    UnknownSource,
    #[error("oracle price precision is invalid")]
    InvalidPrecision,
    #[error("oracle price normalization overflow")]
    NormalizationOverflow,
    #[error("oracle price cannot be negative")]
    NegativePrice,
    #[error("oracle update is stale")]
    StaleUpdate,
    #[error("oracle update is from the future")]
    FutureUpdate,
    #[error("oracle update is older than the latest source value")]
    OutOfOrderUpdate,
    #[error("oracle price is unavailable")]
    PriceUnavailable,
    #[error("state storage error: {0}")]
    Storage(String),
}

/// Deterministic oracle ledger over a caller-provided database.
///
/// The ledger validates signed oracle transactions, mutates authenticated state through
/// [`OracleDB`], and derives market-level oracle status from stored source data. It does not fetch
/// external data and does not enforce trading policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleLedger<D> {
    db: D,
}

impl<D: OracleDB> OracleLedger<D> {
    /// Wrap a database backend as an oracle ledger.
    pub fn new(db: D) -> Self {
        Self { db }
    }

    /// Borrow the underlying database.
    pub fn db(&self) -> &D {
        &self.db
    }

    pub(crate) fn db_mut(&mut self) -> &mut D {
        &mut self.db
    }

    /// Consume the ledger, returning the underlying database.
    pub fn into_inner(self) -> D {
        self.db
    }

    /// Validate and apply a signed oracle transaction.
    ///
    /// Freshness checks use the deterministic block timestamp from [`RuntimeContext`], not local
    /// wall-clock time.
    pub async fn apply_transaction(
        &mut self,
        tx: &Transaction,
        context: RuntimeContext,
    ) -> Result<(), OracleError> {
        tx.verify()?;

        let expected = self.db.nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(OracleError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        self.apply_operation(&tx.account_id, &tx.payload.operation, context)
            .await?;
        let next_nonce = expected.checked_add(1).ok_or(OracleError::NonceOverflow)?;
        self.db.set_nonce(&tx.account_id, next_nonce);
        Ok(())
    }

    /// Load market oracle configuration.
    pub async fn config(&self, market: &MarketId) -> Result<Option<OracleConfig>, OracleError> {
        self.db.config(market).await
    }

    /// Load market-level oracle state.
    pub async fn oracle(&self, market: &MarketId) -> Result<Option<OracleState>, OracleError> {
        self.db.oracle(market).await
    }

    /// Load the latest accepted feed state for a market/source pair.
    pub async fn feed(
        &self,
        market: &MarketId,
        source: &SourceId,
    ) -> Result<Option<FeedState>, OracleError> {
        self.db.feed(market, source).await
    }

    /// Load the latest mark inputs for a market.
    pub async fn mark(&self, market: &MarketId) -> Result<Option<MarkInputs>, OracleError> {
        self.db.mark(market).await
    }

    /// Load current mark/oracle divergence state for a market.
    pub async fn divergence(
        &self,
        market: &MarketId,
    ) -> Result<Option<DivergenceState>, OracleError> {
        self.db.divergence(market).await
    }

    async fn apply_operation(
        &mut self,
        signer: &Address,
        operation: &OracleOperation,
        context: RuntimeContext,
    ) -> Result<(), OracleError> {
        match operation {
            OracleOperation::ConfigureMarket { market, config } => {
                self.configure_market(signer, market, config.clone()).await
            }
            OracleOperation::SetUpdater {
                market,
                source,
                updater,
                policy,
            } => {
                self.set_updater(signer, market, source, updater, policy.clone())
                    .await
            }
            OracleOperation::SubmitFeedUpdate {
                market,
                source,
                feed,
                raw_value,
                raw_decimals,
                publish_time_ms,
                confidence,
            } => {
                let update = FeedUpdate {
                    market,
                    source,
                    feed: *feed,
                    raw_value: *raw_value,
                    raw_decimals: *raw_decimals,
                    publish_time_ms: *publish_time_ms,
                    confidence: *confidence,
                };
                self.submit_feed_update(signer, update, context).await
            }
            OracleOperation::SubmitMarkInputs { market, inputs } => {
                self.submit_mark_inputs(signer, market, inputs.clone())
                    .await
            }
        }
    }

    async fn configure_market(
        &mut self,
        signer: &Address,
        market: &MarketId,
        config: OracleConfig,
    ) -> Result<(), OracleError> {
        validate_config(&config)?;
        match self.db.config(market).await? {
            Some(existing) if existing.admin != *signer => return Err(OracleError::Unauthorized),
            None if config.admin != *signer => return Err(OracleError::Unauthorized),
            _ => {}
        }

        self.db.set_config(market, &config);
        if self.db.oracle(market).await?.is_none() {
            self.db.set_oracle(
                market,
                &OracleState {
                    external_observed_price: None,
                    external_reference_price: None,
                    oracle_price: None,
                    source_id: None,
                    publish_time_ms: 0,
                    status: OracleStatus::Unavailable,
                },
            );
        }
        Ok(())
    }

    async fn set_updater(
        &mut self,
        signer: &Address,
        market: &MarketId,
        source: &SourceId,
        updater: &Address,
        policy: UpdaterPolicy,
    ) -> Result<(), OracleError> {
        let config = self
            .db
            .config(market)
            .await?
            .ok_or(OracleError::MarketNotConfigured)?;
        if config.admin != *signer {
            return Err(OracleError::Unauthorized);
        }
        require_source(&config, source)?;
        self.db.set_updater(market, source, updater, &policy);
        Ok(())
    }

    async fn submit_feed_update(
        &mut self,
        signer: &Address,
        update: FeedUpdate<'_>,
        context: RuntimeContext,
    ) -> Result<(), OracleError> {
        let config = self
            .db
            .config(update.market)
            .await?
            .ok_or(OracleError::MarketNotConfigured)?;
        require_source(&config, update.source)?;
        if !self
            .db
            .updater(update.market, update.source, signer)
            .await?
            .is_some_and(|policy| policy.enabled)
        {
            return Err(OracleError::Unauthorized);
        }
        if update.publish_time_ms > context.timestamp_ms {
            return Err(OracleError::FutureUpdate);
        }
        if update
            .publish_time_ms
            .saturating_add(config.max_staleness_ms)
            < context.timestamp_ms
        {
            return Err(OracleError::StaleUpdate);
        }
        if let Some(existing) = self.db.feed(update.market, update.source).await? {
            if update.publish_time_ms <= existing.publish_time_ms {
                return Err(OracleError::OutOfOrderUpdate);
            }
        }

        let normalized = normalize_price(
            update.raw_value,
            update.raw_decimals,
            config.price_decimals,
            config.allow_negative,
        )?;
        let feed = FeedState {
            feed_id: update.feed,
            raw_value: update.raw_value,
            raw_decimals: update.raw_decimals,
            normalized_price: normalized,
            publish_time_ms: update.publish_time_ms,
            confidence: update.confidence,
            updater: signer.clone(),
        };
        self.db.set_feed(update.market, update.source, &feed);

        let oracle = self
            .aggregate(update.market, &config, context.timestamp_ms)
            .await?;
        self.db.set_oracle(update.market, &oracle);
        Ok(())
    }

    async fn submit_mark_inputs(
        &mut self,
        signer: &Address,
        market: &MarketId,
        inputs: MarkInputs,
    ) -> Result<(), OracleError> {
        let config = self
            .db
            .config(market)
            .await?
            .ok_or(OracleError::MarketNotConfigured)?;
        if config.admin != *signer {
            return Err(OracleError::Unauthorized);
        }
        let oracle = self
            .db
            .oracle(market)
            .await?
            .ok_or(OracleError::PriceUnavailable)?;
        let oracle_price = oracle.oracle_price.ok_or(OracleError::PriceUnavailable)?;
        if inputs.mark_price.decimals != config.price_decimals {
            return Err(OracleError::InvalidPrecision);
        }

        let bps = price_diff_bps(inputs.mark_price.value, oracle_price.value);
        let level = if bps >= config.divergence_halt_bps {
            DivergenceLevel::Halt
        } else if bps >= config.divergence_warn_bps {
            DivergenceLevel::Warn
        } else {
            DivergenceLevel::None
        };
        self.db.set_mark(market, &inputs);
        self.db
            .set_divergence(market, &DivergenceState { bps, level });

        let mut next = oracle;
        if level != DivergenceLevel::None {
            next.status = OracleStatus::Divergent;
        } else if next.status == OracleStatus::Divergent {
            next.status = OracleStatus::Fresh;
        }
        self.db.set_oracle(market, &next);
        Ok(())
    }

    async fn aggregate(
        &self,
        market: &MarketId,
        config: &OracleConfig,
        timestamp_ms: u64,
    ) -> Result<OracleState, OracleError> {
        let previous = self.db.oracle(market).await?.unwrap_or(OracleState {
            external_observed_price: None,
            external_reference_price: None,
            oracle_price: None,
            source_id: None,
            publish_time_ms: 0,
            status: OracleStatus::Unavailable,
        });
        let mut selected: Option<(SourceId, FeedState)> = None;
        for source in &config.source_priority {
            let Some(feed) = self.db.feed(market, source).await? else {
                continue;
            };
            if feed.publish_time_ms.saturating_add(config.max_staleness_ms) >= timestamp_ms {
                selected = Some((*source, feed));
                break;
            }
        }

        let Some((source, feed)) = selected else {
            return Ok(OracleState {
                status: OracleStatus::Unavailable,
                source_id: None,
                ..previous
            });
        };
        let previous_price = previous.oracle_price;
        let confidence_high = confidence_bps(feed.confidence, feed.normalized_price.value)
            > config.max_confidence_bps;
        let price_jump_high = previous_price
            .map(|price| price_diff_bps(feed.normalized_price.value, price.value))
            .is_some_and(|bps| bps >= config.high_volatility_bps);
        let mut status = if confidence_high || price_jump_high {
            OracleStatus::HighVolatility
        } else {
            OracleStatus::Fresh
        };
        if self
            .db
            .divergence(market)
            .await?
            .is_some_and(|divergence| divergence.level != DivergenceLevel::None)
        {
            status = OracleStatus::Divergent;
        }

        Ok(OracleState {
            external_observed_price: Some(feed.normalized_price),
            external_reference_price: Some(feed.normalized_price),
            oracle_price: Some(feed.normalized_price),
            source_id: Some(source),
            publish_time_ms: feed.publish_time_ms,
            status,
        })
    }
}

struct FeedUpdate<'a> {
    market: &'a MarketId,
    source: &'a SourceId,
    feed: FeedId,
    raw_value: i128,
    raw_decimals: u8,
    publish_time_ms: u64,
    confidence: u128,
}

pub(crate) fn validate_config(config: &OracleConfig) -> Result<(), OracleError> {
    if config.price_decimals > MAX_DECIMALS {
        return Err(OracleError::InvalidConfig("precision exceeds maximum"));
    }
    if config.source_priority.is_empty() {
        return Err(OracleError::InvalidConfig("source priority is empty"));
    }
    if config.divergence_warn_bps > config.divergence_halt_bps {
        return Err(OracleError::InvalidConfig(
            "divergence thresholds are inverted",
        ));
    }
    let mut sources = BTreeSet::new();
    if !config
        .source_priority
        .iter()
        .all(|source| sources.insert(source))
    {
        return Err(OracleError::InvalidConfig("duplicate source"));
    }
    Ok(())
}

fn require_source(config: &OracleConfig, source: &SourceId) -> Result<(), OracleError> {
    if config
        .source_priority
        .iter()
        .any(|candidate| candidate == source)
    {
        Ok(())
    } else {
        Err(OracleError::UnknownSource)
    }
}

fn normalize_price(
    raw_value: i128,
    raw_decimals: u8,
    price_decimals: u8,
    allow_negative: bool,
) -> Result<Price, OracleError> {
    if raw_decimals > MAX_DECIMALS || price_decimals > MAX_DECIMALS {
        return Err(OracleError::InvalidPrecision);
    }
    if raw_value < 0 && !allow_negative {
        return Err(OracleError::NegativePrice);
    }
    let value = if raw_decimals == price_decimals {
        raw_value
    } else if raw_decimals > price_decimals {
        raw_value / pow10(raw_decimals - price_decimals)?
    } else {
        raw_value
            .checked_mul(pow10(price_decimals - raw_decimals)?)
            .ok_or(OracleError::NormalizationOverflow)?
    };
    Ok(Price::new(value, price_decimals))
}

fn pow10(exp: u8) -> Result<i128, OracleError> {
    let mut value = 1i128;
    for _ in 0..exp {
        value = value
            .checked_mul(10)
            .ok_or(OracleError::NormalizationOverflow)?;
    }
    Ok(value)
}

fn confidence_bps(confidence: u128, price: i128) -> u32 {
    let denominator = checked_abs(price);
    if denominator == 0 {
        return if confidence == 0 { 0 } else { u32::MAX };
    }
    let bps = confidence
        .saturating_mul(BPS_DENOMINATOR)
        .saturating_div(denominator);
    bps.min(u32::MAX as u128) as u32
}

fn price_diff_bps(left: i128, right: i128) -> u32 {
    let denominator = checked_abs(right);
    let diff = left.abs_diff(right);
    if denominator == 0 {
        return if diff == 0 { 0 } else { u32::MAX };
    }
    let bps = diff
        .saturating_mul(BPS_DENOMINATOR)
        .saturating_div(denominator);
    bps.min(u32::MAX as u128) as u32
}

fn checked_abs(value: i128) -> u128 {
    value.unsigned_abs()
}
