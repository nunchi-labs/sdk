use commonware_codec::{EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_common::Address;

/// Maximum number of configured sources a market can read.
pub const MAX_SOURCES: usize = 32;

/// Identifier for a market whose price is tracked by the oracle.
///
/// TODO(distractedm1nd): market registry should define how market IDs are
/// derived/which market params they bind to
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MarketId(pub Digest);

/// Identifier for one configured source of data for a market.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceId(pub Digest);

/// Provider-specific feed identifier included for audit and debugging.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FeedId(pub Digest);

macro_rules! digest_id_codec {
    ($ty:ty) => {
        impl Write for $ty {
            fn write(&self, buf: &mut impl bytes::BufMut) {
                self.0.write(buf);
            }
        }

        impl Read for $ty {
            type Cfg = ();

            fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
                Ok(Self(Digest::read(buf)?))
            }
        }

        impl FixedSize for $ty {
            const SIZE: usize = Digest::SIZE;
        }
    };
}

digest_id_codec!(MarketId);
digest_id_codec!(SourceId);
digest_id_codec!(FeedId);

/// Fixed-point integer price.
///
/// `value` should be interpreted as `value / 10^decimals`. The oracle never uses floating point
/// arithmetic, so all feed values are normalized into this representation before downstream
/// modules consume them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Price {
    /// Signed integer price amount.
    pub value: i128,
    /// Number of decimal places implied by [`Price::value`].
    pub decimals: u8,
}

impl Price {
    /// Construct a fixed-point price.
    pub const fn new(value: i128, decimals: u8) -> Self {
        Self { value, decimals }
    }
}

impl Write for Price {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.value.write(buf);
        self.decimals.write(buf);
    }
}

impl Read for Price {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            value: i128::read(buf)?,
            decimals: u8::read(buf)?,
        })
    }
}

impl EncodeSize for Price {
    fn encode_size(&self) -> usize {
        self.value.encode_size() + self.decimals.encode_size()
    }
}

/// Temporary (pre Market Registry) v1 oracle policy for a market.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleConfig {
    /// Account allowed to configure this market and updater set.
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
    /// Ordered source fallback list. The first fresh source is selected as the oracle price.
    pub source_priority: Vec<SourceId>,
    /// Whether negative prices are valid for this market.
    pub allow_negative: bool,
}

impl Write for OracleConfig {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.admin.write(buf);
        self.price_decimals.write(buf);
        self.max_staleness_ms.write(buf);
        self.max_confidence_bps.write(buf);
        self.high_volatility_bps.write(buf);
        self.divergence_warn_bps.write(buf);
        self.divergence_halt_bps.write(buf);
        self.source_priority.write(buf);
        self.allow_negative.write(buf);
    }
}

impl Read for OracleConfig {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            admin: Address::read(buf)?,
            price_decimals: u8::read(buf)?,
            max_staleness_ms: u64::read(buf)?,
            max_confidence_bps: u32::read(buf)?,
            high_volatility_bps: u32::read(buf)?,
            divergence_warn_bps: u32::read(buf)?,
            divergence_halt_bps: u32::read(buf)?,
            source_priority: Vec::read_cfg(buf, &(RangeCfg::new(0..=MAX_SOURCES), ()))?,
            allow_negative: bool::read(buf)?,
        })
    }
}

impl EncodeSize for OracleConfig {
    fn encode_size(&self) -> usize {
        self.admin.encode_size()
            + self.price_decimals.encode_size()
            + self.max_staleness_ms.encode_size()
            + self.max_confidence_bps.encode_size()
            + self.high_volatility_bps.encode_size()
            + self.divergence_warn_bps.encode_size()
            + self.divergence_halt_bps.encode_size()
            + self.source_priority.encode_size()
            + self.allow_negative.encode_size()
    }
}

/// Authorization switch for one updater account on one `(market, source)` lane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdaterPolicy {
    /// Whether the updater may submit feed updates.
    pub enabled: bool,
}

impl Write for UpdaterPolicy {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.enabled.write(buf);
    }
}

impl Read for UpdaterPolicy {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            enabled: bool::read(buf)?,
        })
    }
}

impl EncodeSize for UpdaterPolicy {
    fn encode_size(&self) -> usize {
        self.enabled.encode_size()
    }
}

/// Market-level oracle status consumed by downstream modules.
///
/// These statuses do not themselves enforce trading rules. Perps, CLOB, liquidation, and market
/// registry policy decide how to react.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleStatus {
    /// The oracle has a usable current price.
    Fresh = 0,
    /// The oracle price is too old for risk-increasing actions.
    Stale = 1,
    /// Confidence or price movement is high enough that downstream modules should restrict risk.
    HighVolatility = 2,
    /// Book-derived mark price and oracle price are far apart.
    Divergent = 3,
    /// The oracle cannot produce a usable market-level price.
    Unavailable = 4,
}

impl Write for OracleStatus {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        (*self as u8).write(buf);
    }
}

impl Read for OracleStatus {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Fresh),
            1 => Ok(Self::Stale),
            2 => Ok(Self::HighVolatility),
            3 => Ok(Self::Divergent),
            4 => Ok(Self::Unavailable),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for OracleStatus {
    fn encode_size(&self) -> usize {
        1
    }
}

/// Latest accepted update from a single source for a single market.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedState {
    /// Provider-specific feed identity supplied by the adapter.
    pub feed_id: FeedId,
    /// Raw integer value submitted before normalization.
    pub raw_value: i128,
    /// Decimal precision of [`FeedState::raw_value`].
    pub raw_decimals: u8,
    /// Raw value normalized into the market's canonical price precision.
    pub normalized_price: Price,
    /// External source publish time in Unix milliseconds.
    pub publish_time_ms: u64,
    /// Confidence band around the submitted price.
    ///
    /// The value is interpreted in the same integer scale as the submitted price.
    pub confidence: u128,
    /// Account that signed the accepted update.
    pub updater: Address,
}

impl Write for FeedState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.feed_id.write(buf);
        self.raw_value.write(buf);
        self.raw_decimals.write(buf);
        self.normalized_price.write(buf);
        self.publish_time_ms.write(buf);
        self.confidence.write(buf);
        self.updater.write(buf);
    }
}

impl Read for FeedState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            feed_id: FeedId::read(buf)?,
            raw_value: i128::read(buf)?,
            raw_decimals: u8::read(buf)?,
            normalized_price: Price::read(buf)?,
            publish_time_ms: u64::read(buf)?,
            confidence: u128::read(buf)?,
            updater: Address::read(buf)?,
        })
    }
}

impl EncodeSize for FeedState {
    fn encode_size(&self) -> usize {
        self.feed_id.encode_size()
            + self.raw_value.encode_size()
            + self.raw_decimals.encode_size()
            + self.normalized_price.encode_size()
            + self.publish_time_ms.encode_size()
            + self.confidence.encode_size()
            + self.updater.encode_size()
    }
}

/// Market-level price view derived from configured source state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleState {
    /// Current external observation, if official external data is presently available.
    ///
    /// This can be `None` during expected closures or feed outages.
    pub external_observed_price: Option<Price>,
    /// Last valid external observed price.
    ///
    /// This is expected to remain numeric even when current external
    /// data is closed.
    pub external_reference_price: Option<Price>,
    /// Canonical chain oracle price for downstream modules.
    pub oracle_price: Option<Price>,
    /// Source selected for the current oracle price.
    pub source_id: Option<SourceId>,
    /// Publish time of the selected source update.
    pub publish_time_ms: u64,
    /// Market-level oracle status.
    pub status: OracleStatus,
}

impl Write for OracleState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.external_observed_price.write(buf);
        self.external_reference_price.write(buf);
        self.oracle_price.write(buf);
        self.source_id.write(buf);
        self.publish_time_ms.write(buf);
        self.status.write(buf);
    }
}

impl Read for OracleState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            external_observed_price: Option::read(buf)?,
            external_reference_price: Option::read(buf)?,
            oracle_price: Option::read(buf)?,
            source_id: Option::read(buf)?,
            publish_time_ms: u64::read(buf)?,
            status: OracleStatus::read(buf)?,
        })
    }
}

impl EncodeSize for OracleState {
    fn encode_size(&self) -> usize {
        self.external_observed_price.encode_size()
            + self.external_reference_price.encode_size()
            + self.oracle_price.encode_size()
            + self.source_id.encode_size()
            + self.publish_time_ms.encode_size()
            + self.status.encode_size()
    }
}

/// Book-derived inputs used to compare a trading mark against the oracle.
///
/// Mark price is typically a risk/accounting price. The oracle records these inputs only to track
/// divergence; it does not implement order matching or perps accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarkInputs {
    /// Bid-side impact price after consuming configured depth.
    pub impact_bid: Option<Price>,
    /// Ask-side impact price after consuming configured depth.
    pub impact_ask: Option<Price>,
    /// Highest visible bid.
    pub best_bid: Option<Price>,
    /// Lowest visible ask.
    pub best_ask: Option<Price>,
    /// Mark price to compare against the current oracle price.
    pub mark_price: Price,
    /// Time the mark inputs were measured, in Unix milliseconds.
    pub mark_time_ms: u64,
}

impl Write for MarkInputs {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.impact_bid.write(buf);
        self.impact_ask.write(buf);
        self.best_bid.write(buf);
        self.best_ask.write(buf);
        self.mark_price.write(buf);
        self.mark_time_ms.write(buf);
    }
}

impl Read for MarkInputs {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            impact_bid: Option::read(buf)?,
            impact_ask: Option::read(buf)?,
            best_bid: Option::read(buf)?,
            best_ask: Option::read(buf)?,
            mark_price: Price::read(buf)?,
            mark_time_ms: u64::read(buf)?,
        })
    }
}

impl EncodeSize for MarkInputs {
    fn encode_size(&self) -> usize {
        self.impact_bid.encode_size()
            + self.impact_ask.encode_size()
            + self.best_bid.encode_size()
            + self.best_ask.encode_size()
            + self.mark_price.encode_size()
            + self.mark_time_ms.encode_size()
    }
}

/// Severity bucket for mark/oracle divergence.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DivergenceLevel {
    /// Divergence is below the warning threshold.
    None = 0,
    /// Divergence is above warning threshold.
    Warn = 1,
    /// Divergence is above halt threshold.
    Halt = 2,
}

impl Write for DivergenceLevel {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        (*self as u8).write(buf);
    }
}

impl Read for DivergenceLevel {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::None),
            1 => Ok(Self::Warn),
            2 => Ok(Self::Halt),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for DivergenceLevel {
    fn encode_size(&self) -> usize {
        1
    }
}

/// Current absolute difference between mark price and oracle price.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DivergenceState {
    /// Absolute mark/oracle distance in basis points.
    pub bps: u32,
    /// Threshold bucket for the divergence distance.
    pub level: DivergenceLevel,
}

impl Write for DivergenceState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.bps.write(buf);
        self.level.write(buf);
    }
}

impl Read for DivergenceState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            bps: u32::read(buf)?,
            level: DivergenceLevel::read(buf)?,
        })
    }
}

impl EncodeSize for DivergenceState {
    fn encode_size(&self) -> usize {
        self.bps.encode_size() + self.level.encode_size()
    }
}
