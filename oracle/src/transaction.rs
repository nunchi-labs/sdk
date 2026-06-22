use crate::{
    FeedId, MarkInputs, MarketId, OracleConfig, SourceId, UpdaterPolicy, ORACLE_NAMESPACE,
};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::{Address, Operation as CommonOperation};

const OP_CONFIGURE_MARKET: u8 = 0;
const OP_SET_UPDATER: u8 = 1;
const OP_SUBMIT_FEED_UPDATE: u8 = 2;
const OP_SUBMIT_MARK_INPUTS: u8 = 3;

/// Oracle state-machine operation carried by a signed Nunchi transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleOperation {
    /// Create or update temporary v1 oracle config for a market.
    ///
    /// The signer must be the configured admin for a new market, or the current admin for an
    /// existing market. Long-term, market registry should own most of this policy.
    ConfigureMarket {
        /// Market whose oracle policy is being configured.
        market: MarketId,
        /// Oracle policy to store for the market.
        config: OracleConfig,
    },
    /// Enable or disable a feed updater for one market/source pair.
    ///
    /// The signer must be the market admin.
    SetUpdater {
        /// Market whose updater policy is changing.
        market: MarketId,
        /// Source lane the updater may submit on.
        source: SourceId,
        /// Account being enabled or disabled.
        updater: Address,
        /// New updater policy.
        policy: UpdaterPolicy,
    },
    /// Submit an external observation for a market/source.
    ///
    /// This is the core adapter interface into `nunchi-oracle`: external source-specific code
    /// fetches data, signs this operation with an authorized updater key, and submits it as a
    /// normal runtime transaction.
    SubmitFeedUpdate {
        /// Market being updated.
        market: MarketId,
        /// Configured source that produced the observation.
        source: SourceId,
        /// Provider-specific feed identifier.
        feed: FeedId,
        /// Raw integer price before normalization.
        raw_value: i128,
        /// Decimal precision of `raw_value`.
        raw_decimals: u8,
        /// External source publish time in Unix milliseconds.
        publish_time_ms: u64,
        /// Confidence band around the submitted price.
        confidence: u128,
    },
    /// Submit book-derived mark inputs for divergence tracking.
    ///
    /// This is admin-only in v1. Later CLOB/perps integration should decide whether these inputs
    /// come from a module hook, ordinary transactions, or a consensus extension.
    SubmitMarkInputs {
        /// Market whose mark inputs are being updated.
        market: MarketId,
        /// Mark/book data used to compute divergence from oracle price.
        inputs: MarkInputs,
    },
}

impl Write for OracleOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::ConfigureMarket { market, config } => {
                OP_CONFIGURE_MARKET.write(buf);
                market.write(buf);
                config.write(buf);
            }
            Self::SetUpdater {
                market,
                source,
                updater,
                policy,
            } => {
                OP_SET_UPDATER.write(buf);
                market.write(buf);
                source.write(buf);
                updater.write(buf);
                policy.write(buf);
            }
            Self::SubmitFeedUpdate {
                market,
                source,
                feed,
                raw_value,
                raw_decimals,
                publish_time_ms,
                confidence,
            } => {
                OP_SUBMIT_FEED_UPDATE.write(buf);
                market.write(buf);
                source.write(buf);
                feed.write(buf);
                raw_value.write(buf);
                raw_decimals.write(buf);
                publish_time_ms.write(buf);
                confidence.write(buf);
            }
            Self::SubmitMarkInputs { market, inputs } => {
                OP_SUBMIT_MARK_INPUTS.write(buf);
                market.write(buf);
                inputs.write(buf);
            }
        }
    }
}

impl Read for OracleOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            OP_CONFIGURE_MARKET => Ok(Self::ConfigureMarket {
                market: MarketId::read(buf)?,
                config: OracleConfig::read(buf)?,
            }),
            OP_SET_UPDATER => Ok(Self::SetUpdater {
                market: MarketId::read(buf)?,
                source: SourceId::read(buf)?,
                updater: Address::read(buf)?,
                policy: UpdaterPolicy::read(buf)?,
            }),
            OP_SUBMIT_FEED_UPDATE => Ok(Self::SubmitFeedUpdate {
                market: MarketId::read(buf)?,
                source: SourceId::read(buf)?,
                feed: FeedId::read(buf)?,
                raw_value: i128::read(buf)?,
                raw_decimals: u8::read(buf)?,
                publish_time_ms: u64::read(buf)?,
                confidence: u128::read(buf)?,
            }),
            OP_SUBMIT_MARK_INPUTS => Ok(Self::SubmitMarkInputs {
                market: MarketId::read(buf)?,
                inputs: MarkInputs::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for OracleOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::ConfigureMarket { market, config } => market.encode_size() + config.encode_size(),
            Self::SetUpdater {
                market,
                source,
                updater,
                policy,
            } => {
                market.encode_size()
                    + source.encode_size()
                    + updater.encode_size()
                    + policy.encode_size()
            }
            Self::SubmitFeedUpdate {
                market,
                source,
                feed,
                raw_value,
                raw_decimals,
                publish_time_ms,
                confidence,
            } => {
                market.encode_size()
                    + source.encode_size()
                    + feed.encode_size()
                    + raw_value.encode_size()
                    + raw_decimals.encode_size()
                    + publish_time_ms.encode_size()
                    + confidence.encode_size()
            }
            Self::SubmitMarkInputs { market, inputs } => {
                market.encode_size() + inputs.encode_size()
            }
        }
    }
}

impl CommonOperation for OracleOperation {
    const NAMESPACE: &'static [u8] = ORACLE_NAMESPACE;
}

/// Signed oracle transaction payload.
pub type TransactionPayload = nunchi_common::TransactionPayload<OracleOperation>;
/// Signed oracle transaction.
pub type Transaction = nunchi_common::Transaction<OracleOperation>;
