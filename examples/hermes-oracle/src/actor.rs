use async_trait::async_trait;
use commonware_runtime::{Clock, Handle, Spawner};
use futures::{channel::mpsc, SinkExt};
use nunchi_crypto::PrivateKey;
use nunchi_mempool::{AdmissionError, MempoolHandle, PoolTransaction};
use nunchi_oracle::{
    FeedId, MarketId, OracleOperation, SourceId, Transaction as OracleTransaction,
};
use std::{error::Error as StdError, fmt, time::Duration};
use tracing::{debug, warn};

/// One external price observation ready for the oracle transaction format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeedObservation {
    /// Raw fixed-point price value before oracle normalization.
    pub raw_value: i128,
    /// Decimal precision of [`Self::raw_value`].
    pub raw_decimals: u8,
    /// Source publish time in Unix milliseconds.
    pub publish_time_ms: u64,
    /// Confidence band in the same precision as [`Self::raw_value`].
    pub confidence: u128,
}

/// Pull interface for real-time price feed adapters.
#[async_trait]
pub trait PriceFeed: Send + 'static {
    type Error: StdError + Send + Sync + 'static;

    async fn next(&mut self) -> Result<FeedObservation, Self::Error>;
}

/// Transaction sink used by the adapter actor.
#[async_trait]
pub trait OracleUpdateSink: Send + 'static {
    type Digest: Clone + Send + 'static;
    type Error: StdError + Send + Sync + 'static;

    async fn submit(&mut self, tx: OracleTransaction) -> Result<Self::Digest, Self::Error>;
}

#[async_trait]
impl<T> OracleUpdateSink for MempoolHandle<T>
where
    T: PoolTransaction + From<OracleTransaction> + Send + 'static,
    T::Digest: Clone + Send + 'static,
{
    type Digest = T::Digest;
    type Error = AdmissionError;

    async fn submit(&mut self, tx: OracleTransaction) -> Result<Self::Digest, Self::Error> {
        MempoolHandle::submit(self, tx.into()).await
    }
}

/// Configuration for the Hermes oracle update actor.
#[derive(Clone, Debug)]
pub struct ActorConfig {
    /// Oracle market being updated.
    pub market: MarketId,
    /// Oracle source lane configured for this Hermes feed.
    pub source: SourceId,
    /// Provider-specific feed identifier stored in oracle state.
    pub feed: FeedId,
    /// Authorized oracle updater key used to sign update transactions.
    pub updater: PrivateKey,
    /// First nonce to use for the updater account.
    pub initial_nonce: u64,
    /// Minimum delay after each accepted submission.
    pub min_submit_interval: Duration,
    /// Optional stop condition for deterministic benchmarks and tests.
    pub max_updates: Option<usize>,
}

impl ActorConfig {
    /// Create actor config with no submission delay and no update cap.
    pub fn new(
        market: MarketId,
        source: SourceId,
        feed: FeedId,
        updater: PrivateKey,
        initial_nonce: u64,
    ) -> Self {
        Self {
            market,
            source,
            feed,
            updater,
            initial_nonce,
            min_submit_interval: Duration::ZERO,
            max_updates: None,
        }
    }
}

/// Report emitted after the actor submits an oracle update transaction.
#[derive(Clone, Debug)]
pub struct SubmittedUpdate<D> {
    /// Nonce used for the signed oracle transaction.
    pub nonce: u64,
    /// Transaction digest returned by the sink.
    pub digest: D,
    /// Observation included in the submitted transaction.
    pub observation: FeedObservation,
    /// Local runtime time when the sink accepted the transaction.
    pub submitted_at_ms: u64,
}

/// Errors returned by the update actor.
#[derive(Debug)]
pub enum ActorError<F, S> {
    Feed(F),
    Sink(S),
    NonceOverflow,
}

impl<F, S> fmt::Display for ActorError<F, S>
where
    F: fmt::Display,
    S: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Feed(error) => write!(f, "price feed error: {error}"),
            Self::Sink(error) => write!(f, "oracle update sink error: {error}"),
            Self::NonceOverflow => write!(f, "oracle updater nonce overflow"),
        }
    }
}

impl<F, S> StdError for ActorError<F, S>
where
    F: StdError + 'static,
    S: StdError + 'static,
{
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Feed(error) => Some(error),
            Self::Sink(error) => Some(error),
            Self::NonceOverflow => None,
        }
    }
}

/// Actor that turns price feed observations into signed oracle update transactions.
pub struct Actor<F, S>
where
    F: PriceFeed,
    S: OracleUpdateSink,
{
    config: ActorConfig,
    feed: F,
    sink: S,
    reports: Option<mpsc::Sender<SubmittedUpdate<S::Digest>>>,
}

impl<F, S> Actor<F, S>
where
    F: PriceFeed,
    S: OracleUpdateSink,
{
    /// Create a Hermes oracle update actor.
    pub fn new(config: ActorConfig, feed: F, sink: S) -> Self {
        Self {
            config,
            feed,
            sink,
            reports: None,
        }
    }

    /// Emit a report for each accepted update submission.
    pub fn with_reports(mut self, reports: mpsc::Sender<SubmittedUpdate<S::Digest>>) -> Self {
        self.reports = Some(reports);
        self
    }

    /// Spawn the actor.
    pub fn start<E>(self, context: E) -> Handle<Result<(), ActorError<F::Error, S::Error>>>
    where
        E: Clock + Spawner,
    {
        context.spawn(|context| self.run(context))
    }

    /// Run the actor until its feed or sink errors, or until [`ActorConfig::max_updates`] is hit.
    pub async fn run<C>(mut self, context: C) -> Result<(), ActorError<F::Error, S::Error>>
    where
        C: Clock,
    {
        let mut nonce = self.config.initial_nonce;
        let mut submitted = 0usize;
        let mut last_publish_time_ms = None;

        loop {
            let observation = self.feed.next().await.map_err(ActorError::Feed)?;
            if last_publish_time_ms.is_some_and(|last| observation.publish_time_ms <= last) {
                debug!(
                    publish_time_ms = observation.publish_time_ms,
                    "skipping non-new oracle observation"
                );
                continue;
            }

            let operation = OracleOperation::SubmitFeedUpdate {
                market: self.config.market,
                source: self.config.source,
                feed: self.config.feed,
                raw_value: observation.raw_value,
                raw_decimals: observation.raw_decimals,
                publish_time_ms: observation.publish_time_ms,
                confidence: observation.confidence,
            };
            let tx = OracleTransaction::sign(&self.config.updater, nonce, operation);
            let digest = self.sink.submit(tx).await.map_err(ActorError::Sink)?;
            let submitted_at_ms = context
                .current()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .min(u128::from(u64::MAX)) as u64;

            if let Some(reports) = &mut self.reports {
                let report = SubmittedUpdate {
                    nonce,
                    digest: digest.clone(),
                    observation,
                    submitted_at_ms,
                };
                if reports.send(report).await.is_err() {
                    warn!("oracle update report receiver closed");
                    self.reports = None;
                }
            }

            last_publish_time_ms = Some(observation.publish_time_ms);
            nonce = nonce.checked_add(1).ok_or(ActorError::NonceOverflow)?;
            submitted = submitted.saturating_add(1);

            if self
                .config
                .max_updates
                .is_some_and(|max_updates| submitted >= max_updates)
            {
                return Ok(());
            }
            if !self.config.min_submit_interval.is_zero() {
                context.sleep(self.config.min_submit_interval).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Hasher, Sha256};
    use commonware_runtime::{deterministic, Runner};
    use futures::{channel::mpsc, StreamExt};
    use nunchi_oracle::Transaction as OracleTransaction;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    use thiserror::Error;

    #[derive(Debug, Error)]
    enum MockError {
        #[error("empty mock feed")]
        Empty,
    }

    struct MockFeed {
        observations: VecDeque<FeedObservation>,
    }

    #[async_trait]
    impl PriceFeed for MockFeed {
        type Error = MockError;

        async fn next(&mut self) -> Result<FeedObservation, Self::Error> {
            self.observations.pop_front().ok_or(MockError::Empty)
        }
    }

    #[derive(Clone, Default)]
    struct MockSink {
        submitted: Arc<Mutex<Vec<OracleTransaction>>>,
    }

    #[async_trait]
    impl OracleUpdateSink for MockSink {
        type Digest = commonware_cryptography::sha256::Digest;
        type Error = MockError;

        async fn submit(&mut self, tx: OracleTransaction) -> Result<Self::Digest, Self::Error> {
            let digest = tx.digest();
            self.submitted.lock().unwrap().push(tx);
            Ok(digest)
        }
    }

    fn config(max_updates: usize) -> ActorConfig {
        ActorConfig {
            market: MarketId(Sha256::hash(b"market")),
            source: SourceId(Sha256::hash(b"source")),
            feed: FeedId(Sha256::hash(b"feed")),
            updater: PrivateKey::ed25519_from_seed(7),
            initial_nonce: 3,
            min_submit_interval: Duration::ZERO,
            max_updates: Some(max_updates),
        }
    }

    fn observation(raw_value: i128, publish_time_ms: u64) -> FeedObservation {
        FeedObservation {
            raw_value,
            raw_decimals: 8,
            publish_time_ms,
            confidence: 10,
        }
    }

    #[test]
    fn actor_submits_signed_oracle_updates() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let feed = MockFeed {
                observations: VecDeque::from([observation(100, 1_000), observation(200, 2_000)]),
            };
            let sink = MockSink::default();
            let submitted = sink.submitted.clone();
            let (reports, mut report_rx) = mpsc::channel(4);
            let actor = Actor::new(config(2), feed, sink).with_reports(reports);

            actor.run(context).await.unwrap();

            let txs = submitted.lock().unwrap();
            assert_eq!(txs.len(), 2);
            assert_eq!(txs[0].payload.nonce, 3);
            assert_eq!(txs[1].payload.nonce, 4);
            assert!(txs[0].verify().is_ok());
            assert!(txs[1].verify().is_ok());

            assert!(matches!(
                &txs[0].payload.operation,
                OracleOperation::SubmitFeedUpdate {
                    raw_value: 100,
                    raw_decimals: 8,
                    publish_time_ms: 1_000,
                    confidence: 10,
                    ..
                }
            ));
            assert!(matches!(
                &txs[1].payload.operation,
                OracleOperation::SubmitFeedUpdate {
                    raw_value: 200,
                    raw_decimals: 8,
                    publish_time_ms: 2_000,
                    confidence: 10,
                    ..
                }
            ));
            drop(txs);

            let first = report_rx.next().await.unwrap();
            let second = report_rx.next().await.unwrap();
            assert_eq!(first.nonce, 3);
            assert_eq!(second.nonce, 4);
            assert_eq!(first.observation.raw_value, 100);
            assert_eq!(second.observation.raw_value, 200);
        });
    }

    #[test]
    fn actor_skips_non_new_observations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let feed = MockFeed {
                observations: VecDeque::from([
                    observation(100, 1_000),
                    observation(150, 1_000),
                    observation(200, 2_000),
                ]),
            };
            let sink = MockSink::default();
            let submitted = sink.submitted.clone();
            let actor = Actor::new(config(2), feed, sink);

            actor.run(context).await.unwrap();

            let txs = submitted.lock().unwrap();
            assert_eq!(txs.len(), 2);
            assert!(matches!(
                &txs[0].payload.operation,
                OracleOperation::SubmitFeedUpdate { raw_value: 100, .. }
            ));
            assert!(matches!(
                &txs[1].payload.operation,
                OracleOperation::SubmitFeedUpdate { raw_value: 200, .. }
            ));
        });
    }
}
