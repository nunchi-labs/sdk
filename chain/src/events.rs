use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::types::Height;
use commonware_cryptography::sha256;
use futures::future::BoxFuture;
use nunchi_common::{EventLimits, TransactionEvents};
use std::sync::Arc;
use thiserror::Error;

/// Full event output for a finalized block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedEvents {
    pub height: Height,
    pub block_digest: sha256::Digest,
    pub block_timestamp: u64,
    pub receipts_root: sha256::Digest,
    pub transactions: Vec<TransactionEvents>,
}

impl Write for FinalizedEvents {
    fn write(&self, buf: &mut impl BufMut) {
        self.height.write(buf);
        self.block_digest.write(buf);
        self.block_timestamp.write(buf);
        self.receipts_root.write(buf);
        self.transactions.write(buf);
    }
}

impl Read for FinalizedEvents {
    type Cfg = EventLimits;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::read(buf)?,
            block_digest: sha256::Digest::read(buf)?,
            block_timestamp: u64::read(buf)?,
            receipts_root: sha256::Digest::read(buf)?,
            transactions: Vec::<TransactionEvents>::read_cfg(
                buf,
                &(
                    RangeCfg::new(0..=limits.max_transactions_per_block),
                    *limits,
                ),
            )?,
        })
    }
}

impl EncodeSize for FinalizedEvents {
    fn encode_size(&self) -> usize {
        self.height.encode_size()
            + self.block_digest.encode_size()
            + self.block_timestamp.encode_size()
            + self.receipts_root.encode_size()
            + self.transactions.encode_size()
    }
}

/// Error returned by finalized event reporters.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct FinalizedEventReportError {
    message: String,
}

impl FinalizedEventReportError {
    /// Create a finalized event reporter error.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Receives finalized event batches after a block is durably finalized.
pub trait FinalizedEventReporter: Send + Sync + 'static {
    fn report(
        &self,
        events: FinalizedEvents,
    ) -> BoxFuture<'static, Result<(), FinalizedEventReportError>>;
}

/// Cloneable finalized event reporter handle used by the chain application.
#[derive(Clone)]
pub struct FinalizedEventReporterHandle {
    reporter: Arc<dyn FinalizedEventReporter>,
}

impl FinalizedEventReporterHandle {
    /// Create a handle around a finalized event reporter.
    pub fn new(reporter: impl FinalizedEventReporter) -> Self {
        Self {
            reporter: Arc::new(reporter),
        }
    }

    /// Report a finalized event batch.
    pub async fn report(&self, events: FinalizedEvents) -> Result<(), FinalizedEventReportError> {
        self.reporter.report(events).await
    }
}

impl Default for FinalizedEventReporterHandle {
    fn default() -> Self {
        Self::new(NoopFinalizedEventReporter)
    }
}

/// Finalized event reporter that drops every batch.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopFinalizedEventReporter;

impl FinalizedEventReporter for NoopFinalizedEventReporter {
    fn report(
        &self,
        _events: FinalizedEvents,
    ) -> BoxFuture<'static, Result<(), FinalizedEventReportError>> {
        Box::pin(async { Ok(()) })
    }
}
