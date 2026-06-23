//! Consensus-committed runtime events and receipt roots.
//!
//! Status: experimental
//!
//! Runtime modules emit [`Event`] values through an [`EventSink`]. Successful transaction
//! events are wrapped in transaction receipts and committed by an ordered, domain-separated
//! receipts root.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use thiserror::Error;

const EVENT_LEAF_DOMAIN: &[u8] = b"nunchi:event-leaf:v1";
const EVENT_NODE_DOMAIN: &[u8] = b"nunchi:event-node:v1";
const EVENT_ROOT_DOMAIN: &[u8] = b"nunchi:event-root:v1";
const RECEIPT_LEAF_DOMAIN: &[u8] = b"nunchi:receipt-leaf:v1";
const RECEIPT_NODE_DOMAIN: &[u8] = b"nunchi:receipt-node:v1";
const RECEIPT_ROOT_DOMAIN: &[u8] = b"nunchi:receipt-root:v1";

pub const DEFAULT_MAX_EVENTS_PER_TRANSACTION: usize = 1_024;
pub const DEFAULT_MAX_ATTRIBUTES_PER_EVENT: usize = 32;
pub const DEFAULT_MAX_TRANSACTIONS_PER_BLOCK: usize = 4_096;
pub const DEFAULT_MAX_EVENT_BYTES: usize = 16 * 1024;
pub const DEFAULT_MAX_TRANSACTION_EVENT_BYTES: usize = 256 * 1024;
pub const DEFAULT_MAX_BLOCK_EVENT_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_MODULE_BYTES: usize = 64;
pub const DEFAULT_MAX_KIND_BYTES: usize = 64;
pub const DEFAULT_MAX_KEY_BYTES: usize = 64;
pub const DEFAULT_MAX_VALUE_BYTES: usize = 16 * 1024;

/// A generic runtime event emitted by a deterministic module execution path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub module: Bytes,
    pub kind: Bytes,
    pub version: u16,
    pub attributes: Vec<EventAttribute>,
}

impl Event {
    /// Create a new event.
    pub fn new(
        module: impl Into<Bytes>,
        kind: impl Into<Bytes>,
        version: u16,
        attributes: Vec<EventAttribute>,
    ) -> Self {
        Self {
            module: module.into(),
            kind: kind.into(),
            version,
            attributes,
        }
    }

    /// Validate this event against deterministic event limits.
    pub fn validate(&self, limits: &EventLimits) -> Result<(), EventError> {
        if self.module.len() > limits.max_module_bytes {
            return Err(EventError::ModuleTooLarge {
                max: limits.max_module_bytes,
                actual: self.module.len(),
            });
        }
        if self.kind.len() > limits.max_kind_bytes {
            return Err(EventError::KindTooLarge {
                max: limits.max_kind_bytes,
                actual: self.kind.len(),
            });
        }
        if self.attributes.len() > limits.max_attributes_per_event {
            return Err(EventError::TooManyAttributes {
                max: limits.max_attributes_per_event,
                actual: self.attributes.len(),
            });
        }
        for attribute in &self.attributes {
            attribute.validate(limits)?;
        }

        let actual = self.encode_size();
        if actual > limits.max_event_bytes {
            return Err(EventError::EventTooLarge {
                max: limits.max_event_bytes,
                actual,
            });
        }

        Ok(())
    }
}

impl Write for Event {
    fn write(&self, buf: &mut impl BufMut) {
        self.module.write(buf);
        self.kind.write(buf);
        self.version.write(buf);
        self.attributes.write(buf);
    }
}

impl Read for Event {
    type Cfg = EventLimits;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        let module = Bytes::read_cfg(buf, &RangeCfg::new(0..=limits.max_module_bytes))?;
        let kind = Bytes::read_cfg(buf, &RangeCfg::new(0..=limits.max_kind_bytes))?;
        let version = u16::read(buf)?;
        let attributes = Vec::<EventAttribute>::read_cfg(
            buf,
            &(RangeCfg::new(0..=limits.max_attributes_per_event), *limits),
        )?;
        let event = Self {
            module,
            kind,
            version,
            attributes,
        };
        event
            .validate(limits)
            .map_err(|_| CodecError::Invalid("event", "event limits exceeded"))?;
        Ok(event)
    }
}

impl EncodeSize for Event {
    fn encode_size(&self) -> usize {
        self.module.encode_size()
            + self.kind.encode_size()
            + self.version.encode_size()
            + self.attributes.encode_size()
    }
}

/// A key-value attribute attached to an [`Event`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventAttribute {
    pub key: Bytes,
    pub value: Bytes,
}

impl EventAttribute {
    /// Create a new event attribute.
    pub fn new(key: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    /// Validate this attribute against deterministic event limits.
    pub fn validate(&self, limits: &EventLimits) -> Result<(), EventError> {
        if self.key.len() > limits.max_key_bytes {
            return Err(EventError::KeyTooLarge {
                max: limits.max_key_bytes,
                actual: self.key.len(),
            });
        }
        if self.value.len() > limits.max_value_bytes {
            return Err(EventError::ValueTooLarge {
                max: limits.max_value_bytes,
                actual: self.value.len(),
            });
        }
        Ok(())
    }
}

impl Write for EventAttribute {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.write(buf);
        self.value.write(buf);
    }
}

impl Read for EventAttribute {
    type Cfg = EventLimits;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            key: Bytes::read_cfg(buf, &RangeCfg::new(0..=limits.max_key_bytes))?,
            value: Bytes::read_cfg(buf, &RangeCfg::new(0..=limits.max_value_bytes))?,
        })
    }
}

impl EncodeSize for EventAttribute {
    fn encode_size(&self) -> usize {
        self.key.encode_size() + self.value.encode_size()
    }
}

/// An event with the transaction and event positions used when constructing an events root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventEnvelope {
    pub tx_index: u32,
    pub tx_digest: Digest,
    pub event_index: u32,
    pub event: Event,
}

impl Write for EventEnvelope {
    fn write(&self, buf: &mut impl BufMut) {
        self.tx_index.write(buf);
        self.tx_digest.write(buf);
        self.event_index.write(buf);
        self.event.write(buf);
    }
}

impl Read for EventEnvelope {
    type Cfg = EventLimits;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            tx_index: u32::read(buf)?,
            tx_digest: Digest::read(buf)?,
            event_index: u32::read(buf)?,
            event: Event::read_cfg(buf, limits)?,
        })
    }
}

impl EncodeSize for EventEnvelope {
    fn encode_size(&self) -> usize {
        self.tx_index.encode_size()
            + self.tx_digest.encode_size()
            + self.event_index.encode_size()
            + self.event.encode_size()
    }
}

/// Receipt for a successful transaction's event output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReceipt {
    pub tx_index: u32,
    pub tx_digest: Digest,
    pub events_root: Digest,
    pub event_count: u32,
}

impl Write for TransactionReceipt {
    fn write(&self, buf: &mut impl BufMut) {
        self.tx_index.write(buf);
        self.tx_digest.write(buf);
        self.events_root.write(buf);
        self.event_count.write(buf);
    }
}

impl Read for TransactionReceipt {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            tx_index: u32::read(buf)?,
            tx_digest: Digest::read(buf)?,
            events_root: Digest::read(buf)?,
            event_count: u32::read(buf)?,
        })
    }
}

impl EncodeSize for TransactionReceipt {
    fn encode_size(&self) -> usize {
        self.tx_index.encode_size()
            + self.tx_digest.encode_size()
            + self.events_root.encode_size()
            + self.event_count.encode_size()
    }
}

/// Full event output for one successful transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionEvents {
    pub receipt: TransactionReceipt,
    pub events: Vec<Event>,
}

impl TransactionEvents {
    /// Build transaction events and the matching receipt.
    pub fn new(tx_index: u32, tx_digest: Digest, events: Vec<Event>) -> Result<Self, EventError> {
        let receipt = transaction_receipt(tx_index, tx_digest, &events)?;
        Ok(Self { receipt, events })
    }

    /// Build transaction events after validating event limits.
    pub fn with_limits(
        tx_index: u32,
        tx_digest: Digest,
        events: Vec<Event>,
        limits: EventLimits,
    ) -> Result<Self, EventError> {
        validate_transaction_events(&events, &limits)?;
        Self::new(tx_index, tx_digest, events)
    }

    /// Validate this transaction output and its receipt.
    pub fn validate(&self, limits: &EventLimits) -> Result<(), EventError> {
        validate_transaction_events(&self.events, limits)?;
        let expected =
            transaction_receipt(self.receipt.tx_index, self.receipt.tx_digest, &self.events)?;
        if self.receipt != expected {
            return Err(EventError::ReceiptMismatch);
        }
        Ok(())
    }
}

impl Write for TransactionEvents {
    fn write(&self, buf: &mut impl BufMut) {
        self.receipt.write(buf);
        self.events.write(buf);
    }
}

impl Read for TransactionEvents {
    type Cfg = EventLimits;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        let receipt = TransactionReceipt::read(buf)?;
        let events = Vec::<Event>::read_cfg(
            buf,
            &(
                RangeCfg::new(0..=limits.max_events_per_transaction),
                *limits,
            ),
        )?;
        let output = Self { receipt, events };
        output
            .validate(limits)
            .map_err(|_| CodecError::Invalid("transaction events", "invalid event output"))?;
        Ok(output)
    }
}

impl EncodeSize for TransactionEvents {
    fn encode_size(&self) -> usize {
        self.receipt.encode_size() + self.events.encode_size()
    }
}

/// Event output for a fully executed block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockExecutionOutput {
    pub receipts_root: Digest,
    pub transactions: Vec<TransactionEvents>,
}

impl BlockExecutionOutput {
    /// Build block execution output and compute the matching receipts root.
    pub fn new(transactions: Vec<TransactionEvents>) -> Self {
        let receipts = transactions
            .iter()
            .map(|transaction| transaction.receipt)
            .collect::<Vec<_>>();
        Self {
            receipts_root: receipts_root(&receipts),
            transactions,
        }
    }

    /// Build block execution output after validating event limits.
    pub fn with_limits(
        transactions: Vec<TransactionEvents>,
        limits: EventLimits,
    ) -> Result<Self, EventError> {
        let output = Self::new(transactions);
        output.validate(&limits)?;
        Ok(output)
    }

    /// Validate this block output and its receipts root.
    pub fn validate(&self, limits: &EventLimits) -> Result<(), EventError> {
        if self.transactions.len() > limits.max_transactions_per_block {
            return Err(EventError::TooManyTransactions {
                max: limits.max_transactions_per_block,
                actual: self.transactions.len(),
            });
        }
        for transaction in &self.transactions {
            transaction.validate(limits)?;
        }
        let receipts = self
            .transactions
            .iter()
            .map(|transaction| transaction.receipt)
            .collect::<Vec<_>>();
        if self.receipts_root != receipts_root(&receipts) {
            return Err(EventError::ReceiptsRootMismatch);
        }

        let actual = self.encode_size();
        if actual > limits.max_block_event_bytes {
            return Err(EventError::BlockEventsTooLarge {
                max: limits.max_block_event_bytes,
                actual,
            });
        }

        Ok(())
    }
}

impl Write for BlockExecutionOutput {
    fn write(&self, buf: &mut impl BufMut) {
        self.receipts_root.write(buf);
        self.transactions.write(buf);
    }
}

impl Read for BlockExecutionOutput {
    type Cfg = EventLimits;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        let receipts_root = Digest::read(buf)?;
        let transactions = Vec::<TransactionEvents>::read_cfg(
            buf,
            &(
                RangeCfg::new(0..=limits.max_transactions_per_block),
                *limits,
            ),
        )?;
        let output = Self {
            receipts_root,
            transactions,
        };
        output
            .validate(limits)
            .map_err(|_| CodecError::Invalid("block execution output", "invalid event output"))?;
        Ok(output)
    }
}

impl EncodeSize for BlockExecutionOutput {
    fn encode_size(&self) -> usize {
        self.receipts_root.encode_size() + self.transactions.encode_size()
    }
}

/// Deterministic limits enforced while collecting event output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventLimits {
    pub max_events_per_transaction: usize,
    pub max_attributes_per_event: usize,
    pub max_transactions_per_block: usize,
    pub max_event_bytes: usize,
    pub max_transaction_event_bytes: usize,
    pub max_block_event_bytes: usize,
    pub max_module_bytes: usize,
    pub max_kind_bytes: usize,
    pub max_key_bytes: usize,
    pub max_value_bytes: usize,
}

impl Default for EventLimits {
    fn default() -> Self {
        Self {
            max_events_per_transaction: DEFAULT_MAX_EVENTS_PER_TRANSACTION,
            max_attributes_per_event: DEFAULT_MAX_ATTRIBUTES_PER_EVENT,
            max_transactions_per_block: DEFAULT_MAX_TRANSACTIONS_PER_BLOCK,
            max_event_bytes: DEFAULT_MAX_EVENT_BYTES,
            max_transaction_event_bytes: DEFAULT_MAX_TRANSACTION_EVENT_BYTES,
            max_block_event_bytes: DEFAULT_MAX_BLOCK_EVENT_BYTES,
            max_module_bytes: DEFAULT_MAX_MODULE_BYTES,
            max_kind_bytes: DEFAULT_MAX_KIND_BYTES,
            max_key_bytes: DEFAULT_MAX_KEY_BYTES,
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
        }
    }
}

/// Errors produced when event output is invalid or exceeds deterministic limits.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EventError {
    #[error("transaction has {actual} events, but the maximum is {max}")]
    TooManyEvents { max: usize, actual: usize },
    #[error("event has {actual} attributes, but the maximum is {max}")]
    TooManyAttributes { max: usize, actual: usize },
    #[error("block has {actual} transaction event outputs, but the maximum is {max}")]
    TooManyTransactions { max: usize, actual: usize },
    #[error("event is {actual} bytes, but the maximum is {max}")]
    EventTooLarge { max: usize, actual: usize },
    #[error("transaction event output is {actual} bytes, but the maximum is {max}")]
    TransactionEventsTooLarge { max: usize, actual: usize },
    #[error("block event output is {actual} bytes, but the maximum is {max}")]
    BlockEventsTooLarge { max: usize, actual: usize },
    #[error("module is {actual} bytes, but the maximum is {max}")]
    ModuleTooLarge { max: usize, actual: usize },
    #[error("event kind is {actual} bytes, but the maximum is {max}")]
    KindTooLarge { max: usize, actual: usize },
    #[error("attribute key is {actual} bytes, but the maximum is {max}")]
    KeyTooLarge { max: usize, actual: usize },
    #[error("attribute value is {actual} bytes, but the maximum is {max}")]
    ValueTooLarge { max: usize, actual: usize },
    #[error("transaction receipt does not match events")]
    ReceiptMismatch,
    #[error("block receipts root does not match transaction receipts")]
    ReceiptsRootMismatch,
}

/// Event sink passed through deterministic transaction execution.
pub trait EventSink {
    fn emit(&mut self, event: Event) -> Result<(), EventError>;
}

impl<T: EventSink + ?Sized> EventSink for &mut T {
    fn emit(&mut self, event: Event) -> Result<(), EventError> {
        (**self).emit(event)
    }
}

/// Event sink that drops events.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn emit(&mut self, _event: Event) -> Result<(), EventError> {
        Ok(())
    }
}

/// Per-transaction event collector with deterministic limit enforcement.
#[derive(Clone, Debug)]
pub struct EventBuffer {
    limits: EventLimits,
    events: Vec<Event>,
    events_encoded_bytes: usize,
}

impl EventBuffer {
    /// Create an empty event buffer.
    pub fn new(limits: EventLimits) -> Self {
        Self {
            limits,
            events: Vec::new(),
            events_encoded_bytes: 0,
        }
    }

    /// Return the limits enforced by this buffer.
    pub fn limits(&self) -> EventLimits {
        self.limits
    }

    /// Return the buffered events in emission order.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Return the number of buffered events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Return whether the buffer has no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Clear all buffered events.
    pub fn clear(&mut self) {
        self.events.clear();
        self.events_encoded_bytes = 0;
    }

    /// Return the encoded size of the buffered event list.
    pub fn transaction_event_bytes(&self) -> usize {
        self.events.len().encode_size() + self.events_encoded_bytes
    }

    /// Build the receipt for the buffered events.
    pub fn receipt(
        &self,
        tx_index: u32,
        tx_digest: Digest,
    ) -> Result<TransactionReceipt, EventError> {
        transaction_receipt(tx_index, tx_digest, &self.events)
    }

    /// Consume the buffer into transaction events and a matching receipt.
    pub fn finish(self, tx_index: u32, tx_digest: Digest) -> Result<TransactionEvents, EventError> {
        TransactionEvents::new(tx_index, tx_digest, self.events)
    }

    /// Consume the buffer into its raw events.
    pub fn into_events(self) -> Vec<Event> {
        self.events
    }
}

impl Default for EventBuffer {
    fn default() -> Self {
        Self::new(EventLimits::default())
    }
}

impl EventSink for EventBuffer {
    fn emit(&mut self, event: Event) -> Result<(), EventError> {
        event.validate(&self.limits)?;

        let next_count = self.events.len() + 1;
        if next_count > self.limits.max_events_per_transaction {
            return Err(EventError::TooManyEvents {
                max: self.limits.max_events_per_transaction,
                actual: next_count,
            });
        }

        let event_size = event.encode_size();
        let next_bytes = next_count.encode_size() + self.events_encoded_bytes + event_size;
        if next_bytes > self.limits.max_transaction_event_bytes {
            return Err(EventError::TransactionEventsTooLarge {
                max: self.limits.max_transaction_event_bytes,
                actual: next_bytes,
            });
        }

        self.events.push(event);
        self.events_encoded_bytes += event_size;
        Ok(())
    }
}

/// Return the fixed empty events root.
pub fn empty_events_root() -> Digest {
    finalize_ordered_root(EVENT_ROOT_DOMAIN, 0, None)
}

/// Return the fixed empty receipts root.
pub fn empty_receipts_root() -> Digest {
    finalize_ordered_root(RECEIPT_ROOT_DOMAIN, 0, None)
}

/// Compute the ordered events root for a successful transaction.
pub fn events_root(
    tx_index: u32,
    tx_digest: Digest,
    events: &[Event],
) -> Result<Digest, EventError> {
    if events.is_empty() {
        return Ok(empty_events_root());
    }

    let mut leaves = Vec::with_capacity(events.len());
    for (event_index, event) in events.iter().enumerate() {
        let event_index = u32::try_from(event_index).map_err(|_| EventError::TooManyEvents {
            max: u32::MAX as usize,
            actual: events.len(),
        })?;
        leaves.push(hash_event_leaf(tx_index, tx_digest, event_index, event));
    }
    Ok(ordered_root(leaves, EVENT_NODE_DOMAIN, EVENT_ROOT_DOMAIN))
}

/// Build a transaction receipt for a successful transaction's events.
pub fn transaction_receipt(
    tx_index: u32,
    tx_digest: Digest,
    events: &[Event],
) -> Result<TransactionReceipt, EventError> {
    let event_count = u32::try_from(events.len()).map_err(|_| EventError::TooManyEvents {
        max: u32::MAX as usize,
        actual: events.len(),
    })?;
    Ok(TransactionReceipt {
        tx_index,
        tx_digest,
        events_root: events_root(tx_index, tx_digest, events)?,
        event_count,
    })
}

/// Compute the ordered receipts root for a block.
pub fn receipts_root(receipts: &[TransactionReceipt]) -> Digest {
    if receipts.is_empty() {
        return empty_receipts_root();
    }

    let leaves = receipts
        .iter()
        .map(|receipt| hash_encoded_leaf(RECEIPT_LEAF_DOMAIN, receipt))
        .collect::<Vec<_>>();
    ordered_root(leaves, RECEIPT_NODE_DOMAIN, RECEIPT_ROOT_DOMAIN)
}

fn validate_transaction_events(events: &[Event], limits: &EventLimits) -> Result<(), EventError> {
    if events.len() > limits.max_events_per_transaction {
        return Err(EventError::TooManyEvents {
            max: limits.max_events_per_transaction,
            actual: events.len(),
        });
    }
    for event in events {
        event.validate(limits)?;
    }

    let actual = encoded_event_list_size(events);
    if actual > limits.max_transaction_event_bytes {
        return Err(EventError::TransactionEventsTooLarge {
            max: limits.max_transaction_event_bytes,
            actual,
        });
    }

    Ok(())
}

fn encoded_event_list_size(events: &[Event]) -> usize {
    events.len().encode_size() + events.iter().map(EncodeSize::encode_size).sum::<usize>()
}

fn hash_event_leaf(tx_index: u32, tx_digest: Digest, event_index: u32, event: &Event) -> Digest {
    let mut encoded = BytesMut::with_capacity(
        tx_index.encode_size()
            + tx_digest.encode_size()
            + event_index.encode_size()
            + event.encode_size(),
    );
    tx_index.write(&mut encoded);
    tx_digest.write(&mut encoded);
    event_index.write(&mut encoded);
    event.write(&mut encoded);

    let mut hasher = Sha256::new();
    hasher.update(EVENT_LEAF_DOMAIN);
    hasher.update(&encoded);
    hasher.finalize()
}

fn hash_encoded_leaf<T: EncodeSize + Write>(domain: &[u8], item: &T) -> Digest {
    let mut encoded = BytesMut::with_capacity(item.encode_size());
    item.write(&mut encoded);

    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(&encoded);
    hasher.finalize()
}

fn ordered_root(mut nodes: Vec<Digest>, node_domain: &[u8], root_domain: &[u8]) -> Digest {
    let count = nodes.len();
    while nodes.len() > 1 {
        let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut pairs = nodes.chunks_exact(2);
        for pair in pairs.by_ref() {
            next.push(hash_node(node_domain, pair[0], pair[1]));
        }
        if let Some(single) = pairs.remainder().first() {
            next.push(*single);
        }
        nodes = next;
    }

    finalize_ordered_root(root_domain, count, nodes.first().copied())
}

fn hash_node(domain: &[u8], left: Digest, right: Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(&left);
    hasher.update(&right);
    hasher.finalize()
}

fn finalize_ordered_root(domain: &[u8], count: usize, root: Option<Digest>) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(&(count as u64).to_be_bytes());
    if let Some(root) = root {
        hasher.update(&root);
    }
    hasher.finalize()
}
