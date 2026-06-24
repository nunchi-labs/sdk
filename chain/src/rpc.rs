//! JSON-RPC surface for finalized event archives.

use bytes::Bytes;
use commonware_consensus::types::Height;
use commonware_cryptography::sha256::Digest;
use commonware_formatting::hex;
use jsonrpsee::{
    core::{async_trait, RegisterMethodError, RpcResult},
    proc_macros::rpc,
    types::ErrorObjectOwned,
};
use nunchi_common::{
    Event, EventAttribute, TransactionEvents as CommonTransactionEvents, TransactionReceipt,
};
use nunchi_rpc::{decode_hex, encode_hex, invalid_params, module_error, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::archive::{
    ArchivedEvent, ArchivedTransactionEvents, EventArchiveError, EventArchiveQuery, EventKey,
    DEFAULT_EVENT_QUERY_LIMIT, DEFAULT_EVENT_STREAM_LIMIT, MAX_EVENT_QUERY_LIMIT,
    MAX_EVENT_STREAM_LIMIT,
};
use crate::FinalizedEvents;

/// Concrete event RPC server over an archive backend.
#[derive(Clone)]
pub struct EventsRpc<Q> {
    query: Q,
}

impl<Q> EventsRpc<Q> {
    pub fn new(query: Q) -> Self {
        Self { query }
    }
}

#[rpc(server, namespace = "events", namespace_separator = ".")]
pub trait Events {
    #[method(name = "batch_by_height", param_kind = map)]
    async fn batch_by_height(&self, height: u64) -> RpcResult<Option<FinalizedEventsResponse>>;

    #[method(name = "batch_by_block", param_kind = map)]
    async fn batch_by_block(
        &self,
        block_digest: String,
    ) -> RpcResult<Option<FinalizedEventsResponse>>;

    #[method(name = "transaction", param_kind = map)]
    async fn transaction(&self, transaction_digest: String) -> RpcResult<TransactionQueryResponse>;

    #[method(name = "query", param_kind = map)]
    async fn query(
        &self,
        module: String,
        kind: String,
        version: u16,
        key: String,
        from_height: Option<u64>,
        limit: Option<usize>,
    ) -> RpcResult<EventQueryResponse>;

    #[method(name = "stream", param_kind = map)]
    async fn stream(
        &self,
        from_height: u64,
        limit: Option<usize>,
    ) -> RpcResult<EventStreamResponse>;
}

#[async_trait]
impl<Q> EventsServer for EventsRpc<Q>
where
    Q: EventArchiveQuery,
{
    async fn batch_by_height(&self, height: u64) -> RpcResult<Option<FinalizedEventsResponse>> {
        self.query
            .batch_by_height(Height::new(height))
            .map(|batch| batch.map(FinalizedEventsResponse::from))
            .map_err(rpc_error)
    }

    async fn batch_by_block(
        &self,
        block_digest: String,
    ) -> RpcResult<Option<FinalizedEventsResponse>> {
        let block_digest = decode_digest(&block_digest, "block digest")?;
        self.query
            .batch_by_block_digest(block_digest)
            .map(|batch| batch.map(FinalizedEventsResponse::from))
            .map_err(rpc_error)
    }

    async fn transaction(&self, transaction_digest: String) -> RpcResult<TransactionQueryResponse> {
        let transaction_digest = decode_digest(&transaction_digest, "transaction digest")?;
        let transactions = self
            .query
            .transactions_by_digest(transaction_digest)
            .map_err(rpc_error)?
            .into_iter()
            .map(ArchivedTransactionEventsResponse::from)
            .collect();
        Ok(TransactionQueryResponse { transactions })
    }

    async fn query(
        &self,
        module: String,
        kind: String,
        version: u16,
        key: String,
        from_height: Option<u64>,
        limit: Option<usize>,
    ) -> RpcResult<EventQueryResponse> {
        let limit = bounded_limit(limit, DEFAULT_EVENT_QUERY_LIMIT, MAX_EVENT_QUERY_LIMIT)?;
        let key = EventKey::new(
            module.into_bytes(),
            kind.into_bytes(),
            version,
            key.into_bytes(),
        );
        let events = self
            .query
            .events_by_key(&key, from_height.map(Height::new), limit)
            .map_err(rpc_error)?
            .into_iter()
            .map(ArchivedEventResponse::from)
            .collect();
        Ok(EventQueryResponse { events })
    }

    async fn stream(
        &self,
        from_height: u64,
        limit: Option<usize>,
    ) -> RpcResult<EventStreamResponse> {
        let limit = bounded_limit(limit, DEFAULT_EVENT_STREAM_LIMIT, MAX_EVENT_STREAM_LIMIT)?;
        let from_height = Height::new(from_height);
        let batches = self
            .query
            .stream_from(from_height, limit)
            .map_err(rpc_error)?;
        let next_height = batches
            .last()
            .and_then(|batch| batch.height.get().checked_add(1));
        Ok(EventStreamResponse {
            from_height: from_height.get(),
            next_height,
            batches: batches
                .into_iter()
                .map(FinalizedEventsResponse::from)
                .collect(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FinalizedEventsResponse {
    pub height: u64,
    pub block_digest: String,
    pub block_timestamp: u64,
    pub receipts_root: String,
    pub transactions: Vec<TransactionEventsResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionEventsResponse {
    pub receipt: TransactionReceiptResponse,
    pub events: Vec<EventResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArchivedTransactionEventsResponse {
    pub height: u64,
    pub block_digest: String,
    pub block_timestamp: u64,
    pub receipts_root: String,
    pub receipt: TransactionReceiptResponse,
    pub events: Vec<EventResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionReceiptResponse {
    pub tx_index: u32,
    pub tx_digest: String,
    pub events_root: String,
    pub event_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArchivedEventResponse {
    pub height: u64,
    pub block_digest: String,
    pub block_timestamp: u64,
    pub receipts_root: String,
    pub tx_index: u32,
    pub tx_digest: String,
    pub event_index: u32,
    pub event: EventResponse,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventResponse {
    pub module: String,
    pub kind: String,
    pub version: u16,
    pub attributes: Vec<EventAttributeResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventAttributeResponse {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionQueryResponse {
    pub transactions: Vec<ArchivedTransactionEventsResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventQueryResponse {
    pub events: Vec<ArchivedEventResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventStreamResponse {
    pub from_height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_height: Option<u64>,
    pub batches: Vec<FinalizedEventsResponse>,
}

/// Register finalized event archive RPC methods into a downstream router.
pub fn register<Context, Q>(
    router: &mut RpcRouter<Context>,
    rpc: EventsRpc<Q>,
) -> Result<(), RegisterMethodError>
where
    Q: EventArchiveQuery,
{
    router.merge(rpc.into_rpc())
}

fn bounded_limit(
    limit: Option<usize>,
    default: usize,
    max: usize,
) -> Result<usize, ErrorObjectOwned> {
    let limit = limit.unwrap_or(default);
    if limit > max {
        return Err(invalid_params(format!("limit exceeds maximum {max}")));
    }
    Ok(limit)
}

fn decode_digest(value: &str, name: &'static str) -> RpcResult<Digest> {
    decode_hex(value, name)
}

fn rpc_error(error: EventArchiveError) -> ErrorObjectOwned {
    module_error(error.to_string())
}

fn bytes_text(bytes: &Bytes) -> String {
    std::str::from_utf8(bytes.as_ref())
        .map(str::to_owned)
        .unwrap_or_else(|_| format!("0x{}", hex(bytes.as_ref())))
}

fn bytes_hex(bytes: &Bytes) -> String {
    hex(bytes.as_ref())
}

impl From<FinalizedEvents> for FinalizedEventsResponse {
    fn from(batch: FinalizedEvents) -> Self {
        Self {
            height: batch.height.get(),
            block_digest: encode_hex(&batch.block_digest),
            block_timestamp: batch.block_timestamp,
            receipts_root: encode_hex(&batch.receipts_root),
            transactions: batch
                .transactions
                .into_iter()
                .map(TransactionEventsResponse::from)
                .collect(),
        }
    }
}

impl From<CommonTransactionEvents> for TransactionEventsResponse {
    fn from(events: CommonTransactionEvents) -> Self {
        Self {
            receipt: TransactionReceiptResponse::from(events.receipt),
            events: events.events.into_iter().map(EventResponse::from).collect(),
        }
    }
}

impl From<ArchivedTransactionEvents> for ArchivedTransactionEventsResponse {
    fn from(events: ArchivedTransactionEvents) -> Self {
        Self {
            height: events.height.get(),
            block_digest: encode_hex(&events.block_digest),
            block_timestamp: events.block_timestamp,
            receipts_root: encode_hex(&events.receipts_root),
            receipt: TransactionReceiptResponse::from(events.receipt),
            events: events.events.into_iter().map(EventResponse::from).collect(),
        }
    }
}

impl From<TransactionReceipt> for TransactionReceiptResponse {
    fn from(receipt: TransactionReceipt) -> Self {
        Self {
            tx_index: receipt.tx_index,
            tx_digest: encode_hex(&receipt.tx_digest),
            events_root: encode_hex(&receipt.events_root),
            event_count: receipt.event_count,
        }
    }
}

impl From<ArchivedEvent> for ArchivedEventResponse {
    fn from(event: ArchivedEvent) -> Self {
        Self {
            height: event.height.get(),
            block_digest: encode_hex(&event.block_digest),
            block_timestamp: event.block_timestamp,
            receipts_root: encode_hex(&event.receipts_root),
            tx_index: event.tx_index,
            tx_digest: encode_hex(&event.tx_digest),
            event_index: event.event_index,
            event: EventResponse::from(event.event),
        }
    }
}

impl From<Event> for EventResponse {
    fn from(event: Event) -> Self {
        Self {
            module: bytes_text(&event.module),
            kind: bytes_text(&event.kind),
            version: event.version,
            attributes: event
                .attributes
                .into_iter()
                .map(EventAttributeResponse::from)
                .collect(),
        }
    }
}

impl From<EventAttribute> for EventAttributeResponse {
    fn from(attribute: EventAttribute) -> Self {
        Self {
            key: bytes_text(&attribute.key),
            value: bytes_hex(&attribute.value),
        }
    }
}
