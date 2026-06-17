//! JSON-RPC surface for the oracle module.

#[cfg(feature = "mempool")]
mod mempool;
#[cfg(feature = "mempool")]
pub use mempool::{
    register_mempool, MempoolIngress, OracleMempoolRpc, OracleMempoolServer,
    SubmitTransactionParams, SubmitTransactionResponse, TransactionStatusResponse,
};

use std::sync::Arc;

use commonware_cryptography::sha256::Digest;
use commonware_formatting::hex as fmt_hex;
use futures::lock::Mutex as AsyncMutex;
use jsonrpsee::{
    core::{async_trait, RegisterMethodError, RpcResult},
    proc_macros::rpc,
};
use nunchi_rpc::{encode_hex, module_error, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::{FeedDefinition, FeedId, FeedPayloadEncoding, FeedRecord, FeedSubmission, OracleDB,
            OracleError, OracleLedger};
use nunchi_common::CommitState;

/// Read-only oracle state required by the oracle RPC server.
#[async_trait]
pub trait OracleQuery: Clone + Send + Sync + 'static {
    async fn nonce(&self, feed_id: String) -> Result<u64, OracleError>;

    async fn feed(&self, feed_id: String) -> Result<Option<FeedDefinition>, OracleError>;

    async fn latest_submission(
        &self,
        feed_id: String,
    ) -> Result<Option<FeedSubmission>, OracleError>;

    async fn record(&self, feed_id: String) -> Result<Option<FeedRecord>, OracleError>;

    async fn state_root(&self) -> Result<Digest, OracleError>;
}

/// Shared committed oracle ledger handle suitable for RPC query servers.
pub struct SharedLedger<D> {
    ledger: Arc<AsyncMutex<OracleLedger<D>>>,
}

impl<D> SharedLedger<D> {
    pub fn new(ledger: OracleLedger<D>) -> Self {
        Self {
            ledger: Arc::new(AsyncMutex::new(ledger)),
        }
    }

    pub async fn lock(&self) -> futures::lock::MutexGuard<'_, OracleLedger<D>> {
        self.ledger.lock().await
    }
}

impl<D> Clone for SharedLedger<D> {
    fn clone(&self) -> Self {
        Self {
            ledger: self.ledger.clone(),
        }
    }
}

#[async_trait]
impl<D> OracleQuery for SharedLedger<D>
where
    D: OracleDB + CommitState + Send + Sync + 'static,
{
    async fn nonce(&self, account: String) -> Result<u64, OracleError> {
        let account = parse_address(&account)?;
        self.lock().await.nonce(&account).await
    }

    async fn feed(&self, feed_id: String) -> Result<Option<FeedDefinition>, OracleError> {
        let feed_id = parse_feed_id(&feed_id)?;
        self.lock().await.feed(&feed_id).await
    }

    async fn latest_submission(
        &self,
        feed_id: String,
    ) -> Result<Option<FeedSubmission>, OracleError> {
        let feed_id = parse_feed_id(&feed_id)?;
        self.lock().await.latest_submission(&feed_id).await
    }

    async fn record(&self, feed_id: String) -> Result<Option<FeedRecord>, OracleError> {
        let feed_id = parse_feed_id(&feed_id)?;
        self.lock().await.record(&feed_id).await
    }

    async fn state_root(&self) -> Result<Digest, OracleError> {
        Ok(self.lock().await.root())
    }
}

/// Concrete oracle RPC server over a query backend.
#[derive(Clone)]
pub struct OracleRpc<Q> {
    query: Q,
}

impl<Q> OracleRpc<Q> {
    pub fn new(query: Q) -> Self {
        Self { query }
    }
}

#[rpc(server, namespace = "oracle", namespace_separator = ".")]
pub trait Oracle {
    #[method(name = "nonce", param_kind = map)]
    async fn nonce(&self, account: String) -> RpcResult<NonceResponse>;

    #[method(name = "feed", param_kind = map)]
    async fn feed(&self, feed_id: String) -> RpcResult<Option<FeedDefinitionResponse>>;

    #[method(name = "latest_submission", param_kind = map)]
    async fn latest_submission(
        &self,
        feed_id: String,
    ) -> RpcResult<Option<SubmissionResponse>>;

    #[method(name = "record", param_kind = map)]
    async fn record(&self, feed_id: String) -> RpcResult<Option<RecordResponse>>;

    #[method(name = "state_root")]
    async fn state_root(&self) -> RpcResult<RootResponse>;
}

#[async_trait]
impl<Q> OracleServer for OracleRpc<Q>
where
    Q: OracleQuery,
{
    async fn nonce(&self, account: String) -> RpcResult<NonceResponse> {
        let nonce = self.query.nonce(account.clone()).await.map_err(rpc_error)?;
        Ok(NonceResponse { account, nonce })
    }

    async fn feed(&self, feed_id: String) -> RpcResult<Option<FeedDefinitionResponse>> {
        let definition = self
            .query
            .feed(feed_id)
            .await
            .map_err(rpc_error)?;
        Ok(definition.map(FeedDefinitionResponse::from))
    }

    async fn latest_submission(
        &self,
        feed_id: String,
    ) -> RpcResult<Option<SubmissionResponse>> {
        let submission = self
            .query
            .latest_submission(feed_id)
            .await
            .map_err(rpc_error)?;
        Ok(submission.map(SubmissionResponse::from))
    }

    async fn record(&self, feed_id: String) -> RpcResult<Option<RecordResponse>> {
        let record = self.query.record(feed_id).await.map_err(rpc_error)?;
        Ok(record.map(RecordResponse::from))
    }

    async fn state_root(&self) -> RpcResult<RootResponse> {
        let root = self.query.state_root().await.map_err(rpc_error)?;
        Ok(RootResponse {
            root: encode_hex(&root),
        })
    }
}

// ── Response types ────────────────────────────────────────────────────────────

/// Response to `oracle.nonce`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NonceResponse {
    pub account: String,
    pub nonce: u64,
}

/// An oracle feed payload in a JSON-friendly form.
///
/// * Raw payloads are returned as a hex string.
/// * JSON payloads are inlined as a JSON value.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeedPayloadResponse {
    pub encoding: String,
    pub body: serde_json::Value,
}

/// Response to `oracle.feed`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeedDefinitionResponse {
    pub id: String,
    pub owner: String,
    pub metadata: FeedPayloadResponse,
}

/// Response to `oracle.latest_submission`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmissionResponse {
    pub observed_at_ms: u64,
    pub sequence: u64,
    pub payload: FeedPayloadResponse,
}

/// Response to `oracle.record`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecordResponse {
    pub definition: FeedDefinitionResponse,
    pub latest: Option<SubmissionResponse>,
}

/// Response to `oracle.state_root`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootResponse {
    pub root: String,
}

// ── Conversions ───────────────────────────────────────────────────────────────

impl From<FeedDefinition> for FeedDefinitionResponse {
    fn from(def: FeedDefinition) -> Self {
        Self {
            id: def.id.as_str().to_owned(),
            owner: encode_hex(&def.owner),
            metadata: payload_to_response(&def.metadata),
        }
    }
}

impl From<FeedSubmission> for SubmissionResponse {
    fn from(sub: FeedSubmission) -> Self {
        Self {
            observed_at_ms: sub.observed_at_ms,
            sequence: sub.sequence,
            payload: payload_to_response(&sub.payload),
        }
    }
}

impl From<FeedRecord> for RecordResponse {
    fn from(rec: FeedRecord) -> Self {
        Self {
            definition: FeedDefinitionResponse::from(rec.definition),
            latest: rec.latest.map(SubmissionResponse::from),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Register the oracle module's query RPC methods into a downstream router.
///
/// Transaction submission lives in [`register_mempool`] (behind the `mempool`
/// feature) so chains without a pool can still serve queries.
pub fn register<Context, Q>(
    router: &mut RpcRouter<Context>,
    rpc: OracleRpc<Q>,
) -> Result<(), RegisterMethodError>
where
    Q: OracleQuery,
{
    router.merge(rpc.into_rpc())
}

fn payload_to_response(payload: &crate::FeedPayload) -> FeedPayloadResponse {
    match payload.encoding {
        FeedPayloadEncoding::Raw => FeedPayloadResponse {
            encoding: "raw".to_string(),
            body: serde_json::Value::String(fmt_hex(&payload.body)),
        },
        FeedPayloadEncoding::Json => {
            let body = serde_json::from_slice(&payload.body)
                .unwrap_or(serde_json::Value::String(fmt_hex(&payload.body)));
            FeedPayloadResponse {
                encoding: "json".to_string(),
                body,
            }
        }
    }
}

fn parse_feed_id(value: &str) -> Result<FeedId, OracleError> {
    FeedId::new(value).map_err(|err| OracleError::Storage(err.to_string()))
}

fn parse_address(value: &str) -> Result<nunchi_common::Address, OracleError> {
    use commonware_codec::DecodeExt;
    use commonware_formatting::from_hex;
    let bytes =
        from_hex(value).ok_or_else(|| OracleError::Storage("invalid hex address".to_string()))?;
    nunchi_common::Address::decode(bytes.as_ref())
        .map_err(|err| OracleError::Storage(err.to_string()))
}

fn rpc_error(error: OracleError) -> jsonrpsee::types::ErrorObjectOwned {
    module_error(error.to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use commonware_cryptography::{Hasher, Sha256};
    use commonware_runtime::Runner as _;

    use super::*;
    use crate::{FeedDefinition, FeedId, FeedPayload, FeedRecord, FeedSubmission, OracleError};
    use nunchi_common::Address;
    use nunchi_crypto::PrivateKey;
    use serde_json::json;

    // ── Mock query backend ───────────────────────────────────────────────────

    #[derive(Clone)]
    struct MockQuery {
        inner: Arc<MockState>,
    }

    struct MockState {
        account: Address,
        feed_id: FeedId,
        definition: FeedDefinition,
        submission: FeedSubmission,
    }

    impl MockQuery {
        fn new() -> Self {
            let account = Address::external(&PrivateKey::ed25519_from_seed(1).public_key());
            let feed_id = FeedId::new("btc/usd").unwrap();
            let definition = FeedDefinition {
                id: feed_id.clone(),
                owner: account.clone(),
                metadata: FeedPayload::json(&json!({"kind": "price"})).unwrap(),
            };
            let submission = FeedSubmission {
                observed_at_ms: 1_717_171_717_000,
                sequence: 0,
                payload: FeedPayload::json(&json!({"price": "106500.12"})).unwrap(),
            };
            Self {
                inner: Arc::new(MockState {
                    account,
                    feed_id,
                    definition,
                    submission,
                }),
            }
        }
    }

    #[async_trait]
    impl OracleQuery for MockQuery {
        async fn nonce(&self, _account: String) -> Result<u64, OracleError> {
            Ok(3)
        }

        async fn feed(&self, feed_id: String) -> Result<Option<FeedDefinition>, OracleError> {
            if feed_id == self.inner.feed_id.as_str() {
                Ok(Some(self.inner.definition.clone()))
            } else {
                Ok(None)
            }
        }

        async fn latest_submission(
            &self,
            feed_id: String,
        ) -> Result<Option<FeedSubmission>, OracleError> {
            if feed_id == self.inner.feed_id.as_str() {
                Ok(Some(self.inner.submission.clone()))
            } else {
                Ok(None)
            }
        }

        async fn record(&self, feed_id: String) -> Result<Option<FeedRecord>, OracleError> {
            if feed_id == self.inner.feed_id.as_str() {
                Ok(Some(FeedRecord {
                    definition: self.inner.definition.clone(),
                    latest: Some(self.inner.submission.clone()),
                }))
            } else {
                Ok(None)
            }
        }

        async fn state_root(&self) -> Result<Digest, OracleError> {
            Ok(Sha256::hash(b"root"))
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn build_module(query: MockQuery) -> jsonrpsee::RpcModule<()> {
        let mut router = RpcRouter::new(());
        register(&mut router, OracleRpc::new(query)).expect("register oracle RPC");
        router.into_module()
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn oracle_rpc_nonce() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let query = MockQuery::new();
            let account = encode_hex(&query.inner.account);
            let module = build_module(query);

            let mut params = jsonrpsee::core::params::ObjectParams::new();
            params
                .insert("account", account.clone())
                .expect("serialize param");
            let response: NonceResponse =
                module.call("oracle.nonce", params).await.expect("nonce");
            assert_eq!(response.nonce, 3);
            assert_eq!(response.account, account);
        });
    }

    #[test]
    fn oracle_rpc_feed_found_and_missing() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let query = MockQuery::new();
            let module = build_module(query);

            let mut params = jsonrpsee::core::params::ObjectParams::new();
            params
                .insert("feed_id", "btc/usd")
                .expect("serialize param");
            let response: Option<FeedDefinitionResponse> =
                module.call("oracle.feed", params).await.expect("feed");
            assert!(response.is_some());
            let def = response.unwrap();
            assert_eq!(def.id, "btc/usd");
            assert_eq!(def.metadata.encoding, "json");
            assert_eq!(def.metadata.body["kind"], "price");

            let mut params = jsonrpsee::core::params::ObjectParams::new();
            params
                .insert("feed_id", "unknown/feed")
                .expect("serialize param");
            let missing: Option<FeedDefinitionResponse> =
                module.call("oracle.feed", params).await.expect("feed");
            assert!(missing.is_none());
        });
    }

    #[test]
    fn oracle_rpc_latest_submission() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let module = build_module(MockQuery::new());

            let mut params = jsonrpsee::core::params::ObjectParams::new();
            params
                .insert("feed_id", "btc/usd")
                .expect("serialize param");
            let response: Option<SubmissionResponse> = module
                .call("oracle.latest_submission", params)
                .await
                .expect("latest_submission");
            let sub = response.unwrap();
            assert_eq!(sub.sequence, 0);
            assert_eq!(sub.observed_at_ms, 1_717_171_717_000);
            assert_eq!(sub.payload.body["price"], "106500.12");
        });
    }

    #[test]
    fn oracle_rpc_record() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let module = build_module(MockQuery::new());

            let mut params = jsonrpsee::core::params::ObjectParams::new();
            params
                .insert("feed_id", "btc/usd")
                .expect("serialize param");
            let response: Option<RecordResponse> =
                module.call("oracle.record", params).await.expect("record");
            let rec = response.unwrap();
            assert_eq!(rec.definition.id, "btc/usd");
            assert_eq!(rec.latest.as_ref().unwrap().sequence, 0);
        });
    }

    #[test]
    fn oracle_rpc_state_root() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let module = build_module(MockQuery::new());
            let response: RootResponse = module
                .call(
                    "oracle.state_root",
                    jsonrpsee::core::EmptyServerParams::new(),
                )
                .await
                .expect("state_root");
            assert_eq!(response.root, encode_hex(&Sha256::hash(b"root")));
        });
    }

    #[test]
    fn raw_payload_is_hex_encoded_in_response() {
        let raw = crate::FeedPayload::raw(vec![0xde, 0xad, 0xbe, 0xef]).unwrap();
        let response = payload_to_response(&raw);
        assert_eq!(response.encoding, "raw");
        assert_eq!(response.body, serde_json::Value::String("deadbeef".to_string()));
    }
}
