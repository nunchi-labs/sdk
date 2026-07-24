//! Bounded, server-only read surface for authorized costs projections.
//!
//! This trait intentionally exposes no transaction, signer, writer, or
//! mutation capability. A BFF must authorize a account before calling it.

use jsonrpsee::{core::{async_trait, RegisterMethodError, RpcResult}, proc_macros::rpc};
use nunchi_rpc::{module_error, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::{AccountReadV1, CostsError, LedgerMutationV1, QuoteV1, RateCardEntry, Reservation, AccountProfile};

pub const MAX_READ_PAGE: u16 = 100;

#[async_trait]
pub trait CostsQuery: Clone + Send + Sync + 'static {
    async fn account_read(&self, account_id: String) -> Result<Option<AccountReadV1>, CostsError>;
    async fn profile(&self, account_id: String) -> Result<Option<AccountProfile>, CostsError>;
    async fn quote(&self, account_id: String, event_category: String, task_key: String, quantity: u64, quoted_at: u64, expires_at: u64) -> Result<Option<QuoteV1>, CostsError>;
    async fn reservation(&self, reservation_id: String) -> Result<Option<Reservation>, CostsError>;
    async fn journal(&self, from_sequence: u64, limit: u16) -> Result<Vec<LedgerMutationV1>, CostsError>;
    async fn active_rate(&self, account_id: String, event_category: String, task_key: String, price_at: u64) -> Result<Option<RateCardEntry>, CostsError>;
}

#[derive(Clone)]
pub struct CostsRpc<Q> { query: Q }
impl<Q> CostsRpc<Q> { pub fn new(query: Q) -> Self { Self { query } } }

#[rpc(server, namespace = "costs", namespace_separator = ".")]
pub trait Costs {
    #[method(name = "account_read", param_kind = map)]
    async fn account_read(&self, account_id: String) -> RpcResult<Option<AccountReadResponse>>;
    #[method(name = "profile", param_kind = map)]
    async fn profile(&self, account_id: String) -> RpcResult<Option<ProfileResponse>>;
    #[method(name = "quote", param_kind = map)]
    async fn quote(&self, account_id: String, event_category: String, task_key: String, quantity: u64, quoted_at: u64, expires_at: u64) -> RpcResult<Option<QuoteResponse>>;
    #[method(name = "reservation", param_kind = map)]
    async fn reservation(&self, reservation_id: String) -> RpcResult<Option<ReservationResponse>>;
    #[method(name = "journal", param_kind = map)]
    async fn journal(&self, from_sequence: u64, limit: u16) -> RpcResult<Vec<JournalResponse>>;
    #[method(name = "active_rate", param_kind = map)]
    async fn active_rate(&self, account_id: String, event_category: String, task_key: String, price_at: u64) -> RpcResult<Option<RateResponse>>;
}

#[async_trait]
impl<Q: CostsQuery> CostsServer for CostsRpc<Q> {
    async fn account_read(&self, account_id: String) -> RpcResult<Option<AccountReadResponse>> { Ok(self.query.account_read(account_id).await.map_err(rpc_error)?.map(Into::into)) }
    async fn profile(&self, account_id: String) -> RpcResult<Option<ProfileResponse>> { Ok(self.query.profile(account_id).await.map_err(rpc_error)?.map(Into::into)) }
    async fn quote(&self, account_id: String, event_category: String, task_key: String, quantity: u64, quoted_at: u64, expires_at: u64) -> RpcResult<Option<QuoteResponse>> { Ok(self.query.quote(account_id, event_category, task_key, quantity, quoted_at, expires_at).await.map_err(rpc_error)?.map(Into::into)) }
    async fn reservation(&self, reservation_id: String) -> RpcResult<Option<ReservationResponse>> { Ok(self.query.reservation(reservation_id).await.map_err(rpc_error)?.map(Into::into)) }
    async fn journal(&self, from_sequence: u64, limit: u16) -> RpcResult<Vec<JournalResponse>> { if limit == 0 || limit > MAX_READ_PAGE { return Err(module_error("invalid journal limit")); } Ok(self.query.journal(from_sequence, limit).await.map_err(rpc_error)?.into_iter().map(Into::into).collect()) }
    async fn active_rate(&self, account_id: String, event_category: String, task_key: String, price_at: u64) -> RpcResult<Option<RateResponse>> { Ok(self.query.active_rate(account_id, event_category, task_key, price_at).await.map_err(rpc_error)?.map(Into::into)) }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountReadResponse { pub status: String, pub available_credits: u64, pub reserved_credits: u64, pub policy_ref: String, pub cohort_ref: String }
impl From<AccountReadV1> for AccountReadResponse { fn from(v: AccountReadV1) -> Self { Self { status: format!("{:?}", v.account.status).to_lowercase(), available_credits: v.account.available_credits, reserved_credits: v.account.reserved_credits, policy_ref: v.profile.policy_ref, cohort_ref: v.profile.cohort_ref } } }
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProfileResponse { pub account_id: String, pub external_ref: String, pub policy_ref: String, pub cohort_ref: String, pub created_at: u64, pub status_reason: String, pub status_changed_at: u64 }
impl From<AccountProfile> for ProfileResponse { fn from(v: AccountProfile) -> Self { Self { account_id: v.account_id, external_ref: v.external_ref, policy_ref: v.policy_ref, cohort_ref: v.cohort_ref, created_at: v.created_at, status_reason: v.status_reason, status_changed_at: v.status_changed_at } } }
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuoteResponse { pub quote_id: String, pub snapshot_hash: String, pub account_id: String, pub event_category: String, pub task_key: String, pub total_credits: u64, pub quantity: u64, pub expires_at: u64, pub policy_version: String, pub rate_version: String }
impl From<QuoteV1> for QuoteResponse { fn from(v: QuoteV1) -> Self { Self { quote_id: v.quote_id, snapshot_hash: v.snapshot_hash, account_id: v.account_id, event_category: v.event_category, task_key: v.task_key, total_credits: v.total_credits, quantity: v.quantity, expires_at: v.expires_at, policy_version: v.policy_version, rate_version: v.rate_version } } }
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReservationResponse { pub reservation_id: String, pub account_id: String, pub quote_id: String, pub snapshot_hash: String, pub lineage_ref: String, pub credits: u64, pub expires_at: u64, pub status: String }
impl From<Reservation> for ReservationResponse { fn from(v: Reservation) -> Self { Self { reservation_id: v.reservation_id, account_id: v.account_id, quote_id: v.quote.quote_id, snapshot_hash: v.quote.snapshot_hash, lineage_ref: v.lineage_ref, credits: v.credits, expires_at: v.expires_at, status: format!("{:?}", v.status).to_lowercase() } } }
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RateResponse { pub account_id: String, pub event_category: String, pub task_key: String, pub credits: u64, pub effective_at: u64, pub expires_at: u64, pub policy_version: String, pub rate_version: String }
impl From<RateCardEntry> for RateResponse { fn from(v: RateCardEntry) -> Self { Self { account_id: v.account_id, event_category: v.event_category, task_key: v.task_key, credits: v.credits, effective_at: v.effective_at, expires_at: v.expires_at, policy_version: v.policy_version, rate_version: v.rate_version } } }
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JournalResponse { pub sequence: u64, pub transaction_id: String, pub kind: String, pub account_id: String, pub reason_code: String, pub occurred_at: u64, pub approval_ref: String, pub audit_ref: String }
impl From<LedgerMutationV1> for JournalResponse { fn from(v: LedgerMutationV1) -> Self { Self { sequence: v.sequence, transaction_id: v.transaction_id, kind: format!("{:?}", v.kind), account_id: v.account_id, reason_code: v.reason_code, occurred_at: v.occurred_at, approval_ref: v.approval_ref, audit_ref: v.audit_ref } } }

pub fn register<Context, Q>(router: &mut RpcRouter<Context>, rpc: CostsRpc<Q>) -> Result<(), RegisterMethodError> where Q: CostsQuery { router.merge(rpc.into_rpc()) }
fn rpc_error(error: CostsError) -> jsonrpsee::types::ErrorObjectOwned { module_error(error.to_string()) }
