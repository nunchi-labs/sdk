use std::collections::{BTreeMap, BTreeSet};

use commonware_codec::Write;
use commonware_cryptography::{Hasher, Sha256};
use nunchi_common::Address;
use nunchi_crypto::SignatureError;
use thiserror::Error;

use crate::{
    AccountReadV1, AdjustmentKind, AdjustmentMetadata, BalanceMutationDirection, CostsDB, CostsOperation,
    LedgerMutationKind, LedgerMutationV1, QuoteRequestV1, QuoteV1, RateCardChangeSetV1,
    RateCardCompletionV1, StoredValueAccountReadV1, StoredValueFinalityEventV1,
    StoredValueFinalityPayloadV1, StoredValueLotReadV1,
    Reservation, ReservationStatus, CreditAccount, AccountProfile, AccountStatus, StatusHistoryEntry,
    StatusChangeMetadataV1, Transaction, UntrackedSourceV1, WriterRole,
};

/// Maximum normalized records accepted in one metering transaction.
pub const MAX_SPEND_RECORDS_PER_BATCH: usize = 150;
/// Maximum rate targets carried by one staged or activation command.
pub const MAX_RATE_ENTRIES_PER_COMMAND: usize = 64;
/// Bound control-plane fan-out and onboarding inheritance work in one
/// deterministic state transition. A production migration can raise this only
/// through an explicit storage and gas review.
pub const MAX_REGISTERED_SITES: u64 = 4_096;
pub const MAX_GLOBAL_RATE_REVISIONS: u64 = 4_096;

/// Deterministic failures exposed by the costs state machine.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum CostsError {
    #[error("bad costs transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("unauthorized {role:?} writer {writer:?}")]
    Unauthorized { role: WriterRole, writer: Box<Address> },
    #[error("invalid {field}")]
    InvalidField { field: &'static str },
    #[error("legacy operation {operation} is no longer accepted; use the V1 command")]
    LegacyOperationRejected { operation: &'static str },
    #[error("account account {account_id} already exists")]
    AccountAlreadyExists { account_id: String },
    #[error("account account {account_id} was not found")]
    AccountNotFound { account_id: String },
    #[error("account account {account_id} is suspended")]
    AccountSuspended { account_id: String },
    #[error("insufficient credits for {account_id}: available {available}, required {required}")]
    InsufficientCredits {
        account_id: String,
        available: u64,
        required: u64,
    },
    #[error("spend batch contains {actual} records; maximum is {maximum}")]
    BatchTooLarge { actual: usize, maximum: usize },
    #[error("credit balance overflow")]
    CreditOverflow,
    #[error("reserved credit balance underflow")]
    ReservedCreditUnderflow,
    #[error("reservation {reservation_id} already exists with different terms")]
    ReservationConflict { reservation_id: String },
    #[error("reservation {reservation_id} was not found")]
    ReservationNotFound { reservation_id: String },
    #[error("reservation {reservation_id} is not active")]
    ReservationNotActive { reservation_id: String },
    #[error("rate change set {change_set_id} was not found")]
    RateChangeSetNotFound { change_set_id: String },
    #[error("rate change set {change_set_id} conflicts with its approved manifest")]
    RateChangeSetConflict { change_set_id: String },
    #[error("rate change set {change_set_id} is incomplete: staged {staged}, expected {expected}")]
    RateChangeSetIncomplete {
        change_set_id: String,
        staged: u16,
        expected: u16,
    },
    #[error("rate command contains {actual} entries; maximum is {maximum}")]
    RateCommandTooLarge { actual: usize, maximum: usize },
    #[error("registered account capacity {maximum} has been reached")]
    AccountRegistryFull { maximum: u64 },
    #[error("global rate revision capacity {maximum} has been reached")]
    GlobalRateRegistryFull { maximum: u64 },
    #[error("idempotency reference {reference} was replayed with different contents")]
    IdempotencyConflict { reference: String },
    #[error("spend {event_id} does not match its pinned rate snapshot")]
    PinnedRateMismatch { event_id: String },
    #[error("reservation {reservation_id} cannot settle while its account is suspended")]
    ReservationAccountSuspended { reservation_id: String },
    #[error("reservation {reservation_id} expired at {expires_at}")]
    ReservationExpired { reservation_id: String, expires_at: u64 },
    #[error("state storage error: {0}")]
    Storage(String),
}

/// Generic custodial ledger for client account accounts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostsLedger<D> {
    pub(crate) db: D,
}

/// The narrow set of state changes that are entitled to a persisted finality
/// mutation.  Idempotency is a state-machine property: a successful replay
/// advances its signer nonce but must not manufacture a second ledger event.
#[derive(Clone, Debug)]
enum AppliedMutation {
    None,
    Onboarded,
    OnboardedWithRates(Vec<crate::RateCardEntry>),
    BalanceChanged,
    Spend(Vec<crate::SpendRecordV1>),
    StatusChanged,
    ReservationChanged,
    UntrackedSourceRegistered,
    RatesStaged(Vec<crate::RateCardEntry>),
    RatesApplied(Vec<crate::RateCardEntry>),
}

impl<D: CostsDB> CostsLedger<D> {
    /// Wrap a database backend as a costs ledger.
    pub fn new(db: D) -> Self {
        Self { db }
    }

    /// Borrow the underlying database.
    pub fn db(&self) -> &D {
        &self.db
    }

    /// Consume the ledger, returning the underlying database.
    pub fn into_inner(self) -> D {
        self.db
    }

    /// Read one opaque account account.
    pub async fn account(&self, account_id: &str) -> Result<Option<CreditAccount>, CostsError> {
        self.db.account(account_id).await
    }

    /// Read a long-running action's hold state.
    pub async fn reservation(
        &self,
        reservation_id: &str,
    ) -> Result<Option<Reservation>, CostsError> {
        self.db.reservation(reservation_id).await
    }

    /// Read non-financial onboarding/status metadata for a account. This remains
    /// a private backend/BFF surface; it is not a public chain RPC.
    pub async fn profile(&self, account_id: &str) -> Result<Option<AccountProfile>, CostsError> {
        self.db.profile(account_id).await
    }

    /// Private BFF-facing account read. Callers must enforce their own
    /// account-scoped authorization before invoking this chain read.
    pub async fn account_read(&self, account_id: &str) -> Result<Option<AccountReadV1>, CostsError> {
        let Some(account) = self.db.account(account_id).await? else {
            return Ok(None);
        };
        let profile = self.db.profile(account_id).await?.ok_or_else(|| CostsError::Storage(
            "account is missing its immutable profile".to_string(),
        ))?;
        Ok(Some(AccountReadV1 { account, profile }))
    }

    /// Private BFF-facing, provenance-preserving stored-value read. The V2
    /// economic ledger is intentionally separate from aggregate metering
    /// balances while the clean-state migration remains unapproved.
    pub async fn stored_value_account_read(
        &self,
        account_id: &str,
        now: u64,
        period_ref: &str,
        reset_at: u64,
    ) -> Result<Option<StoredValueAccountReadV1>, CostsError> {
        if self.db.account(account_id).await?.is_none() {
            return Ok(None);
        }
        self.db
            .stored_value_ledger()
            .await?
            .account_read(account_id, now, period_ref, reset_at)
            .map(Some)
            .map_err(stored_value_error)
    }

    /// Private sink/BFF lot history. Do not expose this from a public client
    /// RPC: caller-side `account_id` authorization remains mandatory.
    pub async fn stored_value_lots(
        &self,
        account_id: &str,
    ) -> Result<Option<Vec<StoredValueLotReadV1>>, CostsError> {
        if self.db.account(account_id).await?.is_none() {
            return Ok(None);
        }
        self.db
            .stored_value_ledger()
            .await?
            .lots_for_account(account_id)
            .map(Some)
            .map_err(stored_value_error)
    }

    /// Read immutable V2 projection inputs. A finality adapter must consume
    /// these only for finalized chain transactions, then dedupe using the
    /// stored event identity before projecting to downstream warehouse or a client-safe BFF.
    pub async fn stored_value_finality_events(
        &self,
        from_sequence: u64,
        limit: u16,
    ) -> Result<Vec<StoredValueFinalityEventV1>, CostsError> {
        Ok(self.db.stored_value_ledger().await?.finality_events(from_sequence, limit))
    }

    /// Convenience one-unit quote with a complete ID and snapshot hash. New
    /// callers should prefer `quote_request` to supply an explicit expiry.
    pub async fn quote(
        &self,
        account_id: &str,
        event_category: &str,
        task_key: &str,
        quoted_at: u64,
    ) -> Result<Option<QuoteV1>, CostsError> {
        let Some(rate) = self.active_rate(account_id, event_category, task_key, quoted_at).await? else { return Ok(None); };
        let expires_at = if rate.expires_at == 0 { quoted_at.checked_add(1).ok_or(CostsError::CreditOverflow)? } else { rate.expires_at };
        self.quote_request(QuoteRequestV1 { account_id: account_id.to_string(), event_category: event_category.to_string(), task_key: task_key.to_string(), quantity: 1, quoted_at, expires_at }).await
    }

    /// Produce a fixed-price, bounded-lifetime quote snapshot for reservation.
    pub async fn quote_request(&self, request: QuoteRequestV1) -> Result<Option<QuoteV1>, CostsError> {
        if request.quantity == 0 || request.expires_at <= request.quoted_at { return Err(CostsError::InvalidField { field: "quote_expiry_or_quantity" }); }
        let Some(rate) = self.active_rate(&request.account_id, &request.event_category, &request.task_key, request.quoted_at).await? else { return Ok(None); };
        if rate.expires_at != 0 && request.expires_at > rate.expires_at { return Err(CostsError::InvalidField { field: "quote_expires_at" }); }
        let total_credits = rate.credits.checked_mul(request.quantity).ok_or(CostsError::CreditOverflow)?;
        let mut quote = QuoteV1 { quote_id: String::new(), snapshot_hash: String::new(), account_id: request.account_id, event_category: request.event_category, task_key: request.task_key, quoted_at: request.quoted_at, credits_per_unit: rate.credits, quantity: request.quantity, total_credits, policy_version: rate.policy_version, rate_version: rate.rate_version, expires_at: request.expires_at };
        quote.snapshot_hash = quote_snapshot_hash(&quote);
        quote.quote_id = format!("quote:{}", &quote.snapshot_hash[..32]);
        Ok(Some(quote))
    }

    /// Read the append-only status history, oldest first.
    pub async fn status_history(
        &self,
        account_id: &str,
    ) -> Result<Vec<StatusHistoryEntry>, CostsError> {
        let count = self.db.status_history_count(account_id).await?;
        let mut result = Vec::with_capacity(count as usize);
        for sequence in 0..count {
            if let Some(entry) = self.db.status_history(account_id, sequence).await? {
                result.push(entry);
            }
        }
        Ok(result)
    }

    /// Read append-only post-state mutation records, oldest first. This is a
    /// private chain-read seam for the finality sink and reconciliation, never
    /// a public client endpoint.
    pub async fn journal(&self, from_sequence: u64, limit: u16) -> Result<Vec<LedgerMutationV1>, CostsError> {
        let count = self.db.journal_count().await?;
        let end = from_sequence.saturating_add(u64::from(limit)).min(count);
        let mut entries = Vec::with_capacity((end - from_sequence) as usize);
        for sequence in from_sequence..end {
            if let Some(entry) = self.db.journal_entry(sequence).await? {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    /// Resolve the active scoped rate at `price_at` using account/task, account/category,
    /// global/task, then global/category precedence.
    pub async fn active_rate(
        &self,
        account_id: &str,
        event_category: &str,
        task_key: &str,
        price_at: u64,
    ) -> Result<Option<crate::RateCardEntry>, CostsError> {
        for (candidate_account, candidate_task) in [
            (account_id, task_key),
            (account_id, ""),
            ("", task_key),
            ("", ""),
        ] {
            let count = self.db.rate_history_count(candidate_account, event_category, candidate_task).await?;
            let mut selected: Option<crate::RateCardEntry> = None;
            for sequence in 0..count {
                if let Some(entry) = self.db.rate_history_entry(candidate_account, event_category, candidate_task, sequence).await? {
                    // Global defaults may be materialized for read-model and
                    // reconciliation purposes, but their stored account-shaped
                    // copy is not an explicit account rule. Skip it here so the
                    // declared scope order remains account/task > account/category
                    // > global/task > global/category.
                    if !candidate_account.is_empty()
                        && self.db.rate_history_global_materialization(candidate_account, event_category, candidate_task, sequence).await? {
                        continue;
                    }
                    let eligible = entry.effective_at <= price_at && (entry.expires_at == 0 || price_at < entry.expires_at);
                    let replaces = selected
                        .as_ref()
                        .is_none_or(|current| entry.effective_at >= current.effective_at);
                    if eligible && replaces {
                    // Equal effective timestamps are a deliberate revision; the
                    // last activated entry wins while the earlier entry stays
                    // queryable in history for reconciliation.
                    selected = Some(entry);
                    }
                }
            }
            if selected.is_some() {
                return Ok(selected);
            }
        }
        Ok(None)
    }

    /// Apply one signed costs transaction.
    pub async fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), CostsError> {
        self.apply_transaction_with_outcomes(tx).await.map(|_| ())
    }

    /// Apply one transaction and return the ledger-generated, persisted
    /// post-state outcomes. Adapters may publish them only after chain finality.
    pub async fn apply_transaction_with_outcomes(
        &mut self,
        tx: &Transaction,
    ) -> Result<Vec<LedgerMutationV1>, CostsError> {
        tx.verify()?;

        let expected = self.db.nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(CostsError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        let stored_value_transaction_id = format!("{:?}", tx.digest());
        let applied = match &tx.payload.operation {
            CostsOperation::RegisterAccount { .. } => return Err(CostsError::LegacyOperationRejected { operation: "RegisterAccount" }),
            CostsOperation::CreateAccount { account_id, external_ref, policy_ref, cohort_ref, created_at } => {
                validate_identifier(account_id, "account_id")?;
                validate_identifier(external_ref, "external_ref")?;
                validate_identifier(policy_ref, "policy_ref")?;
                if !cohort_ref.is_empty() { validate_identifier(cohort_ref, "cohort_ref")?; }
                self.require_writer(WriterRole::Admin, &tx.account_id).await?;
                if let Some(existing_account) = self.db.onboarding_account(external_ref).await? {
                    if existing_account != *account_id {
                        return Err(CostsError::IdempotencyConflict { reference: external_ref.clone() });
                    }
                }
                let requested = AccountProfile {
                    account_id: account_id.clone(), external_ref: external_ref.clone(),
                    policy_ref: policy_ref.clone(), cohort_ref: cohort_ref.clone(), created_at: *created_at,
                    status_reason: "onboarded".to_string(), status_changed_at: *created_at,
                };
                match (self.db.account(account_id).await?, self.db.profile(account_id).await?) {
                    (None, None) => {
                        self.preflight_account_registry_append(account_id).await?;
                        self.db.set_account(account_id, CreditAccount::active());
                        let mut stored_value = self.db.stored_value_ledger().await?;
                        stored_value.onboard(account_id).map_err(stored_value_error)?;
                        self.db.set_stored_value_ledger(stored_value);
                        self.db.set_profile(requested);
                        self.db.set_onboarding_account(external_ref, account_id);
                        self.append_account_to_registry(account_id).await?;
                        self.append_status_history(account_id, AccountStatus::Active, "onboarded", *created_at, "onboarded", "onboarded").await?;
                        let inherited = self.materialize_active_global_rates(account_id, *created_at).await?;
                        if inherited.is_empty() { AppliedMutation::Onboarded } else { AppliedMutation::OnboardedWithRates(inherited) }
                    }
                    (Some(_), Some(existing)) if existing == requested => AppliedMutation::None,
                    _ => return Err(CostsError::IdempotencyConflict { reference: external_ref.clone() }),
                }
            }
            CostsOperation::SetWriter { .. } => return Err(CostsError::LegacyOperationRejected { operation: "SetWriter" }),
            CostsOperation::SetAccountWriter { account_id, role, writer, enabled } => {
                validate_identifier(account_id, "account_id")?;
                self.require_writer(WriterRole::Admin, &tx.account_id).await?;
                self.require_account(account_id).await?;
                self.db.set_account_writer(*role, account_id, writer, *enabled);
                AppliedMutation::None
            }
            CostsOperation::RotateAdmin { replacement } => {
                self.require_writer(WriterRole::Admin, &tx.account_id).await?;
                if replacement == &tx.account_id {
                    return Err(CostsError::InvalidField { field: "replacement" });
                }
                self.db.set_writer(WriterRole::Admin, replacement, true);
                self.db.set_writer(WriterRole::Admin, &tx.account_id, false);
                AppliedMutation::None
            }
            CostsOperation::CreditTopup {
                account_id,
                credits,
                rail_ref,
            } => {
                validate_identifier(account_id, "account_id")?;
                validate_identifier(rail_ref, "rail_ref")?;
                if *credits == 0 {
                    return Err(CostsError::InvalidField { field: "credits" });
                }
                self.require_writer_for_account(WriterRole::Billing, account_id, &tx.account_id).await?;
                let fingerprint = topup_fingerprint(account_id, *credits);
                if let Some(existing) = self.db.rail_fingerprint(rail_ref).await? {
                    if existing == fingerprint {
                        self.advance_nonce(&tx.account_id, expected)?;
                        return Ok(Vec::new());
                    }
                    return Err(CostsError::IdempotencyConflict {
                        reference: rail_ref.clone(),
                    });
                }
                let mut account = self.require_account(account_id).await?;
                account.available_credits = account
                    .available_credits
                    .checked_add(*credits)
                    .ok_or(CostsError::CreditOverflow)?;
                self.db.set_account(account_id, account);
                self.db.mark_rail(rail_ref, &fingerprint);
                AppliedMutation::BalanceChanged
            }
            CostsOperation::StoredValueTopupV2 { topup } => {
                self.require_writer_for_account(WriterRole::Billing, &topup.account_id, &tx.account_id).await?;
                self.require_account(&topup.account_id).await?;
                let mut stored_value = self.db.stored_value_ledger().await?;
                stored_value.credit_topup(topup.clone()).map_err(stored_value_error)?;
                stored_value.append_finality_event(
                    format!("topup:{}", topup.rail_ref), stored_value_transaction_id.clone(), topup.account_id.clone(),
                    StoredValueFinalityPayloadV1::Topup(topup.clone()),
                ).map_err(stored_value_error)?;
                self.db.set_stored_value_ledger(stored_value);
                AppliedMutation::None
            }
            CostsOperation::StoredValueGrantV2 { grant } => {
                self.require_writer_for_account(WriterRole::Adjustment, &grant.account_id, &tx.account_id).await?;
                self.require_account(&grant.account_id).await?;
                let mut stored_value = self.db.stored_value_ledger().await?;
                stored_value.credit_grant(grant.clone()).map_err(stored_value_error)?;
                stored_value.append_finality_event(
                    format!("grant:{}", grant.reference), stored_value_transaction_id.clone(), grant.account_id.clone(),
                    StoredValueFinalityPayloadV1::Grant(grant.clone()),
                ).map_err(stored_value_error)?;
                self.db.set_stored_value_ledger(stored_value);
                AppliedMutation::None
            }
            CostsOperation::StoredValueSpendV2 { spend } => {
                self.require_writer_for_account(WriterRole::Ingest, &spend.account_id, &tx.account_id).await?;
                let account = self.require_account(&spend.account_id).await?;
                if account.status == AccountStatus::Suspended {
                    return Err(CostsError::AccountSuspended { account_id: spend.account_id.clone() });
                }
                let mut stored_value = self.db.stored_value_ledger().await?;
                let allocations = stored_value.record_spend(spend.clone()).map_err(stored_value_error)?;
                stored_value.append_finality_event(
                    format!("spend:{}", spend.event_id), stored_value_transaction_id.clone(), spend.account_id.clone(),
                    StoredValueFinalityPayloadV1::Spend { spend: spend.clone(), allocations },
                ).map_err(stored_value_error)?;
                self.db.set_stored_value_ledger(stored_value);
                AppliedMutation::None
            }
            CostsOperation::RefundPaidLotV1 { refund } => {
                self.require_writer_for_account(WriterRole::Adjustment, &refund.account_id, &tx.account_id).await?;
                self.require_account(&refund.account_id).await?;
                let mut stored_value = self.db.stored_value_ledger().await?;
                stored_value.refund_paid_lot(refund.clone()).map_err(stored_value_error)?;
                stored_value.append_finality_event(
                    format!("refund:{}", refund.refund_rail_ref), stored_value_transaction_id.clone(), refund.account_id.clone(),
                    StoredValueFinalityPayloadV1::Refund(refund.clone()),
                ).map_err(stored_value_error)?;
                self.db.set_stored_value_ledger(stored_value);
                AppliedMutation::None
            }
            CostsOperation::ReserveStoredValueV2 { reservation_id, account_id, credits, expires_at, reserved_at } => {
                self.require_writer_for_account(WriterRole::Ingest, account_id, &tx.account_id).await?;
                let account = self.require_account(account_id).await?;
                if account.status == AccountStatus::Suspended {
                    return Err(CostsError::AccountSuspended { account_id: account_id.clone() });
                }
                let mut stored_value = self.db.stored_value_ledger().await?;
                stored_value.reserve(reservation_id, account_id, *credits, *expires_at, *reserved_at).map_err(stored_value_error)?;
                self.db.set_stored_value_ledger(stored_value);
                AppliedMutation::None
            }
            CostsOperation::ReleaseStoredValueReservationV2 { reservation_id, released_at } => {
                let mut stored_value = self.db.stored_value_ledger().await?;
                let account_id = stored_value.reservation(reservation_id)
                    .ok_or_else(|| stored_value_error(crate::StoredValueError::ReservationNotFound(reservation_id.clone())))?
                    .account_id.clone();
                self.require_writer_for_account(WriterRole::Ingest, &account_id, &tx.account_id).await?;
                stored_value.release_reservation(reservation_id, *released_at).map_err(stored_value_error)?;
                self.db.set_stored_value_ledger(stored_value);
                AppliedMutation::None
            }
            CostsOperation::ExpireStoredValueReservationV2 { reservation_id, expired_at } => {
                let mut stored_value = self.db.stored_value_ledger().await?;
                let account_id = stored_value.reservation(reservation_id)
                    .ok_or_else(|| stored_value_error(crate::StoredValueError::ReservationNotFound(reservation_id.clone())))?
                    .account_id.clone();
                self.require_writer_for_account(WriterRole::Ingest, &account_id, &tx.account_id).await?;
                stored_value.expire_reservation(reservation_id, *expired_at).map_err(stored_value_error)?;
                self.db.set_stored_value_ledger(stored_value);
                AppliedMutation::None
            }
            CostsOperation::SettleStoredValueReservationV2 { reservation_id, spend } => {
                let mut stored_value = self.db.stored_value_ledger().await?;
                let account_id = stored_value.reservation(reservation_id)
                    .ok_or_else(|| stored_value_error(crate::StoredValueError::ReservationNotFound(reservation_id.clone())))?
                    .account_id.clone();
                if account_id != spend.account_id {
                    return Err(CostsError::InvalidField { field: "stored_value_reservation_account" });
                }
                self.require_writer_for_account(WriterRole::Ingest, &account_id, &tx.account_id).await?;
                let account = self.require_account(&account_id).await?;
                if account.status == AccountStatus::Suspended {
                    return Err(CostsError::AccountSuspended { account_id });
                }
                let allocations = stored_value.settle_reservation(reservation_id, spend.clone()).map_err(stored_value_error)?;
                stored_value.append_finality_event(
                    format!("spend:{}", spend.event_id), stored_value_transaction_id.clone(), spend.account_id.clone(),
                    StoredValueFinalityPayloadV1::Spend { spend: spend.clone(), allocations },
                ).map_err(stored_value_error)?;
                self.db.set_stored_value_ledger(stored_value);
                AppliedMutation::None
            }
            CostsOperation::RecordSpendBatch { records } => {
                AppliedMutation::Spend(self.apply_spend_batch(records, &tx.account_id).await?)
            }
            CostsOperation::SetAccountStatus { .. } => return Err(CostsError::LegacyOperationRejected { operation: "SetAccountStatus" }),
            CostsOperation::SetAccountStatusV1 { account_id, status, metadata } => {
                self.require_writer(WriterRole::Admin, &tx.account_id).await?;
                self.set_account_status_v1(account_id, *status, metadata).await?
            }
            CostsOperation::CreditGrant { .. } => return Err(CostsError::LegacyOperationRejected { operation: "CreditGrant" }),
            CostsOperation::CreditReversal { .. } => return Err(CostsError::LegacyOperationRejected { operation: "CreditReversal" }),
            CostsOperation::ReserveCredits { .. } => return Err(CostsError::LegacyOperationRejected { operation: "ReserveCredits" }),
            CostsOperation::ReserveCreditsV1 { reservation_id, quote, lineage_ref, reserved_at } => {
                self.require_writer_for_account(WriterRole::Ingest, &quote.account_id, &tx.account_id).await?;
                if self.reserve_v1(reservation_id, quote, lineage_ref, *reserved_at).await? { AppliedMutation::ReservationChanged } else { AppliedMutation::None }
            }
            CostsOperation::ReleaseReservation { .. } => return Err(CostsError::LegacyOperationRejected { operation: "ReleaseReservation" }),
            CostsOperation::ExpireReservation { .. } => return Err(CostsError::LegacyOperationRejected { operation: "ExpireReservation" }),
            CostsOperation::ReleaseReservationV1 { reservation_id, metadata } => {
                let reservation = self.db.reservation(reservation_id).await?.ok_or_else(|| CostsError::ReservationNotFound { reservation_id: reservation_id.clone() })?;
                self.require_writer_for_account(WriterRole::Ingest, &reservation.account_id, &tx.account_id).await?;
                validate_reservation_metadata(metadata)?;
                if self.release_reservation(reservation_id).await? { AppliedMutation::ReservationChanged } else { AppliedMutation::None }
            }
            CostsOperation::ExpireReservationV1 { reservation_id, metadata } => {
                let reservation = self.db.reservation(reservation_id).await?.ok_or_else(|| CostsError::ReservationNotFound { reservation_id: reservation_id.clone() })?;
                self.require_writer_for_account(WriterRole::Ingest, &reservation.account_id, &tx.account_id).await?;
                validate_reservation_metadata(metadata)?;
                if self.expire_reservation(reservation_id, metadata.occurred_at).await? { AppliedMutation::ReservationChanged } else { AppliedMutation::None }
            }
            CostsOperation::SettleSpend { .. } => return Err(CostsError::LegacyOperationRejected { operation: "SettleSpend" }),
            CostsOperation::SettleSpendV1 { reservation_id, event_id, event_category, task_key, quote_id, snapshot_hash, lineage_ref, metadata } => {
                let reservation = self.db.reservation(reservation_id).await?.ok_or_else(|| CostsError::ReservationNotFound { reservation_id: reservation_id.clone() })?;
                self.require_writer_for_account(WriterRole::Ingest, &reservation.account_id, &tx.account_id).await?;
                validate_reservation_metadata(metadata)?;
                if self.settle_reservation_v1(reservation_id, event_id, event_category, task_key, quote_id, snapshot_hash, lineage_ref, metadata.occurred_at).await? { AppliedMutation::ReservationChanged } else { AppliedMutation::None }
            }
            CostsOperation::RegisterUntrackedSource { .. } => return Err(CostsError::LegacyOperationRejected { operation: "RegisterUntrackedSource" }),
            CostsOperation::RegisterUntrackedSourceV1 { source } => {
                self.require_writer(WriterRole::Admin, &tx.account_id).await?;
                validate_untracked_source(source)?;
                match self.db.untracked_source(&source.source_id).await? {
                    Some(existing) if existing == *source => AppliedMutation::None,
                    Some(_) => return Err(CostsError::IdempotencyConflict { reference: source.source_id.clone() }),
                    None => { self.db.set_untracked_source(source.clone()); AppliedMutation::UntrackedSourceRegistered }
                }
            }
            CostsOperation::CreditAdjustmentV1 { kind, account_id, credits, metadata } => {
                if self.apply_adjustment_v1(*kind, account_id, *credits, metadata, &tx.account_id).await? { AppliedMutation::BalanceChanged } else { AppliedMutation::None }
            }
            CostsOperation::StageRateCardEntries { .. } => return Err(CostsError::LegacyOperationRejected { operation: "StageRateCardEntries" }),
            CostsOperation::ApplyRateCardChangeSet { .. } => return Err(CostsError::LegacyOperationRejected { operation: "ApplyRateCardChangeSet" }),
            CostsOperation::StageRateCardChangeSetV1 { change_set, entries } => {
                self.require_writer(WriterRole::Admin, &tx.account_id).await?;
                AppliedMutation::RatesStaged(self.stage_rate_entries_v1(change_set, entries).await?)
            }
            CostsOperation::ApplyRateCardChangeSetV1 { change_set, entries } => {
                self.require_writer(WriterRole::Admin, &tx.account_id).await?;
                let applied = self.apply_rate_change_set_v1(change_set, entries).await?;
                if applied.is_empty() { AppliedMutation::None } else { AppliedMutation::RatesApplied(applied) }
            }
        };

        self.advance_nonce(&tx.account_id, expected)?;
        self.append_mutation_outcomes(tx, applied).await
    }

    async fn append_mutation_outcomes(
        &mut self,
        tx: &Transaction, applied: AppliedMutation,
    ) -> Result<Vec<LedgerMutationV1>, CostsError> {
        let transaction_id = format!("{:?}", tx.digest());
        let mut entries = Vec::new();
        match (applied, &tx.payload.operation) {
            (AppliedMutation::Onboarded, CostsOperation::CreateAccount { account_id, cohort_ref, .. }) => {
                entries.push(self.outcome_for_account(&transaction_id, LedgerMutationKind::AccountOnboarded, account_id, cohort_ref, "").await?);
            }
            (AppliedMutation::OnboardedWithRates(rates), CostsOperation::CreateAccount { account_id, cohort_ref, .. }) => {
                entries.push(self.outcome_for_account(&transaction_id, LedgerMutationKind::AccountOnboarded, account_id, cohort_ref, "").await?);
                for rate in rates {
                    let mut entry = self.outcome_for_rate(&transaction_id, LedgerMutationKind::RateCardApplied, "onboarding_inheritance", &rate).await?;
                    entry.has_rate = true;
                    entry.reason_code = "global_rate_inherited".to_string();
                    entries.push(entry);
                }
            }
            (AppliedMutation::BalanceChanged, CostsOperation::CreditTopup { account_id, rail_ref, credits }) => {
                let mut entry = self.outcome_for_account(&transaction_id, LedgerMutationKind::BalanceChanged, account_id, "", rail_ref).await?;
                entry.balance_direction = BalanceMutationDirection::Credit;
                entry.credit_delta = *credits;
                entry.reason_code = "topup".to_string();
                entries.push(entry);
            }
            (AppliedMutation::BalanceChanged, CostsOperation::CreditAdjustmentV1 { kind, account_id, credits, metadata }) => {
                let mut entry = self.outcome_for_account(&transaction_id, LedgerMutationKind::BalanceChanged, account_id, "", &metadata.reference).await?;
                entry.balance_direction = match kind { AdjustmentKind::Grant => BalanceMutationDirection::Credit, AdjustmentKind::Reversal => BalanceMutationDirection::Debit };
                entry.credit_delta = *credits;
                entry.reason_code = metadata.reason_code.clone();
                entry.period_ref = metadata.period_ref.clone();
                entry.approval_ref = metadata.approval_ref.clone();
                entry.audit_ref = metadata.audit_ref.clone();
                entries.push(entry);
            }
            (AppliedMutation::Spend(records), CostsOperation::RecordSpendBatch { .. }) => {
                for record in &records {
                    entries.push(self.outcome_for_account(
                        &transaction_id, LedgerMutationKind::SpendRecorded, &record.account_id,
                        &record.cohort_ref, &record.source_ref,
                    ).await?);
                }
            }
            (AppliedMutation::StatusChanged, CostsOperation::SetAccountStatusV1 { account_id, metadata, .. }) => {
                let mut entry = self.outcome_for_account(&transaction_id, LedgerMutationKind::AccountStatusChanged, account_id, "", "").await?;
                entry.reason_code = metadata.reason_code.clone();
                entry.occurred_at = metadata.changed_at;
                entry.approval_ref = metadata.approval_ref.clone();
                entry.audit_ref = metadata.audit_ref.clone();
                entries.push(entry);
            }
            (AppliedMutation::ReservationChanged, CostsOperation::ReserveCreditsV1 { reservation_id, .. })
            | (AppliedMutation::ReservationChanged, CostsOperation::ReleaseReservationV1 { reservation_id, .. })
            | (AppliedMutation::ReservationChanged, CostsOperation::ExpireReservationV1 { reservation_id, .. })
            | (AppliedMutation::ReservationChanged, CostsOperation::SettleSpendV1 { reservation_id, .. }) => {
                let reservation = self.db.reservation(reservation_id).await?.ok_or_else(|| CostsError::ReservationNotFound { reservation_id: reservation_id.clone() })?;
                let profile = self.db.profile(&reservation.account_id).await?;
                let mut entry = self.outcome_for_account(
                    &transaction_id, LedgerMutationKind::ReservationChanged, &reservation.account_id,
                    profile.as_ref().map_or("", |value| value.cohort_ref.as_str()), "",
                ).await?;
                entry.has_reservation = true;
                entry.reservation = reservation;
                match &tx.payload.operation {
                    CostsOperation::ReleaseReservationV1 { metadata, .. }
                    | CostsOperation::ExpireReservationV1 { metadata, .. }
                    | CostsOperation::SettleSpendV1 { metadata, .. } => {
                        entry.reason_code = metadata.reason_code.clone();
                        entry.occurred_at = metadata.occurred_at;
                        entry.approval_ref = metadata.approval_ref.clone();
                        entry.audit_ref = metadata.audit_ref.clone();
                    }
                    CostsOperation::ReserveCreditsV1 { reserved_at, .. } => entry.occurred_at = *reserved_at,
                    _ => {}
                }
                entries.push(entry);
            }
            (AppliedMutation::UntrackedSourceRegistered, CostsOperation::RegisterUntrackedSourceV1 { source }) => {
                let stored = self.db.untracked_source(&source.source_id).await?.ok_or_else(|| CostsError::Storage("untracked source was not persisted".to_string()))?;
                let mut entry = empty_mutation(&transaction_id, LedgerMutationKind::UntrackedSourceRegistered);
                entry.source_ref = stored.provenance_ref.clone();
                entry.cohort_ref = stored.cohort_ref.clone();
                entry.has_untracked_source = true;
                entry.untracked_source = stored;
                entries.push(entry);
            }
            (AppliedMutation::RatesStaged(rate_entries), CostsOperation::StageRateCardChangeSetV1 { change_set, .. }) => {
                for rate in &rate_entries {
                    let mut entry = self.outcome_for_rate(&transaction_id, LedgerMutationKind::RateCardStaged, &change_set.change_set_id, rate).await?;
                    entry.has_rate = true;
                    entry.approval_ref = change_set.approval_ref.clone();
                    entry.audit_ref = change_set.audit_ref.clone();
                    entries.push(entry);
                }
            }
            (AppliedMutation::RatesApplied(rate_entries), CostsOperation::ApplyRateCardChangeSetV1 { change_set, .. }) => {
                for rate in &rate_entries {
                    let kind = if rate.account_id.is_empty() { LedgerMutationKind::RateCardGlobalApplied } else { LedgerMutationKind::RateCardApplied };
                    let mut entry = self.outcome_for_rate(&transaction_id, kind, &change_set.change_set_id, rate).await?;
                    entry.has_rate = true;
                    entry.approval_ref = change_set.approval_ref.clone();
                    entry.audit_ref = change_set.audit_ref.clone();
                    entries.push(entry);
                }
                let mut completion = empty_mutation(&transaction_id, LedgerMutationKind::RateCardCompleted);
                completion.rate_change_set_id = change_set.change_set_id.clone();
                completion.reason_code = "rate_card_applied".to_string();
                completion.occurred_at = change_set.activation_epoch;
                completion.approval_ref = change_set.approval_ref.clone();
                completion.audit_ref = change_set.audit_ref.clone();
                completion.has_rate_card_completion = true;
                completion.rate_card_completion = RateCardCompletionV1 {
                    change_set_id: change_set.change_set_id.clone(), manifest_hash: change_set.manifest_hash.clone(),
                    entry_count: change_set.expected_entry_count, target_count: change_set.expected_target_count,
                    activation_epoch: change_set.activation_epoch, approval_ref: change_set.approval_ref.clone(),
                    audit_ref: change_set.audit_ref.clone(),
                    affected_rates: rate_entries.clone(),
                };
                entries.push(completion);
            }
            // Writer capability changes and rejected legacy commands cannot
            // change a custodial balance, status, reservation, rate, or source.
            _ => {}
        }
        let mut committed = Vec::with_capacity(entries.len());
        for mut entry in entries {
            let sequence = self.db.journal_count().await?;
            entry.sequence = sequence;
            self.db.set_journal_entry(entry.clone());
            self.db.set_journal_count(sequence.checked_add(1).ok_or(CostsError::NonceOverflow)?);
            committed.push(entry);
        }
        Ok(committed)
    }

    async fn outcome_for_account(
        &self, transaction_id: &str, kind: LedgerMutationKind, account_id: &str,
        cohort_ref: &str, source_ref: &str,
    ) -> Result<LedgerMutationV1, CostsError> {
        let mut entry = empty_mutation(transaction_id, kind);
        entry.account_id = account_id.to_string();
        entry.has_account = true;
        entry.account = self.require_account(account_id).await?;
        entry.cohort_ref = if cohort_ref.is_empty() {
            self.db.profile(account_id).await?.map_or_else(String::new, |profile| profile.cohort_ref)
        } else { cohort_ref.to_string() };
        entry.source_ref = source_ref.to_string();
        Ok(entry)
    }

    async fn outcome_for_rate(
        &self, transaction_id: &str, kind: LedgerMutationKind, change_set_id: &str,
        rate: &crate::RateCardEntry,
    ) -> Result<LedgerMutationV1, CostsError> {
        let mut entry = empty_mutation(transaction_id, kind);
        entry.rate_change_set_id = change_set_id.to_string();
        entry.account_id = rate.account_id.clone();
        entry.has_rate = true;
        entry.rate = rate.clone();
        if !rate.account_id.is_empty() {
            entry.has_account = self.db.account(&rate.account_id).await?.is_some();
            if entry.has_account {
                entry.account = self.require_account(&rate.account_id).await?;
                entry.cohort_ref = self.db.profile(&rate.account_id).await?.map_or_else(String::new, |profile| profile.cohort_ref);
            }
        }
        Ok(entry)
    }

    async fn require_writer(&self, role: WriterRole, writer: &Address) -> Result<(), CostsError> {
        if self.db.writer(role, writer).await? {
            Ok(())
        } else {
            Err(CostsError::Unauthorized {
                role,
                writer: Box::new(writer.clone()),
            })
        }
    }

    async fn require_writer_for_account(
        &self,
        role: WriterRole,
        account_id: &str,
        writer: &Address,
    ) -> Result<(), CostsError> {
        if self.db.writer(role, writer).await? || self.db.account_writer(role, account_id, writer).await? {
            Ok(())
        } else {
            Err(CostsError::Unauthorized { role, writer: Box::new(writer.clone()) })
        }
    }

    async fn require_account(&self, account_id: &str) -> Result<CreditAccount, CostsError> {
        self.db
            .account(account_id)
            .await?
            .ok_or_else(|| CostsError::AccountNotFound {
                account_id: account_id.to_string(),
            })
    }

    async fn append_status_history(
        &mut self,
        account_id: &str,
        status: AccountStatus,
        reason_code: &str,
        changed_at: u64,
        approval_ref: &str,
        audit_ref: &str,
    ) -> Result<(), CostsError> {
        let sequence = self.db.status_history_count(account_id).await?;
        self.db.set_status_history(
            account_id,
            StatusHistoryEntry {
                sequence,
                status,
                reason_code: reason_code.to_string(),
                changed_at,
                approval_ref: approval_ref.to_string(), audit_ref: audit_ref.to_string(),
            },
        );
        self.db.set_status_history_count(
            account_id,
            sequence.checked_add(1).ok_or(CostsError::NonceOverflow)?,
        );
        Ok(())
    }

    async fn update_profile_status(
        &mut self,
        account_id: &str,
        status: AccountStatus,
        reason_code: &str,
        changed_at: u64, approval_ref: &str, audit_ref: &str,
    ) -> Result<(), CostsError> {
        let mut profile = self.db.profile(account_id).await?.unwrap_or(AccountProfile {
            account_id: account_id.to_string(),
            external_ref: format!("legacy:{account_id}"),
            policy_ref: "legacy".to_string(),
            created_at: 0,
            cohort_ref: String::new(),
            status_reason: String::new(),
            status_changed_at: 0,
        });
        profile.status_reason = reason_code.to_string();
        profile.status_changed_at = changed_at;
        self.db.set_profile(profile);
        self.append_status_history(account_id, status, reason_code, changed_at, approval_ref, audit_ref)
            .await
    }

    async fn set_account_status_v1(&mut self, account_id: &str, status: AccountStatus, metadata: &StatusChangeMetadataV1) -> Result<AppliedMutation, CostsError> {
        validate_identifier(account_id, "account_id")?; validate_identifier(&metadata.reason_code, "reason_code")?; validate_identifier(&metadata.approval_ref, "approval_ref")?; validate_identifier(&metadata.audit_ref, "audit_ref")?;
        if metadata.changed_at == 0 { return Err(CostsError::InvalidField { field: "changed_at" }); }
        let mut account = self.require_account(account_id).await?;
        let profile = self.db.profile(account_id).await?.ok_or_else(|| CostsError::AccountNotFound { account_id: account_id.to_string() })?;
        if account.status == status && profile.status_reason == metadata.reason_code && profile.status_changed_at == metadata.changed_at { return Ok(AppliedMutation::None); }
        account.status = status; self.db.set_account(account_id, account);
        self.update_profile_status(account_id, status, &metadata.reason_code, metadata.changed_at, &metadata.approval_ref, &metadata.audit_ref).await?;
        Ok(AppliedMutation::StatusChanged)
    }

    async fn verify_pinned_rate(&self, record: &crate::SpendRecordV1) -> Result<(), CostsError> {
        if !record.task_key.is_empty() {
            validate_identifier(&record.task_key, "task_key")?;
        }
        validate_identifier(&record.policy_version, "policy_version")?;
        validate_identifier(&record.rate_version, "rate_version")?;
        validate_identifier(&record.source_ref, "source_ref")?;
        validate_identifier(&record.lineage_ref, "lineage_ref")?;
        if !record.cohort_ref.is_empty() {
            validate_identifier(&record.cohort_ref, "cohort_ref")?;
        }
        if record.quantity == 0 || record.observed_at == 0 {
            return Err(CostsError::PinnedRateMismatch {
                event_id: record.event_id.clone(),
            });
        }
        let profile = self.db.profile(&record.account_id).await?.ok_or_else(|| CostsError::AccountNotFound {
            account_id: record.account_id.clone(),
        })?;
        if profile.cohort_ref != record.cohort_ref {
            return Err(CostsError::PinnedRateMismatch {
                event_id: record.event_id.clone(),
            });
        }
        let Some(rate) = self
            .active_rate(
                &record.account_id,
                &record.event_category,
                &record.task_key,
                record.observed_at,
            )
            .await?
        else {
            return Err(CostsError::PinnedRateMismatch {
                event_id: record.event_id.clone(),
            });
        };
        let expected = rate
            .credits
            .checked_mul(record.quantity)
            .ok_or(CostsError::CreditOverflow)?;
        if rate.rate_version != record.rate_version
            || rate.policy_version != record.policy_version
            || expected != record.credits
        {
            return Err(CostsError::PinnedRateMismatch {
                event_id: record.event_id.clone(),
            });
        }
        Ok(())
    }

    async fn reserve_v1(&mut self, reservation_id: &str, quote: &QuoteV1, lineage_ref: &str, reserved_at: u64) -> Result<bool, CostsError> {
        validate_identifier(reservation_id, "reservation_id")?; validate_quote(quote)?;
        validate_identifier(lineage_ref, "lineage_ref")?;
        if reserved_at < quote.quoted_at || reserved_at >= quote.expires_at { return Err(CostsError::ReservationExpired { reservation_id: reservation_id.to_string(), expires_at: quote.expires_at }); }
        let Some(rate) = self.active_rate(&quote.account_id, &quote.event_category, &quote.task_key, quote.quoted_at).await? else { return Err(CostsError::PinnedRateMismatch { event_id: quote.quote_id.clone() }); };
        if rate.credits != quote.credits_per_unit || rate.policy_version != quote.policy_version || rate.rate_version != quote.rate_version || quote.total_credits != quote.credits_per_unit.checked_mul(quote.quantity).ok_or(CostsError::CreditOverflow)? || quote.snapshot_hash != quote_snapshot_hash(quote) { return Err(CostsError::PinnedRateMismatch { event_id: quote.quote_id.clone() }); }
        let requested = Reservation { reservation_id: reservation_id.to_string(), account_id: quote.account_id.clone(), quote: quote.clone(), lineage_ref: lineage_ref.to_string(), credits: quote.total_credits, expires_at: quote.expires_at, status: ReservationStatus::Active };
        if let Some(existing) = self.db.reservation(reservation_id).await? { return if existing == requested { Ok(false) } else { Err(CostsError::ReservationConflict { reservation_id: reservation_id.to_string() }) }; }
        let mut account = self.require_account(&quote.account_id).await?; if account.status == AccountStatus::Suspended { return Err(CostsError::AccountSuspended { account_id: quote.account_id.clone() }); }
        let available = account.available_credits; account.available_credits = available.checked_sub(quote.total_credits).ok_or_else(|| CostsError::InsufficientCredits { account_id: quote.account_id.clone(), available, required: quote.total_credits })?; account.reserved_credits = account.reserved_credits.checked_add(quote.total_credits).ok_or(CostsError::CreditOverflow)?;
        self.db.set_account(&quote.account_id, account); self.db.set_reservation(requested); Ok(true)
    }

    async fn release_reservation(&mut self, reservation_id: &str) -> Result<bool, CostsError> {
        validate_identifier(reservation_id, "reservation_id")?;
        let mut reservation = self
            .db
            .reservation(reservation_id)
            .await?
            .ok_or_else(|| CostsError::ReservationNotFound {
                reservation_id: reservation_id.to_string(),
            })?;
        if reservation.status == ReservationStatus::Released {
            return Ok(false);
        }
        if reservation.status != ReservationStatus::Active {
            return Err(CostsError::ReservationNotActive {
                reservation_id: reservation_id.to_string(),
            });
        }
        let mut account = self.require_account(&reservation.account_id).await?;
        account.reserved_credits = account
            .reserved_credits
            .checked_sub(reservation.credits)
            .ok_or(CostsError::ReservedCreditUnderflow)?;
        account.available_credits = account
            .available_credits
            .checked_add(reservation.credits)
            .ok_or(CostsError::CreditOverflow)?;
        reservation.status = ReservationStatus::Released;
        self.db.set_account(&reservation.account_id, account);
        self.db.set_reservation(reservation);
        Ok(true)
    }

    async fn expire_reservation(
        &mut self,
        reservation_id: &str,
        expired_at: u64,
    ) -> Result<bool, CostsError> {
        validate_identifier(reservation_id, "reservation_id")?;
        let mut reservation = self.db.reservation(reservation_id).await?.ok_or_else(|| {
            CostsError::ReservationNotFound { reservation_id: reservation_id.to_string() }
        })?;
        if reservation.status == ReservationStatus::Expired { return Ok(false); }
        if reservation.status != ReservationStatus::Active {
            return Err(CostsError::ReservationNotActive { reservation_id: reservation_id.to_string() });
        }
        if expired_at < reservation.expires_at {
            return Err(CostsError::ReservationExpired { reservation_id: reservation_id.to_string(), expires_at: reservation.expires_at });
        }
        let mut account = self.require_account(&reservation.account_id).await?;
        account.reserved_credits = account.reserved_credits.checked_sub(reservation.credits)
            .ok_or(CostsError::ReservedCreditUnderflow)?;
        account.available_credits = account.available_credits.checked_add(reservation.credits)
            .ok_or(CostsError::CreditOverflow)?;
        reservation.status = ReservationStatus::Expired;
        self.db.set_account(&reservation.account_id, account);
        self.db.set_reservation(reservation);
        Ok(true)
    }

    async fn apply_adjustment_v1(
        &mut self,
        kind: AdjustmentKind,
        account_id: &str,
        credits: u64,
        metadata: &AdjustmentMetadata,
        writer: &Address,
    ) -> Result<bool, CostsError> {
        validate_identifier(account_id, "account_id")?;
        validate_identifier(&metadata.reference, "adjustment_reference")?;
        validate_identifier(&metadata.reason_code, "reason_code")?;
        validate_identifier(&metadata.period_ref, "period_ref")?;
        if credits == 0 { return Err(CostsError::InvalidField { field: "credits" }); }
        self.require_writer_for_account(WriterRole::Adjustment, account_id, writer).await?;
        validate_identifier(&metadata.approval_ref, "approval_ref")?;
        validate_identifier(&metadata.audit_ref, "audit_ref")?;
        let fingerprint = adjustment_fingerprint(kind, account_id, credits, metadata);
        if let Some(existing) = self.db.rail_fingerprint(&metadata.reference).await? {
            if existing == fingerprint { return Ok(false); }
            return Err(CostsError::IdempotencyConflict { reference: metadata.reference.clone() });
        }
        let mut account = self.require_account(account_id).await?;
        match kind {
            AdjustmentKind::Grant => account.available_credits = account.available_credits.checked_add(credits).ok_or(CostsError::CreditOverflow)?,
            AdjustmentKind::Reversal => {
                let available = account.available_credits;
                account.available_credits = available.checked_sub(credits).ok_or_else(|| CostsError::InsufficientCredits {
                    account_id: account_id.to_string(), available, required: credits,
                })?;
            }
        }
        self.db.set_account(account_id, account);
        self.db.mark_rail(&metadata.reference, &fingerprint);
        Ok(true)
    }

    async fn settle_reservation(
        &mut self,
        reservation_id: &str,
        event_id: &str,
        event_category: &str,
    ) -> Result<bool, CostsError> {
        validate_identifier(reservation_id, "reservation_id")?;
        validate_identifier(event_id, "event_id")?;
        validate_identifier(event_category, "event_category")?;
        let mut reservation = self
            .db
            .reservation(reservation_id)
            .await?
            .ok_or_else(|| CostsError::ReservationNotFound {
                reservation_id: reservation_id.to_string(),
            })?;
        let fingerprint = reservation_event_fingerprint(reservation_id, event_id, event_category);
        if let Some(existing) = self.db.event_fingerprint(event_id).await? {
            if existing == fingerprint && reservation.status == ReservationStatus::Settled {
                return Ok(false);
            }
            return Err(CostsError::IdempotencyConflict {
                reference: event_id.to_string(),
            });
        }
        if reservation.status != ReservationStatus::Active {
            return Err(CostsError::ReservationNotActive {
                reservation_id: reservation_id.to_string(),
            });
        }
        let mut account = self.require_account(&reservation.account_id).await?;
        if account.status == AccountStatus::Suspended {
            return Err(CostsError::ReservationAccountSuspended {
                reservation_id: reservation_id.to_string(),
            });
        }
        account.reserved_credits = account
            .reserved_credits
            .checked_sub(reservation.credits)
            .ok_or(CostsError::ReservedCreditUnderflow)?;
        reservation.status = ReservationStatus::Settled;
        self.db.set_account(&reservation.account_id, account);
        self.db.set_reservation(reservation);
        self.db.mark_event(event_id, &fingerprint);
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    async fn settle_reservation_v1(&mut self, reservation_id: &str, event_id: &str, event_category: &str, task_key: &str, quote_id: &str, snapshot_hash: &str, lineage_ref: &str, settled_at: u64) -> Result<bool, CostsError> {
        validate_identifier(quote_id, "quote_id")?; validate_identifier(snapshot_hash, "snapshot_hash")?; validate_identifier(lineage_ref, "lineage_ref")?;
        if !task_key.is_empty() { validate_identifier(task_key, "task_key")?; }
        let reservation = self.db.reservation(reservation_id).await?.ok_or_else(|| CostsError::ReservationNotFound { reservation_id: reservation_id.to_string() })?;
        if reservation.quote.quote_id != quote_id || reservation.quote.snapshot_hash != snapshot_hash
            || reservation.quote.event_category != event_category || reservation.quote.task_key != task_key
            || reservation.lineage_ref != lineage_ref { return Err(CostsError::PinnedRateMismatch { event_id: event_id.to_string() }); }
        if settled_at >= reservation.expires_at { return Err(CostsError::ReservationExpired { reservation_id: reservation_id.to_string(), expires_at: reservation.expires_at }); }
        self.settle_reservation(reservation_id, event_id, event_category).await
    }

    #[allow(dead_code)]
    async fn stage_rate_entries(
        &mut self,
        change_set_id: &str,
        expected_entry_count: u16,
        manifest_hash: &str,
        entries: &[crate::RateCardEntry],
    ) -> Result<Vec<crate::RateCardEntry>, CostsError> {
        validate_identifier(change_set_id, "change_set_id")?;
        validate_identifier(manifest_hash, "manifest_hash")?;
        if expected_entry_count == 0 {
            return Err(CostsError::InvalidField {
                field: "expected_entry_count",
            });
        }
        validate_rate_entries(entries)?;
        let mut change_set = match self.db.rate_change_set(change_set_id).await? {
            Some(change_set) => {
                if change_set.expected_entry_count != expected_entry_count
                    || change_set.manifest_hash != manifest_hash
                {
                    return Err(CostsError::RateChangeSetConflict {
                        change_set_id: change_set_id.to_string(),
                    });
                }
                change_set
            }
            None => crate::RateCardChangeSet {
                change_set_id: change_set_id.to_string(),
                expected_entry_count,
                target_account_ids: Vec::new(),
                expected_target_count: 0,
                manifest_hash: manifest_hash.to_string(),
                staged_entry_count: 0,
                // The current command format predates the explicit V1 control
                // plane envelope. Keep its approved manifest correlation
                // deterministic until callers move to that envelope.
                approval_ref: format!("approved:{manifest_hash}"),
                audit_ref: "legacy".to_string(),
                activation_epoch: 0,
                applied: false,
            },
        };

        let mut new_entries = Vec::new();
        for entry in entries {
            match self.db.staged_rate(change_set_id, entry).await? {
                Some(existing) if existing == *entry => {}
                Some(_) => {
                    return Err(CostsError::RateChangeSetConflict {
                        change_set_id: change_set_id.to_string(),
                    })
                }
                None => new_entries.push(entry.clone()),
            }
        }
        let new_count = u16::try_from(new_entries.len()).map_err(|_| CostsError::RateCommandTooLarge {
            actual: new_entries.len(),
            maximum: MAX_RATE_ENTRIES_PER_COMMAND,
        })?;
        change_set.staged_entry_count = change_set
            .staged_entry_count
            .checked_add(new_count)
            .ok_or(CostsError::CreditOverflow)?;
        if change_set.staged_entry_count > expected_entry_count {
            return Err(CostsError::RateChangeSetConflict {
                change_set_id: change_set_id.to_string(),
            });
        }
        for entry in &new_entries {
            self.db.set_staged_rate(change_set_id, entry.clone());
        }
        self.db.set_rate_change_set(change_set);
        Ok(new_entries)
    }

    async fn stage_rate_entries_v1(&mut self, envelope: &RateCardChangeSetV1, entries: &[crate::RateCardEntry]) -> Result<Vec<crate::RateCardEntry>, CostsError> {
        validate_rate_change_set_v1(envelope)?;
        validate_rate_entries(entries)?;
        // A change set may be staged in bounded chunks; its target manifest is
        // verified atomically at apply once every approved entry is present.
        if entries.len() == envelope.expected_entry_count as usize {
            self.validate_target_manifest(envelope, entries).await?;
            self.validate_canonical_manifest(envelope, entries)?;
            self.validate_activation_boundary(envelope, entries)?;
        }
        let high_watermark = self.db.activation_epoch_high_watermark().await?;
        let mut change_set = match self.db.rate_change_set(&envelope.change_set_id).await? {
            Some(existing) => {
                if !same_rate_change_set_envelope(&existing, envelope) {
                    return Err(CostsError::RateChangeSetConflict { change_set_id: envelope.change_set_id.clone() });
                }
                existing
            }
            None => {
                if envelope.activation_epoch <= high_watermark || envelope.applied {
                    return Err(CostsError::RateChangeSetConflict { change_set_id: envelope.change_set_id.clone() });
                }
                let mut staged = envelope.clone();
                staged.staged_entry_count = 0;
                staged.applied = false;
                staged
            }
        };
        let mut new_entries = Vec::new();
        for entry in entries {
            match self.db.staged_rate(&envelope.change_set_id, entry).await? {
                Some(existing) if existing == *entry => {}
                Some(_) => return Err(CostsError::RateChangeSetConflict { change_set_id: envelope.change_set_id.clone() }),
                None => new_entries.push(entry.clone()),
            }
        }
        let added = u16::try_from(new_entries.len()).map_err(|_| CostsError::RateCommandTooLarge { actual: new_entries.len(), maximum: MAX_RATE_ENTRIES_PER_COMMAND })?;
        change_set.staged_entry_count = change_set.staged_entry_count.checked_add(added).ok_or(CostsError::CreditOverflow)?;
        if change_set.staged_entry_count > change_set.expected_entry_count {
            return Err(CostsError::RateChangeSetConflict { change_set_id: envelope.change_set_id.clone() });
        }
        for entry in &new_entries { self.db.set_staged_rate(&envelope.change_set_id, entry.clone()); }
        self.db.set_rate_change_set(change_set);
        Ok(new_entries)
    }

    async fn apply_rate_change_set(
        &mut self,
        change_set_id: &str,
        manifest_hash: &str,
        entries: &[crate::RateCardEntry],
    ) -> Result<Vec<crate::RateCardEntry>, CostsError> {
        validate_identifier(change_set_id, "change_set_id")?;
        validate_identifier(manifest_hash, "manifest_hash")?;
        validate_rate_entries(entries)?;
        let change_set = self
            .db
            .rate_change_set(change_set_id)
            .await?
            .ok_or_else(|| CostsError::RateChangeSetNotFound {
                change_set_id: change_set_id.to_string(),
            })?;
        if change_set.manifest_hash != manifest_hash
            || entries.len() != change_set.expected_entry_count as usize
        {
            return Err(CostsError::RateChangeSetConflict {
                change_set_id: change_set_id.to_string(),
            });
        }
        if change_set.staged_entry_count != change_set.expected_entry_count {
            return Err(CostsError::RateChangeSetIncomplete {
                change_set_id: change_set_id.to_string(),
                staged: change_set.staged_entry_count,
                expected: change_set.expected_entry_count,
            });
        }
        if change_set.applied {
            return Ok(Vec::new());
        }
        let global_entries = entries.iter().filter(|entry| entry.account_id.is_empty()).count() as u64;
        let global_count = self.db.global_rate_registry_count().await?;
        if global_count.checked_add(global_entries).is_none_or(|count| count > MAX_GLOBAL_RATE_REVISIONS) {
            return Err(CostsError::GlobalRateRegistryFull { maximum: MAX_GLOBAL_RATE_REVISIONS });
        }
        for entry in entries {
            if self.db.staged_rate(change_set_id, entry).await? != Some(entry.clone()) {
                return Err(CostsError::RateChangeSetConflict {
                    change_set_id: change_set_id.to_string(),
                });
            }
        }
        for entry in entries {
            self.db.set_active_rate(entry.clone());
            self.append_rate_history(entry.clone(), false).await?;
            if entry.account_id.is_empty() {
                self.append_global_rate_revision(entry.clone()).await?;
            } else {
                self.db.set_global_rate_materialized(&entry.account_id, &entry.event_category, &entry.task_key, false);
            }
        }
        let mut applied = change_set;
        applied.applied = true;
        self.db.set_rate_change_set(applied);
        let mut materialized = entries.to_vec();
        for entry in entries.iter().filter(|entry| entry.account_id.is_empty()) {
            materialized.extend(self.propagate_global_rate(entry).await?);
        }
        Ok(materialized)
    }

    async fn apply_rate_change_set_v1(&mut self, envelope: &RateCardChangeSetV1, entries: &[crate::RateCardEntry]) -> Result<Vec<crate::RateCardEntry>, CostsError> {
        validate_rate_change_set_v1(envelope)?;
        validate_rate_entries(entries)?;
        self.validate_target_manifest(envelope, entries).await?;
        self.validate_canonical_manifest(envelope, entries)?;
        self.validate_activation_boundary(envelope, entries)?;
        let stored = self.db.rate_change_set(&envelope.change_set_id).await?.ok_or_else(|| CostsError::RateChangeSetNotFound { change_set_id: envelope.change_set_id.clone() })?;
        if !same_rate_change_set_envelope(&stored, envelope) { return Err(CostsError::RateChangeSetConflict { change_set_id: envelope.change_set_id.clone() }); }
        if stored.applied { return Ok(Vec::new()); }
        if envelope.applied || envelope.activation_epoch <= self.db.activation_epoch_high_watermark().await? { return Err(CostsError::RateChangeSetConflict { change_set_id: envelope.change_set_id.clone() }); }
        let applied = self.apply_rate_change_set(&envelope.change_set_id, &envelope.manifest_hash, entries).await?;
        self.db.set_activation_epoch_high_watermark(envelope.activation_epoch);
        Ok(applied)
    }

    fn validate_canonical_manifest(&self, envelope: &RateCardChangeSetV1, entries: &[crate::RateCardEntry]) -> Result<(), CostsError> {
        if envelope.manifest_hash != envelope.expected_manifest_hash(entries) {
            return Err(CostsError::RateChangeSetConflict { change_set_id: envelope.change_set_id.clone() });
        }
        Ok(())
    }

    fn validate_activation_boundary(&self, envelope: &RateCardChangeSetV1, entries: &[crate::RateCardEntry]) -> Result<(), CostsError> {
        // `activation_epoch` is a monotonic control-plane boundary, not wall
        // clock time. Runtime/finality time validation belongs at the
        // operator service integration boundary; this only prevents a command from
        // declaring a rate before its own approved logical epoch.
        if entries.iter().any(|entry| entry.effective_at < envelope.activation_epoch) {
            return Err(CostsError::InvalidField { field: "rate_effective_at_before_activation_epoch" });
        }
        Ok(())
    }

    async fn append_rate_history(&mut self, entry: crate::RateCardEntry, global_materialization: bool) -> Result<(), CostsError> {
        let count = self.db.rate_history_count(&entry.account_id, &entry.event_category, &entry.task_key).await?;
        // Exact replay is normally caught by the changeset applied marker; the
        // defensive scan also prevents a caller from duplicating a revision
        // through a distinct change set.
        for sequence in 0..count {
            if self.db.rate_history_entry(&entry.account_id, &entry.event_category, &entry.task_key, sequence).await? == Some(entry.clone())
                && self.db.rate_history_global_materialization(&entry.account_id, &entry.event_category, &entry.task_key, sequence).await? == global_materialization {
                return Ok(());
            }
        }
        self.db.set_rate_history_entry(entry.clone(), count);
        self.db.set_rate_history_global_materialization(&entry.account_id, &entry.event_category, &entry.task_key, count, global_materialization);
        self.db.set_rate_history_count(&entry.account_id, &entry.event_category, &entry.task_key, count.checked_add(1).ok_or(CostsError::NonceOverflow)?);
        Ok(())
    }

    async fn validate_target_manifest(&self, envelope: &RateCardChangeSetV1, entries: &[crate::RateCardEntry]) -> Result<(), CostsError> {
        let mut expected = BTreeSet::new();
        let explicit = entries.iter().filter(|entry| !entry.account_id.is_empty()).map(|entry| (entry.account_id.clone(), entry.event_category.clone(), entry.task_key.clone())).collect::<BTreeSet<_>>();
        for entry in entries {
            if !entry.account_id.is_empty() { expected.insert(entry.account_id.clone()); continue; }
            let count = self.db.account_registry_count().await?;
            if count > MAX_REGISTERED_SITES { return Err(CostsError::AccountRegistryFull { maximum: MAX_REGISTERED_SITES }); }
            for sequence in 0..count {
                let Some(account_id) = self.db.account_registry_account(sequence).await? else { continue };
                if explicit.contains(&(account_id.clone(), entry.event_category.clone(), entry.task_key.clone())) { continue; }
                if self.global_rate_applies_to_account(&account_id, entry, entry.effective_at).await? { expected.insert(account_id); }
            }
        }
        let supplied = envelope.target_account_ids.iter().cloned().collect::<BTreeSet<_>>();
        if supplied.len() != envelope.target_account_ids.len() || supplied != expected || envelope.expected_target_count as usize != expected.len() {
            return Err(CostsError::RateChangeSetConflict { change_set_id: envelope.change_set_id.clone() });
        }
        Ok(())
    }

    async fn append_account_to_registry(&mut self, account_id: &str) -> Result<(), CostsError> {
        self.preflight_account_registry_append(account_id).await?;
        let count = self.db.account_registry_count().await?;
        for sequence in 0..count {
            if self.db.account_registry_account(sequence).await?.as_deref() == Some(account_id) {
                return Ok(());
            }
        }
        self.db.set_account_registry_account(count, account_id);
        self.db.set_account_registry_count(count + 1);
        Ok(())
    }

    async fn preflight_account_registry_append(&self, account_id: &str) -> Result<(), CostsError> {
        let count = self.db.account_registry_count().await?;
        for sequence in 0..count {
            if self.db.account_registry_account(sequence).await?.as_deref() == Some(account_id) { return Ok(()); }
        }
        if count >= MAX_REGISTERED_SITES { return Err(CostsError::AccountRegistryFull { maximum: MAX_REGISTERED_SITES }); }
        Ok(())
    }

    async fn append_global_rate_revision(&mut self, entry: crate::RateCardEntry) -> Result<(), CostsError> {
        let count = self.db.global_rate_registry_count().await?;
        if count >= MAX_GLOBAL_RATE_REVISIONS { return Err(CostsError::GlobalRateRegistryFull { maximum: MAX_GLOBAL_RATE_REVISIONS }); }
        self.db.set_global_rate_registry_entry(count, entry);
        self.db.set_global_rate_registry_count(count + 1);
        Ok(())
    }

    /// Materialize a newly-approved global key to every current account which
    /// does not own an exact account/key override. The derived local history is
    /// marked so later global updates replace it, while an explicit account rate
    /// clears that marker and remains authoritative.
    async fn propagate_global_rate(&mut self, global: &crate::RateCardEntry) -> Result<Vec<crate::RateCardEntry>, CostsError> {
        let mut materialized = Vec::new();
        let count = self.db.account_registry_count().await?;
        if count > MAX_REGISTERED_SITES { return Err(CostsError::AccountRegistryFull { maximum: MAX_REGISTERED_SITES }); }
        for sequence in 0..count {
            let Some(account_id) = self.db.account_registry_account(sequence).await? else { continue };
            if !self.global_rate_applies_to_account(&account_id, global, global.effective_at).await? { continue; }
            let derived = crate::RateCardEntry { account_id: account_id.clone(), ..global.clone() };
            self.db.set_active_rate(derived.clone());
            self.append_rate_history(derived.clone(), true).await?;
            self.db.set_global_rate_materialized(&account_id, &global.event_category, &global.task_key, true);
            materialized.push(derived);
        }
        Ok(materialized)
    }

    async fn global_rate_applies_to_account(&self, account_id: &str, global: &crate::RateCardEntry, at: u64) -> Result<bool, CostsError> {
        // An explicit account/category is more specific than a global task/SKU;
        // avoid even materializing the lower-priority global target, so the
        // finality stream never falsely claims it became effective there.
        if !global.task_key.is_empty()
            && self.account_has_explicit_active_rate(account_id, &global.event_category, "", at).await? {
            return Ok(false);
        }
        Ok(!self.account_has_explicit_active_rate(account_id, &global.event_category, &global.task_key, at).await?)
    }

    async fn account_has_explicit_active_rate(&self, account_id: &str, event_category: &str, task_key: &str, at: u64) -> Result<bool, CostsError> {
        let count = self.db.rate_history_count(account_id, event_category, task_key).await?;
        for sequence in 0..count {
            let Some(entry) = self.db.rate_history_entry(account_id, event_category, task_key, sequence).await? else { continue };
            if self.db.rate_history_global_materialization(account_id, event_category, task_key, sequence).await? { continue; }
            if entry.effective_at <= at && (entry.expires_at == 0 || at < entry.expires_at) { return Ok(true); }
        }
        Ok(false)
    }

    /// New account accounts inherit all global defaults effective at onboarding.
    /// This writes local snapshots and emits rate mutation records, so clients
    /// can reconcile account creation without querying global internals.
    async fn materialize_active_global_rates(&mut self, account_id: &str, at: u64) -> Result<Vec<crate::RateCardEntry>, CostsError> {
        let count = self.db.global_rate_registry_count().await?;
        if count > MAX_GLOBAL_RATE_REVISIONS { return Err(CostsError::GlobalRateRegistryFull { maximum: MAX_GLOBAL_RATE_REVISIONS }); }
        let mut selected = BTreeMap::<(String, String), crate::RateCardEntry>::new();
        for sequence in 0..count {
            let Some(entry) = self.db.global_rate_registry_entry(sequence).await? else { continue };
            if entry.effective_at > at || (entry.expires_at != 0 && at >= entry.expires_at) { continue; }
            let key = (entry.event_category.clone(), entry.task_key.clone());
            if selected.get(&key).is_none_or(|current| entry.effective_at >= current.effective_at) { selected.insert(key, entry); }
        }
        let mut materialized = Vec::with_capacity(selected.len());
        for (_, global) in selected {
            let derived = crate::RateCardEntry { account_id: account_id.to_string(), ..global };
            self.db.set_active_rate(derived.clone());
            self.append_rate_history(derived.clone(), true).await?;
            self.db.set_global_rate_materialized(account_id, &derived.event_category, &derived.task_key, true);
            materialized.push(derived);
        }
        Ok(materialized)
    }

    fn advance_nonce(&mut self, account: &Address, expected: u64) -> Result<(), CostsError> {
        let next = expected.checked_add(1).ok_or(CostsError::NonceOverflow)?;
        self.db.set_nonce(account, next);
        Ok(())
    }

    async fn apply_spend_batch(
        &mut self,
        records: &[crate::SpendRecordV1],
        writer: &Address,
    ) -> Result<Vec<crate::SpendRecordV1>, CostsError> {
        if records.is_empty() || records.len() > MAX_SPEND_RECORDS_PER_BATCH {
            return Err(CostsError::BatchTooLarge {
                actual: records.len(),
                maximum: MAX_SPEND_RECORDS_PER_BATCH,
            });
        }

        let mut accounts = BTreeMap::<String, CreditAccount>::new();
        let mut unseen_events = BTreeMap::<String, String>::new();
        let mut new_records = Vec::new();

        for record in records {
            validate_identifier(&record.event_id, "event_id")?;
            validate_identifier(&record.account_id, "account_id")?;
            validate_identifier(&record.event_category, "event_category")?;
            if record.credits == 0 {
                return Err(CostsError::InvalidField { field: "credits" });
            }
            let fingerprint = spend_fingerprint(record);
            if let Some(existing) = self.db.event_fingerprint(&record.event_id).await? {
                if existing != fingerprint {
                    return Err(CostsError::IdempotencyConflict {
                        reference: record.event_id.clone(),
                    });
                }
                continue;
            }
            if let Some(existing) = unseen_events.insert(record.event_id.clone(), fingerprint.clone()) {
                if existing != fingerprint {
                    return Err(CostsError::IdempotencyConflict {
                        reference: record.event_id.clone(),
                    });
                }
                continue;
            }

            self.require_writer_for_account(WriterRole::Ingest, &record.account_id, writer).await?;

            self.verify_pinned_rate(record).await?;

            let account = match accounts.get(&record.account_id) {
                Some(account) => account.clone(),
                None => self.require_account(&record.account_id).await?,
            };
            if account.status == AccountStatus::Suspended {
                return Err(CostsError::AccountSuspended {
                    account_id: record.account_id.clone(),
                });
            }
            let available = account.available_credits;
            let next = available.checked_sub(record.credits).ok_or_else(|| {
                CostsError::InsufficientCredits {
                    account_id: record.account_id.clone(),
                    available,
                    required: record.credits,
                }
            })?;
            accounts.insert(
                record.account_id.clone(),
                CreditAccount {
                    available_credits: next,
                    ..account
                },
            );
            new_records.push(record);
        }

        for (account_id, account) in accounts {
            self.db.set_account(&account_id, account);
        }
        let applied_records = new_records.iter().map(|record| (*record).clone()).collect();
        for record in new_records {
            self.db.mark_event(&record.event_id, &spend_fingerprint(record));
        }
        Ok(applied_records)
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), CostsError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/'))
    {
        return Err(CostsError::InvalidField { field });
    }
    Ok(())
}

fn stored_value_error(error: crate::StoredValueError) -> CostsError {
    CostsError::Storage(format!("stored value: {error}"))
}

fn empty_mutation(transaction_id: &str, kind: LedgerMutationKind) -> LedgerMutationV1 {
    LedgerMutationV1 {
        sequence: 0,
        transaction_id: transaction_id.to_string(),
        kind,
        account_id: String::new(),
        has_account: false,
        account: CreditAccount::active(),
        cohort_ref: String::new(),
        source_ref: String::new(),
        balance_direction: BalanceMutationDirection::None,
        credit_delta: 0,
        period_ref: String::new(),
        reason_code: String::new(),
        occurred_at: 0,
        approval_ref: String::new(),
        audit_ref: String::new(),
        has_reservation: false,
        reservation: Reservation {
            reservation_id: String::new(), account_id: String::new(), lineage_ref: String::new(), quote: QuoteV1 { quote_id: String::new(), snapshot_hash: String::new(), account_id: String::new(), event_category: String::new(), task_key: String::new(), quoted_at: 0, credits_per_unit: 0, quantity: 0, total_credits: 0, policy_version: String::new(), rate_version: String::new(), expires_at: 0 }, credits: 0,
            expires_at: 0, status: ReservationStatus::Active,
        },
        rate_change_set_id: String::new(),
        has_rate: false,
        rate: crate::RateCardEntry {
            account_id: String::new(), event_category: String::new(), task_key: String::new(),
            credits: 0, effective_at: 0, expires_at: 0,
            policy_version: String::new(), rate_version: String::new(),
        },
        has_untracked_source: false,
        untracked_source: UntrackedSourceV1 {
            source_id: String::new(), reason_code: String::new(), owner_ref: String::new(),
            period_ref: String::new(), provenance_ref: String::new(), coverage_code: String::new(),
            confidence_code: String::new(), evidence_ref: String::new(), cohort_ref: String::new(),
        },
        has_rate_card_completion: false,
        rate_card_completion: RateCardCompletionV1 {
            change_set_id: String::new(), manifest_hash: String::new(), entry_count: 0, target_count: 0,
            activation_epoch: 0, approval_ref: String::new(), audit_ref: String::new(), affected_rates: Vec::new(),
        },
    }
}

fn validate_rate_entries(entries: &[crate::RateCardEntry]) -> Result<(), CostsError> {
    if entries.is_empty() || entries.len() > MAX_RATE_ENTRIES_PER_COMMAND {
        return Err(CostsError::RateCommandTooLarge {
            actual: entries.len(),
            maximum: MAX_RATE_ENTRIES_PER_COMMAND,
        });
    }
    let mut targets = BTreeSet::new();
    for entry in entries {
        if !entry.account_id.is_empty() {
            validate_identifier(&entry.account_id, "account_id")?;
        }
        validate_identifier(&entry.event_category, "event_category")?;
        if !entry.task_key.is_empty() {
            validate_identifier(&entry.task_key, "task_key")?;
        }
        validate_identifier(&entry.policy_version, "policy_version")?;
        validate_identifier(&entry.rate_version, "rate_version")?;
        if entry.credits == 0 {
            return Err(CostsError::InvalidField { field: "credits" });
        }
        if entry.expires_at != 0 && entry.expires_at <= entry.effective_at {
            return Err(CostsError::InvalidField { field: "expires_at" });
        }
        let target = format!(
            "{}\u{0}{}\u{0}{}",
            entry.account_id, entry.event_category, entry.task_key
        );
        if !targets.insert(target) {
            return Err(CostsError::RateChangeSetConflict {
                change_set_id: "duplicate_rate_target".to_string(),
            });
        }
    }
    Ok(())
}

fn validate_rate_change_set_v1(change_set: &RateCardChangeSetV1) -> Result<(), CostsError> {
    validate_identifier(&change_set.change_set_id, "change_set_id")?; validate_identifier(&change_set.manifest_hash, "manifest_hash")?;
    validate_identifier(&change_set.approval_ref, "approval_ref")?; validate_identifier(&change_set.audit_ref, "audit_ref")?;
    if change_set.activation_epoch == 0 || change_set.expected_entry_count == 0 || change_set.staged_entry_count != 0 || change_set.applied {
        return Err(CostsError::InvalidField { field: "activation_epoch_or_entry_count" });
    }
    if change_set.expected_target_count as usize != change_set.target_account_ids.len()
        || change_set.target_account_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CostsError::InvalidField { field: "target_account_ids" });
    }
    for account_id in &change_set.target_account_ids { validate_identifier(account_id, "target_account_id")?; }
    Ok(())
}

fn same_rate_change_set_envelope(stored: &RateCardChangeSetV1, supplied: &RateCardChangeSetV1) -> bool {
    stored.change_set_id == supplied.change_set_id
        && stored.expected_entry_count == supplied.expected_entry_count
        && stored.target_account_ids == supplied.target_account_ids
        && stored.expected_target_count == supplied.expected_target_count
        && stored.manifest_hash == supplied.manifest_hash
        && stored.approval_ref == supplied.approval_ref
        && stored.audit_ref == supplied.audit_ref
        && stored.activation_epoch == supplied.activation_epoch
}

fn validate_reservation_metadata(metadata: &crate::ReservationActionMetadataV1) -> Result<(), CostsError> {
    validate_identifier(&metadata.reason_code, "reason_code")?;
    validate_identifier(&metadata.approval_ref, "approval_ref")?;
    validate_identifier(&metadata.audit_ref, "audit_ref")?;
    if metadata.occurred_at == 0 { return Err(CostsError::InvalidField { field: "occurred_at" }); }
    Ok(())
}

fn validate_quote(quote: &QuoteV1) -> Result<(), CostsError> {
    validate_identifier(&quote.quote_id, "quote_id")?; validate_identifier(&quote.snapshot_hash, "snapshot_hash")?; validate_identifier(&quote.account_id, "account_id")?; validate_identifier(&quote.event_category, "event_category")?; if !quote.task_key.is_empty() { validate_identifier(&quote.task_key, "task_key")?; }
    validate_identifier(&quote.policy_version, "policy_version")?; validate_identifier(&quote.rate_version, "rate_version")?;
    if quote.quantity == 0 || quote.credits_per_unit == 0 || quote.quoted_at == 0 || quote.expires_at <= quote.quoted_at { return Err(CostsError::InvalidField { field: "quote" }); }
    Ok(())
}

fn quote_snapshot_hash(quote: &QuoteV1) -> String {
    fingerprint(b"nunchi-costs/quote/v1", |buf| {
        crate::types::write_identifier(&quote.account_id, buf); crate::types::write_identifier(&quote.event_category, buf); crate::types::write_identifier(&quote.task_key, buf); quote.quoted_at.write(buf); quote.credits_per_unit.write(buf); quote.quantity.write(buf); quote.total_credits.write(buf); crate::types::write_identifier(&quote.policy_version, buf); crate::types::write_identifier(&quote.rate_version, buf); quote.expires_at.write(buf);
    })
}

fn fingerprint(domain: &[u8], write: impl FnOnce(&mut Vec<u8>)) -> String {
    let mut bytes = Vec::with_capacity(domain.len() + 128);
    (domain.len() as u16).write(&mut bytes);
    bytes.extend_from_slice(domain);
    write(&mut bytes);
    Sha256::hash(&bytes).to_string()
}

fn topup_fingerprint(account_id: &str, credits: u64) -> String {
    fingerprint(b"nunchi-costs/topup/v1", |buf| {
        crate::types::write_identifier(account_id, buf);
        credits.write(buf);
    })
}

fn adjustment_fingerprint(
    kind: AdjustmentKind,
    account_id: &str,
    credits: u64,
    metadata: &AdjustmentMetadata,
) -> String {
    fingerprint(b"nunchi-costs/adjustment/v1", |buf| {
        kind.write(buf);
        crate::types::write_identifier(account_id, buf);
        credits.write(buf);
        metadata.write(buf);
    })
}

fn reservation_event_fingerprint(
    reservation_id: &str,
    event_id: &str,
    event_category: &str,
) -> String {
    fingerprint(b"nunchi-costs/reservation-settlement/v1", |buf| {
        crate::types::write_identifier(reservation_id, buf);
        crate::types::write_identifier(event_id, buf);
        crate::types::write_identifier(event_category, buf);
    })
}

fn spend_fingerprint(record: &crate::SpendRecordV1) -> String {
    fingerprint(b"nunchi-costs/spend/v1", |buf| record.write(buf))
}

fn validate_untracked_source(source: &UntrackedSourceV1) -> Result<(), CostsError> {
    validate_identifier(&source.source_id, "source_id")?;
    validate_identifier(&source.reason_code, "reason_code")?;
    validate_identifier(&source.owner_ref, "owner_ref")?;
    validate_identifier(&source.period_ref, "period_ref")?;
    validate_identifier(&source.provenance_ref, "provenance_ref")?;
    validate_identifier(&source.coverage_code, "coverage_code")?;
    validate_identifier(&source.confidence_code, "confidence_code")?;
    validate_identifier(&source.evidence_ref, "evidence_ref")?;
    if !source.cohort_ref.is_empty() {
        validate_identifier(&source.cohort_ref, "cohort_ref")?;
    }
    Ok(())
}
