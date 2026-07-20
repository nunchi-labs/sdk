use commonware_cryptography::sha256::Digest;

use crate::{CostsOperation, LedgerMutationKind, LedgerMutationV1, RateCardCompletionV1, Transaction};

/// A normalized state-transition result for a post-finality outbox. This is a
/// read-model contract, not a transaction payload and contains no raw source
/// data or client PII.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedOutcomeV1 {
    /// Stable outbox envelope schema; consumers dedupe on `outbox_event_id`.
    pub schema_version: u16,
    pub outbox_event_id: String,
    pub event_type: &'static str,
    pub transaction_id: Digest,
    /// Hash of the immutable finalized transaction payload envelope.
    pub payload_hash: Digest,
    pub finalized_at: u64,
    pub kind: FinalizedOutcomeKind,
    pub account_id: Option<String>,
    pub source_ref: Option<String>,
    pub rate_change_set_id: Option<String>,
    /// Present only for the one durable completion mutation. The finality
    /// outbox retains exact affected targets and policy/rate versions so
    /// `pricing.rate_card_updated` never depends on reconstructing siblings.
    pub rate_card_completion: Option<RateCardCompletionV1>,
}

/// Machine-readable category used by the finality consumer for idempotent
/// projections and reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalizedOutcomeKind {
    AccountRegistered,
    AccountOnboarded,
    WriterChanged,
    CreditsAdded,
    SpendRecorded,
    AccountStatusChanged,
    ReservationCreated,
    ReservationReleased,
    ReservationExpired,
    ReservationSettled,
    UntrackedSourceRegistered,
    CreditAdjustmentApplied,
    RateCardEntriesStaged,
    RateCardApplied,
    RateCardCompleted,
}

impl FinalizedOutcomeV1 {
    /// Build a publishable event from a persisted ledger mutation after the
    /// containing chain transaction is final. A successful idempotent replay
    /// writes no mutation, therefore it cannot produce an outbox event.
    pub fn from_finalized_mutation(
        mutation: &LedgerMutationV1,
        transaction_id: Digest,
        finalized_at: u64,
    ) -> Self {
        let kind = FinalizedOutcomeKind::from_mutation_kind(mutation.kind);
        Self {
            schema_version: 1,
            outbox_event_id: format!("ledger:{transaction_id}:{}", mutation.sequence),
            event_type: kind.event_type(),
            transaction_id,
            payload_hash: transaction_id,
            finalized_at,
            kind,
            account_id: (!mutation.account_id.is_empty()).then(|| mutation.account_id.clone()),
            source_ref: (!mutation.source_ref.is_empty()).then(|| mutation.source_ref.clone()),
            rate_change_set_id: (!mutation.rate_change_set_id.is_empty()).then(|| mutation.rate_change_set_id.clone()),
            rate_card_completion: mutation.has_rate_card_completion.then(|| mutation.rate_card_completion.clone()),
        }
    }

    /// Derive a finality-safe envelope only after the containing transaction has
    /// been finalized by the chain runtime.
    #[deprecated(note = "derive outbox events from persisted LedgerMutationV1 after finality")]
    pub fn from_finalized_transaction(tx: &Transaction, finalized_at: u64) -> Self {
        let (kind, account_id, source_ref, rate_change_set_id) = match &tx.payload.operation {
            CostsOperation::RegisterAccount { account_id } => (
                FinalizedOutcomeKind::AccountRegistered,
                Some(account_id.clone()),
                None,
                None,
            ),
            CostsOperation::CreateAccount { account_id, external_ref, .. } => (
                FinalizedOutcomeKind::AccountOnboarded,
                Some(account_id.clone()),
                Some(external_ref.clone()),
                None,
            ),
            CostsOperation::SetWriter { .. } => {
                (FinalizedOutcomeKind::WriterChanged, None, None, None)
            }
            CostsOperation::SetAccountWriter { account_id, .. } => {
                (FinalizedOutcomeKind::WriterChanged, Some(account_id.clone()), None, None)
            }
            CostsOperation::RotateAdmin { .. } => {
                (FinalizedOutcomeKind::WriterChanged, None, None, None)
            }
            CostsOperation::CreditTopup { account_id, rail_ref, .. } => (
                FinalizedOutcomeKind::CreditsAdded,
                Some(account_id.clone()),
                Some(rail_ref.clone()),
                None,
            ),
            CostsOperation::StoredValueTopupV2 { topup } => (
                FinalizedOutcomeKind::CreditsAdded,
                Some(topup.account_id.clone()),
                Some(topup.rail_ref.clone()),
                None,
            ),
            CostsOperation::StoredValueGrantV2 { grant } => (
                FinalizedOutcomeKind::CreditAdjustmentApplied,
                Some(grant.account_id.clone()),
                Some(grant.reference.clone()),
                None,
            ),
            CostsOperation::StoredValueSpendV2 { spend } => (
                FinalizedOutcomeKind::SpendRecorded,
                Some(spend.account_id.clone()),
                Some(spend.event_id.clone()),
                None,
            ),
            CostsOperation::RefundPaidLotV1 { refund } => (
                FinalizedOutcomeKind::CreditAdjustmentApplied,
                Some(refund.account_id.clone()),
                Some(refund.refund_rail_ref.clone()),
                None,
            ),
            CostsOperation::ReserveStoredValueV2 { reservation_id, account_id, .. } => (
                FinalizedOutcomeKind::ReservationCreated,
                Some(account_id.clone()),
                Some(reservation_id.clone()),
                None,
            ),
            CostsOperation::ReleaseStoredValueReservationV2 { reservation_id, .. } => (
                FinalizedOutcomeKind::ReservationReleased,
                None,
                Some(reservation_id.clone()),
                None,
            ),
            CostsOperation::ExpireStoredValueReservationV2 { reservation_id, .. } => (
                FinalizedOutcomeKind::ReservationExpired,
                None,
                Some(reservation_id.clone()),
                None,
            ),
            CostsOperation::SettleStoredValueReservationV2 { reservation_id, spend } => (
                FinalizedOutcomeKind::ReservationSettled,
                Some(spend.account_id.clone()),
                Some(format!("{reservation_id}:{}", spend.event_id)),
                None,
            ),
            CostsOperation::CreditGrant { account_id, grant_ref, .. } => (
                FinalizedOutcomeKind::CreditsAdded,
                Some(account_id.clone()),
                Some(grant_ref.clone()),
                None,
            ),
            CostsOperation::CreditReversal { account_id, reversal_ref, .. } => (
                FinalizedOutcomeKind::CreditsAdded,
                Some(account_id.clone()),
                Some(reversal_ref.clone()),
                None,
            ),
            CostsOperation::RecordSpendBatch { .. } => {
                (FinalizedOutcomeKind::SpendRecorded, None, None, None)
            }
            CostsOperation::SetAccountStatus { account_id, .. } => (
                FinalizedOutcomeKind::AccountStatusChanged,
                Some(account_id.clone()),
                None,
                None,
            ),
            CostsOperation::SetAccountStatusV1 { account_id, .. } => (FinalizedOutcomeKind::AccountStatusChanged, Some(account_id.clone()), None, None),
            CostsOperation::ReserveCredits { reservation_id, account_id, .. } => (
                FinalizedOutcomeKind::ReservationCreated,
                Some(account_id.clone()),
                Some(reservation_id.clone()),
                None,
            ),
            CostsOperation::ReserveCreditsV1 { reservation_id, quote, .. } => (FinalizedOutcomeKind::ReservationCreated, Some(quote.account_id.clone()), Some(reservation_id.clone()), None),
            CostsOperation::ReleaseReservation { reservation_id } => (
                FinalizedOutcomeKind::ReservationReleased,
                None,
                Some(reservation_id.clone()),
                None,
            ),
            CostsOperation::ExpireReservation { reservation_id, .. } => (
                FinalizedOutcomeKind::ReservationExpired,
                None,
                Some(reservation_id.clone()),
                None,
            ),
            CostsOperation::ReleaseReservationV1 { reservation_id, .. } => (
                FinalizedOutcomeKind::ReservationReleased, None, Some(reservation_id.clone()), None,
            ),
            CostsOperation::ExpireReservationV1 { reservation_id, .. } => (
                FinalizedOutcomeKind::ReservationExpired, None, Some(reservation_id.clone()), None,
            ),
            CostsOperation::SettleSpend { reservation_id, event_id, .. } => (
                FinalizedOutcomeKind::ReservationSettled,
                None,
                Some(format!("{reservation_id}:{event_id}")),
                None,
            ),
            CostsOperation::SettleSpendV1 { reservation_id, event_id, .. } => (FinalizedOutcomeKind::ReservationSettled, None, Some(format!("{reservation_id}:{event_id}")), None),
            CostsOperation::RegisterUntrackedSource { source_id, .. } => (
                FinalizedOutcomeKind::UntrackedSourceRegistered,
                None,
                Some(source_id.clone()),
                None,
            ),
            CostsOperation::RegisterUntrackedSourceV1 { source } => (
                FinalizedOutcomeKind::UntrackedSourceRegistered,
                None,
                Some(source.source_id.clone()),
                None,
            ),
            CostsOperation::CreditAdjustmentV1 { account_id, metadata, .. } => (
                FinalizedOutcomeKind::CreditAdjustmentApplied,
                Some(account_id.clone()),
                Some(metadata.reference.clone()),
                None,
            ),
            CostsOperation::StageRateCardEntries { change_set_id, .. } => (
                FinalizedOutcomeKind::RateCardEntriesStaged,
                None,
                None,
                Some(change_set_id.clone()),
            ),
            CostsOperation::ApplyRateCardChangeSet { change_set_id, .. } => (
                FinalizedOutcomeKind::RateCardApplied,
                None,
                None,
                Some(change_set_id.clone()),
            ),
            CostsOperation::StageRateCardChangeSetV1 { change_set, .. } => (FinalizedOutcomeKind::RateCardEntriesStaged, None, Some(change_set.approval_ref.clone()), Some(change_set.change_set_id.clone())),
            CostsOperation::ApplyRateCardChangeSetV1 { change_set, .. } => (FinalizedOutcomeKind::RateCardApplied, None, Some(change_set.approval_ref.clone()), Some(change_set.change_set_id.clone())),
        };
        let transaction_id = tx.digest();
        Self {
            schema_version: 1,
            outbox_event_id: format!("ledger:{transaction_id}"),
            event_type: kind.event_type(),
            transaction_id,
            payload_hash: transaction_id,
            finalized_at,
            kind,
            account_id,
            source_ref,
            rate_change_set_id,
            rate_card_completion: None,
        }
    }
}

impl FinalizedOutcomeKind {
    pub const fn from_mutation_kind(kind: LedgerMutationKind) -> Self {
        match kind {
            LedgerMutationKind::AccountOnboarded => Self::AccountOnboarded,
            LedgerMutationKind::BalanceChanged => Self::CreditAdjustmentApplied,
            LedgerMutationKind::SpendRecorded => Self::SpendRecorded,
            LedgerMutationKind::AccountStatusChanged => Self::AccountStatusChanged,
            LedgerMutationKind::ReservationChanged => Self::ReservationCreated,
            LedgerMutationKind::RateCardStaged => Self::RateCardEntriesStaged,
            LedgerMutationKind::RateCardApplied => Self::RateCardApplied,
            LedgerMutationKind::RateCardGlobalApplied => Self::RateCardApplied,
            LedgerMutationKind::RateCardCompleted => Self::RateCardCompleted,
            LedgerMutationKind::UntrackedSourceRegistered => Self::UntrackedSourceRegistered,
        }
    }
    /// Stable event-bus type for post-finality consumers. This output cannot
    /// authorize a debit and is intentionally distinct from chain payloads.
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::AccountRegistered | Self::AccountOnboarded => "ledger.account_registered",
            Self::WriterChanged => "ledger.writer_changed",
            Self::CreditsAdded | Self::CreditAdjustmentApplied => "ledger.balance_changed",
            Self::SpendRecorded => "ledger.spend_recorded",
            Self::AccountStatusChanged => "ledger.account_status_changed",
            Self::ReservationCreated => "ledger.reservation_created",
            Self::ReservationReleased => "ledger.reservation_released",
            Self::ReservationExpired => "ledger.reservation_expired",
            Self::ReservationSettled => "ledger.reservation_settled",
            Self::UntrackedSourceRegistered => "ledger.untracked_source_registered",
            Self::RateCardEntriesStaged => "ledger.rate_card_staged",
            Self::RateCardApplied => "ledger.rate_card_applied",
            Self::RateCardCompleted => "pricing.rate_card_updated",
        }
    }
}
