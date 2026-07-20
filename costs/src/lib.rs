//! Custodial, account-scoped credit accounting for Nunchi chains.
//!
//! The module is intentionally generic: it manages opaque credit accounts,
//! allowlisted backend writers, credits, and metered spend. Product-specific
//! event decoding and billing rails remain off-chain.

commonware_macros::stability_scope!(ALPHA {
mod db;
mod genesis;
mod grant;
mod ledger;
mod outcome;
pub mod stored_value;
#[cfg(feature = "rpc")]
pub mod rpc;
mod transaction;
mod types;
#[cfg(test)]
mod tests;

pub use db::CostsDB;
pub use genesis::CostsGenesis;
pub use grant::{
    campaign_grant_metadata, campaign_grant_ref, credit_grant_op, is_known_grant_reason,
    is_non_revenue_grant, periodic_grant_metadata, periodic_grant_ref, ALL_GRANT_REASONS,
    REASON_GOODWILL, REASON_INCLUDED_CREDITS, REASON_PROMOTION, REASON_TOPUP, REASON_TRIAL,
};
pub use ledger::{CostsError, CostsLedger};
pub use outcome::{FinalizedOutcomeKind, FinalizedOutcomeV1};
pub use stored_value::{
    CreditGrantV2, CreditLotKind, CreditTopupV2, LotAllocationV1, RefundPaidLotV1,
    StoredValueAccountReadV1, StoredValueError, StoredValueFinalityEventV1,
    StoredValueFinalityPayloadV1, StoredValueLedger, StoredValueLotReadV1,
    StoredValueReservationV1, StoredValueSpendV2,
};
pub use transaction::{CostsOperation, Transaction, TransactionPayload};
pub use types::{
    AccountReadV1, AdjustmentKind, AdjustmentMetadata, BalanceMutationDirection, LedgerMutationKind, LedgerMutationV1,
    QuoteRequestV1, QuoteV1, RateCardChangeSet, RateCardChangeSetV1, RateCardCompletionV1, RateCardEntry,
    Reservation, ReservationActionMetadataV1, ReservationStatus, CreditAccount, AccountProfile, AccountStatus, SpendRecordV1,
    StatusChangeMetadataV1, StatusHistoryEntry, UntrackedSourceV1, WriterRole,
};

/// Domain separator used for costs transaction signatures and state keys.
pub const COSTS_NAMESPACE: &[u8] = b"_NUNCHI_COSTS";
});
