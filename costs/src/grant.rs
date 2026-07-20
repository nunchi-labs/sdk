//! Credit ingress taxonomy — shared `source_reason` constants and idempotency helpers.
//!
//! See ADR-0004: grants use `CreditAdjustmentV1` with `metadata.reason_code`;
//! paid top-ups use `CreditTopup` with `reason_code = topup` in the journal.

use crate::{AdjustmentKind, AdjustmentMetadata, CostsOperation};

/// Application-defined included, trial, promotional, or goodwill credits.
pub const REASON_INCLUDED_CREDITS: &str = "included_credits";
pub const REASON_TRIAL: &str = "trial";
pub const REASON_PROMOTION: &str = "promotion";
pub const REASON_GOODWILL: &str = "goodwill";

/// Paid rail journal marker (op is `CreditTopup`, not adjustment).
pub const REASON_TOPUP: &str = "topup";

/// All known grant reason codes for validation and downstream warehouse partitioning.
pub const ALL_GRANT_REASONS: &[&str] = &[
    REASON_INCLUDED_CREDITS,
    REASON_TRIAL,
    REASON_PROMOTION,
    REASON_GOODWILL,
];

/// Returns true if `reason_code` is a recognized grant taxonomy value.
pub fn is_known_grant_reason(reason_code: &str) -> bool {
    ALL_GRANT_REASONS.contains(&reason_code)
}

/// Returns true if accounting export should exclude this grant from revenue recognition.
pub fn is_non_revenue_grant(reason_code: &str) -> bool {
    matches!(reason_code, REASON_TRIAL | REASON_PROMOTION | REASON_GOODWILL)
}

/// Idempotency key for an application's periodic grant.
pub fn periodic_grant_ref(account_id: &str, period: &str) -> String {
    format!("grant_{account_id}_{period}")
}

/// Idempotency key for a named campaign grant.
pub fn campaign_grant_ref(campaign_ref: &str, account_id: &str) -> String {
    format!("grant_{campaign_ref}_{account_id}")
}

/// Build metadata for a periodic included-credit grant.
pub fn periodic_grant_metadata(
    account_id: &str,
    period: &str,
    reason_code: &str,
    approval_ref: &str,
) -> AdjustmentMetadata {
    AdjustmentMetadata {
        reference: periodic_grant_ref(account_id, period),
        reason_code: reason_code.to_string(),
        period_ref: period.to_string(),
        approval_ref: approval_ref.to_string(),
        audit_ref: format!("periodic_grant:{period}"),
    }
}

/// Build grant metadata for a promotional credit.
pub fn campaign_grant_metadata(
    campaign_ref: &str,
    account_id: &str,
    reason_code: &str,
    approval_ref: &str,
    audit_ref: &str,
) -> AdjustmentMetadata {
    AdjustmentMetadata {
        reference: campaign_grant_ref(campaign_ref, account_id),
        reason_code: reason_code.to_string(),
        period_ref: format!("campaign:{campaign_ref}"),
        approval_ref: approval_ref.to_string(),
        audit_ref: audit_ref.to_string(),
    }
}

/// Construct a signed-ready grant operation.
pub fn credit_grant_op(
    account_id: String,
    credits: u64,
    metadata: AdjustmentMetadata,
) -> CostsOperation {
    CostsOperation::CreditAdjustmentV1 {
        kind: AdjustmentKind::Grant,
        account_id,
        credits,
        metadata,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_grant_ref_is_stable() {
        assert_eq!(
            periodic_grant_ref("bravo", "2026-07"),
            "grant_bravo_2026-07"
        );
    }

    #[test]
    fn non_revenue_classification_is_explicit() {
        assert!(is_non_revenue_grant(REASON_TRIAL));
        assert!(is_non_revenue_grant(REASON_PROMOTION));
        assert!(!is_non_revenue_grant(REASON_INCLUDED_CREDITS));
    }
}
