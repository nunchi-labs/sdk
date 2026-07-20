#![allow(clippy::cloned_ref_to_slice_refs)] // keeps rate-card fixture setup readable.

use std::collections::BTreeMap;

use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, StateError, StateStore};
use nunchi_crypto::PrivateKey;

use crate::{
    AdjustmentKind, AdjustmentMetadata, CostsDB, CostsError, CostsLedger, CostsOperation,
    CreditGrantV2, CreditTopupV2, FinalizedOutcomeKind, FinalizedOutcomeV1, LedgerMutationKind,
    RateCardEntry, RefundPaidLotV1, AccountStatus, ReservationActionMetadataV1, SpendRecordV1,
    StatusChangeMetadataV1, StoredValueSpendV2, Transaction, UntrackedSourceV1, WriterRole,
};

#[derive(Default)]
struct MemoryState {
    values: BTreeMap<Digest, Vec<u8>>,
}

fn canonical_changeset(mut change_set: crate::RateCardChangeSetV1, entries: &[RateCardEntry]) -> crate::RateCardChangeSetV1 {
    change_set.manifest_hash = change_set.expected_manifest_hash(entries);
    change_set
}

#[test]
fn stored_value_v2_commands_are_signed_scoped_and_persisted() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(701);
        let billing = PrivateKey::ed25519_from_seed(702);
        let adjustment = PrivateKey::ed25519_from_seed(703);
        let ingest = PrivateKey::ed25519_from_seed(704);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Billing, &address(&billing), true);
        state.set_writer(WriterRole::Adjustment, &address(&adjustment), true);
        state.set_writer(WriterRole::Ingest, &address(&ingest), true);

        {
            let mut ledger = CostsLedger::new(&mut state);
            ledger.apply_transaction(&Transaction::sign(&admin, 0, onboard("account_stored"))).await.unwrap();
            let topup = CreditTopupV2 {
                account_id: "account_stored".to_string(), rail_ref: "pi_stored_1".to_string(),
                amount_usd_cents: 10_000, base_credits: 800, bonus_credits: 88,
                purchased_at: 100, terms_version: "terms_v1".to_string(),
            };
            ledger.apply_transaction(&Transaction::sign(&billing, 0, CostsOperation::StoredValueTopupV2 { topup: topup.clone() })).await.unwrap();
            // An idempotent replay advances only its signer nonce; it cannot
            // make a second paid lot.
            ledger.apply_transaction(&Transaction::sign(&billing, 1, CostsOperation::StoredValueTopupV2 { topup })).await.unwrap();
            ledger.apply_transaction(&Transaction::sign(&adjustment, 0, CostsOperation::StoredValueGrantV2 {
                grant: CreditGrantV2 {
                    account_id: "account_stored".to_string(), reference: "grant_account_stored_2026_07".to_string(),
                    credits: 300, reason_code: "included_credits".to_string(), period_ref: "2026-07".to_string(),
                    issued_at: 100, expires_at: 200, approval_ref: "approval_grant_1".to_string(), audit_ref: "audit_grant_1".to_string(),
                },
            })).await.unwrap();
            ledger.apply_transaction(&Transaction::sign(&ingest, 0, CostsOperation::StoredValueSpendV2 {
                spend: StoredValueSpendV2 { event_id: "event_stored_1".to_string(), account_id: "account_stored".to_string(), credits: 350, occurred_at: 150 },
            })).await.unwrap();
            ledger.apply_transaction(&Transaction::sign(&adjustment, 1, CostsOperation::RefundPaidLotV1 {
                refund: RefundPaidLotV1 {
                    account_id: "account_stored".to_string(), rail_ref: "pi_stored_1".to_string(),
                    refund_rail_ref: "re_stored_1".to_string(), credits: 100, requested_at: 160,
                    reason_code: "charge.refunded".to_string(), approval_ref: "approval_refund_1".to_string(), audit_ref: "audit_refund_1".to_string(),
                },
            })).await.unwrap();
            // V2 is deliberately independent from the legacy aggregate path.
            assert_eq!(ledger.account("account_stored").await.unwrap().unwrap().available_credits, 0);
        }

        let ledger = CostsLedger::new(&mut state);
        let read = ledger.stored_value_account_read("account_stored", 160, "2026-07", 200).await.unwrap().unwrap();
        assert_eq!(read.paid_available_credits, 738);
        assert_eq!(read.refundable_paid_credits, 738);
        assert_eq!(read.grant_available_credits, 0);
        assert_eq!(read.included_period_consumed, 300);
        assert_eq!(ledger.stored_value_lots("account_stored").await.unwrap().unwrap().len(), 2);
        let events = ledger.stored_value_finality_events(0, 10).await.unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].event_key, "topup:pi_stored_1");
        assert_eq!(events[2].event_key, "spend:event_stored_1");
        assert_eq!(events[3].event_key, "refund:re_stored_1");
    });
}

#[test]
fn stored_value_v2_reservations_hold_lot_allocations_until_settlement() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(711);
        let billing = PrivateKey::ed25519_from_seed(712);
        let adjustment = PrivateKey::ed25519_from_seed(713);
        let ingest = PrivateKey::ed25519_from_seed(714);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Billing, &address(&billing), true);
        state.set_writer(WriterRole::Adjustment, &address(&adjustment), true);
        state.set_writer(WriterRole::Ingest, &address(&ingest), true);
        let mut ledger = CostsLedger::new(&mut state);
        ledger.apply_transaction(&Transaction::sign(&admin, 0, onboard("account_stored_reservation"))).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&billing, 0, CostsOperation::StoredValueTopupV2 {
            topup: CreditTopupV2 {
                account_id: "account_stored_reservation".to_string(), rail_ref: "pi_reservation_1".to_string(),
                amount_usd_cents: 1_000, base_credits: 100, bonus_credits: 0,
                purchased_at: 100, terms_version: "terms_v1".to_string(),
            },
        })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&adjustment, 0, CostsOperation::StoredValueGrantV2 {
            grant: CreditGrantV2 {
                account_id: "account_stored_reservation".to_string(), reference: "grant_reservation_1".to_string(),
                credits: 100, reason_code: "included_credits".to_string(), period_ref: "2026-07".to_string(),
                issued_at: 100, expires_at: 200, approval_ref: "approval_reservation_1".to_string(), audit_ref: "audit_reservation_1".to_string(),
            },
        })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&ingest, 0, CostsOperation::ReserveStoredValueV2 {
            reservation_id: "sv_reservation_1".to_string(), account_id: "account_stored_reservation".to_string(),
            credits: 150, expires_at: 200, reserved_at: 110,
        })).await.unwrap();
        let refund_while_reserved = ledger.apply_transaction(&Transaction::sign(&adjustment, 1, CostsOperation::RefundPaidLotV1 {
            refund: RefundPaidLotV1 {
                account_id: "account_stored_reservation".to_string(), rail_ref: "pi_reservation_1".to_string(),
                refund_rail_ref: "re_reserved_1".to_string(), credits: 1, requested_at: 111,
                reason_code: "charge.refunded".to_string(), approval_ref: "approval_refund_reserved".to_string(), audit_ref: "audit_refund_reserved".to_string(),
            },
        })).await.unwrap_err();
        assert!(matches!(refund_while_reserved, CostsError::Storage(_)));
        ledger.apply_transaction(&Transaction::sign(&ingest, 1, CostsOperation::SettleStoredValueReservationV2 {
            reservation_id: "sv_reservation_1".to_string(),
            spend: StoredValueSpendV2 { event_id: "event_reserved_1".to_string(), account_id: "account_stored_reservation".to_string(), credits: 150, occurred_at: 120 },
        })).await.unwrap();
        let read = ledger.stored_value_account_read("account_stored_reservation", 120, "2026-07", 200).await.unwrap().unwrap();
        assert_eq!(read.reserved_credits, 0);
        assert_eq!(read.grant_available_credits, 0);
        assert_eq!(read.paid_available_credits, 50);
    });
}

#[test]
fn v1_control_envelopes_bind_approval_status_and_quote_reservation() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(121);
        let billing = PrivateKey::ed25519_from_seed(122);
        let ingest = PrivateKey::ed25519_from_seed(123);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Billing, &address(&billing), true);
        state.set_writer(WriterRole::Ingest, &address(&ingest), true);
        let mut ledger = CostsLedger::new(&mut state);
        ledger.apply_transaction(&Transaction::sign(&admin, 0, onboard("account_v1"))).await.unwrap();
        let rate = RateCardEntry { account_id: String::new(), event_category: "creative.render".to_string(), task_key: String::new(), credits: 7, effective_at: 10, expires_at: 0, policy_version: "policy_v1".to_string(), rate_version: "rate_v1".to_string() };
        let envelope = crate::RateCardChangeSetV1 { change_set_id: "cs_v1".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_v1".to_string()], expected_target_count: 1, manifest_hash: "manifest_v1".to_string(), staged_entry_count: 0, approval_ref: "approval_v1".to_string(), audit_ref: "audit_v1".to_string(), activation_epoch: 1, applied: false };
        let envelope = canonical_changeset(envelope, &[rate.clone()]);
        ledger.apply_transaction(&Transaction::sign(&admin, 1, CostsOperation::StageRateCardChangeSetV1 { change_set: envelope.clone(), entries: vec![rate.clone()] })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&admin, 2, CostsOperation::ApplyRateCardChangeSetV1 { change_set: envelope.clone(), entries: vec![rate] })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&billing, 0, CostsOperation::CreditTopup { account_id: "account_v1".to_string(), credits: 20, rail_ref: "rail_v1".to_string() })).await.unwrap();
        let quote = ledger.quote_request(crate::QuoteRequestV1 { account_id: "account_v1".to_string(), event_category: "creative.render".to_string(), task_key: String::new(), quantity: 2, quoted_at: 11, expires_at: 20 }).await.unwrap().unwrap();
        ledger.apply_transaction(&Transaction::sign(&ingest, 0, CostsOperation::ReserveCreditsV1 { reservation_id: "reservation_v1".to_string(), quote: quote.clone(), lineage_ref: "lineage_v1".to_string(), reserved_at: 12 })).await.unwrap();
        let settlement_metadata = ReservationActionMetadataV1 { reason_code: "settled".to_string(), occurred_at: 13, approval_ref: "approval_settle".to_string(), audit_ref: "audit_settle".to_string() };
        let bad = ledger.apply_transaction(&Transaction::sign(&ingest, 1, CostsOperation::SettleSpendV1 { reservation_id: "reservation_v1".to_string(), event_id: "evt_v1".to_string(), event_category: "creative.render".to_string(), task_key: String::new(), quote_id: quote.quote_id.clone(), snapshot_hash: "wrong_hash".to_string(), lineage_ref: "lineage_v1".to_string(), metadata: settlement_metadata.clone() })).await.unwrap_err();
        assert!(matches!(bad, CostsError::PinnedRateMismatch { .. }));
        ledger.apply_transaction(&Transaction::sign(&ingest, 1, CostsOperation::SettleSpendV1 { reservation_id: "reservation_v1".to_string(), event_id: "evt_v1".to_string(), event_category: "creative.render".to_string(), task_key: String::new(), quote_id: quote.quote_id.clone(), snapshot_hash: quote.snapshot_hash.clone(), lineage_ref: "lineage_v1".to_string(), metadata: settlement_metadata })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&admin, 3, CostsOperation::SetAccountStatusV1 { account_id: "account_v1".to_string(), status: AccountStatus::Suspended, metadata: StatusChangeMetadataV1 { reason_code: "close_block".to_string(), changed_at: 14, approval_ref: "approval_status".to_string(), audit_ref: "audit_status".to_string() } })).await.unwrap();
        let history = ledger.status_history("account_v1").await.unwrap();
        assert_eq!(history.last().unwrap().approval_ref, "approval_status");
        assert_eq!(ledger.account("account_v1").await.unwrap().unwrap().reserved_credits, 0);
        let reservation = ledger.reservation("reservation_v1").await.unwrap().unwrap();
        assert_eq!(reservation.quote, quote);
        assert_eq!(reservation.lineage_ref, "lineage_v1");
        let status = ledger.journal(0, 100).await.unwrap().pop().unwrap();
        assert_eq!(status.reason_code, "close_block");
        assert_eq!(status.occurred_at, 14);
        assert_eq!(status.approval_ref, "approval_status");
        assert_eq!(status.audit_ref, "audit_status");
    });
}

#[test]
fn global_rates_propagate_to_existing_accounts_preserve_overrides_and_inherit_onboarding() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(201);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        let mut ledger = CostsLedger::new(&mut state);
        ledger.apply_transaction(&Transaction::sign(&admin, 0, onboard("account_global_a"))).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&admin, 1, onboard("account_global_b"))).await.unwrap();
        let global = RateCardEntry { account_id: String::new(), event_category: "sms.send".to_string(), task_key: String::new(), credits: 2, effective_at: 10, expires_at: 0, policy_version: "policy_global".to_string(), rate_version: "global_v1".to_string() };
        let changeset = crate::RateCardChangeSetV1 { change_set_id: "global_rates_1".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_global_a".to_string(), "account_global_b".to_string()], expected_target_count: 2, manifest_hash: "manifest_global_1".to_string(), staged_entry_count: 0, approval_ref: "approval_global_1".to_string(), audit_ref: "audit_global_1".to_string(), activation_epoch: 1, applied: false };
        let changeset = canonical_changeset(changeset, &[global.clone()]);
        ledger.apply_transaction(&Transaction::sign(&admin, 2, CostsOperation::StageRateCardChangeSetV1 { change_set: changeset.clone(), entries: vec![global.clone()] })).await.unwrap();
        let applied = ledger.apply_transaction_with_outcomes(&Transaction::sign(&admin, 3, CostsOperation::ApplyRateCardChangeSetV1 { change_set: changeset, entries: vec![global.clone()] })).await.unwrap();
        assert_eq!(applied.iter().filter(|entry| entry.kind == LedgerMutationKind::RateCardApplied && entry.account_id.starts_with("account_global_")).count(), 2);
        assert_eq!(ledger.quote("account_global_a", "sms.send", "", 11).await.unwrap().unwrap().credits_per_unit, 2);

        let scoped = RateCardEntry { account_id: "account_global_a".to_string(), credits: 9, rate_version: "account_v1".to_string(), ..global.clone() };
        let scoped_set = crate::RateCardChangeSetV1 { change_set_id: "account_override_1".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_global_a".to_string()], expected_target_count: 1, manifest_hash: "manifest_override_1".to_string(), staged_entry_count: 0, approval_ref: "approval_override_1".to_string(), audit_ref: "audit_override_1".to_string(), activation_epoch: 2, applied: false };
        let scoped_set = canonical_changeset(scoped_set, &[scoped.clone()]);
        ledger.apply_transaction(&Transaction::sign(&admin, 4, CostsOperation::StageRateCardChangeSetV1 { change_set: scoped_set.clone(), entries: vec![scoped] })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&admin, 5, CostsOperation::ApplyRateCardChangeSetV1 { change_set: scoped_set, entries: vec![RateCardEntry { account_id: "account_global_a".to_string(), credits: 9, rate_version: "account_v1".to_string(), ..global.clone() }] })).await.unwrap();
        let global_v2 = RateCardEntry { credits: 4, effective_at: 20, rate_version: "global_v2".to_string(), ..global };
        let second = crate::RateCardChangeSetV1 { change_set_id: "global_rates_2".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_global_b".to_string()], expected_target_count: 1, manifest_hash: "manifest_global_2".to_string(), staged_entry_count: 0, approval_ref: "approval_global_2".to_string(), audit_ref: "audit_global_2".to_string(), activation_epoch: 3, applied: false };
        let second = canonical_changeset(second, &[global_v2.clone()]);
        ledger.apply_transaction(&Transaction::sign(&admin, 6, CostsOperation::StageRateCardChangeSetV1 { change_set: second.clone(), entries: vec![global_v2.clone()] })).await.unwrap();
        let updated = ledger.apply_transaction_with_outcomes(&Transaction::sign(&admin, 7, CostsOperation::ApplyRateCardChangeSetV1 { change_set: second, entries: vec![global_v2] })).await.unwrap();
        assert!(updated.iter().any(|entry| entry.account_id == "account_global_b" && entry.rate.rate_version == "global_v2"));
        assert!(!updated.iter().any(|entry| entry.account_id == "account_global_a" && entry.rate.rate_version == "global_v2"));
        assert_eq!(ledger.quote("account_global_a", "sms.send", "", 21).await.unwrap().unwrap().credits_per_unit, 9);
        assert_eq!(ledger.quote("account_global_b", "sms.send", "", 21).await.unwrap().unwrap().credits_per_unit, 4);

        let inherited = ledger.apply_transaction_with_outcomes(&Transaction::sign(&admin, 8, CostsOperation::CreateAccount {
            account_id: "account_global_future".to_string(), external_ref: "onboard_account_global_future".to_string(),
            policy_ref: "policy_test_1".to_string(), cohort_ref: String::new(), created_at: 21,
        })).await.unwrap();
        assert!(inherited.iter().any(|entry| entry.kind == LedgerMutationKind::RateCardApplied && entry.account_id == "account_global_future" && entry.reason_code == "global_rate_inherited"));
        assert_eq!(ledger.quote("account_global_future", "sms.send", "", 21).await.unwrap().unwrap().credits_per_unit, 4);
    });
}

impl StateStore for MemoryState {
    async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.values.get(key).cloned())
    }

    fn set(&mut self, key: Digest, value: Vec<u8>) {
        self.values.insert(key, value);
    }

    fn remove(&mut self, key: Digest) {
        self.values.remove(&key);
    }
}

fn address(key: &PrivateKey) -> Address {
    Address::external(&key.public_key())
}

fn onboard(account_id: &str) -> CostsOperation {
    CostsOperation::CreateAccount {
        account_id: account_id.to_string(),
        external_ref: format!("onboard_{account_id}"),
        policy_ref: "policy_test_1".to_string(),
        cohort_ref: String::new(),
        created_at: 1,
    }
}

fn adjustment_metadata(reference: &str) -> AdjustmentMetadata {
    AdjustmentMetadata {
        reference: reference.to_string(),
        reason_code: "manual_correction".to_string(),
        period_ref: "period_2026_07".to_string(),
        approval_ref: "approval_test_1".to_string(),
        audit_ref: "audit_test_1".to_string(),
    }
}

#[test]
fn legacy_mutations_are_rejected_at_the_ledger_boundary() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(90);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        let mut ledger = CostsLedger::new(&mut state);
        let error = ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                0,
                CostsOperation::RegisterAccount { account_id: "account_legacy".to_string() },
            ))
            .await
            .unwrap_err();
        assert!(matches!(error, CostsError::LegacyOperationRejected { operation: "RegisterAccount" }));
        assert_eq!(ledger.db().nonce(&address(&admin)).await.unwrap(), 0);
        let legacy_operations = vec![
            CostsOperation::SetAccountStatus { account_id: "account_legacy".to_string(), status: AccountStatus::Suspended },
            CostsOperation::ReserveCredits { reservation_id: "reservation_legacy".to_string(), account_id: "account_legacy".to_string(), credits: 1, expires_at: 2 },
            CostsOperation::ReleaseReservation { reservation_id: "reservation_legacy".to_string() },
            CostsOperation::ExpireReservation { reservation_id: "reservation_legacy".to_string(), expired_at: 2 },
            CostsOperation::SettleSpend { reservation_id: "reservation_legacy".to_string(), event_id: "event_legacy".to_string(), event_category: "sms.send".to_string() },
            CostsOperation::StageRateCardEntries { change_set_id: "changeset_legacy".to_string(), expected_entry_count: 1, manifest_hash: "manifest_legacy".to_string(), entries: Vec::new() },
            CostsOperation::ApplyRateCardChangeSet { change_set_id: "changeset_legacy".to_string(), manifest_hash: "manifest_legacy".to_string(), entries: Vec::new() },
        ];
        for operation in legacy_operations {
            assert!(matches!(ledger.apply_transaction(&Transaction::sign(&admin, 0, operation)).await, Err(CostsError::LegacyOperationRejected { .. })));
        }
    });
}

#[test]
fn account_writer_scope_onboarding_collision_and_cohort_binding_are_enforced() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(91);
        let billing = PrivateKey::ed25519_from_seed(92);
        let ingest = PrivateKey::ed25519_from_seed(93);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Ingest, &address(&ingest), true);
        let mut ledger = CostsLedger::new(&mut state);
        ledger.apply_transaction(&Transaction::sign(&admin, 0, CostsOperation::CreateAccount {
            account_id: "account_scope_a".to_string(), external_ref: "onboard_scope_1".to_string(),
            policy_ref: "policy_1".to_string(), cohort_ref: "cohort_a".to_string(), created_at: 10,
        })).await.unwrap();
        let collision = ledger.apply_transaction(&Transaction::sign(&admin, 1, CostsOperation::CreateAccount {
            account_id: "account_scope_b".to_string(), external_ref: "onboard_scope_1".to_string(),
            policy_ref: "policy_1".to_string(), cohort_ref: "cohort_b".to_string(), created_at: 10,
        })).await.unwrap_err();
        assert!(matches!(collision, CostsError::IdempotencyConflict { .. }));
        ledger.apply_transaction(&Transaction::sign(&admin, 1, CostsOperation::SetAccountWriter {
            account_id: "account_scope_a".to_string(), role: WriterRole::Billing,
            writer: address(&billing), enabled: true,
        })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&billing, 0, CostsOperation::CreditTopup {
            account_id: "account_scope_a".to_string(), credits: 20, rail_ref: "rail_scope_a".to_string(),
        })).await.unwrap();
        let wrong_account = ledger.apply_transaction(&Transaction::sign(&billing, 1, CostsOperation::CreditTopup {
            account_id: "account_scope_b".to_string(), credits: 20, rail_ref: "rail_scope_b".to_string(),
        })).await.unwrap_err();
        assert!(matches!(wrong_account, CostsError::Unauthorized { role: WriterRole::Billing, .. }));
        let rate = RateCardEntry { account_id: String::new(), event_category: "creative.action".to_string(), task_key: String::new(), credits: 2, effective_at: 10, expires_at: 0, policy_version: "policy_a".to_string(), rate_version: "rate_a".to_string() };
        let changeset = crate::RateCardChangeSetV1 { change_set_id: "scope_rates".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_scope_a".to_string()], expected_target_count: 1, manifest_hash: "scope_manifest".to_string(), staged_entry_count: 0, approval_ref: "approval_scope".to_string(), audit_ref: "audit_scope".to_string(), activation_epoch: 1, applied: false };
        let changeset = canonical_changeset(changeset, &[rate.clone()]);
        ledger.apply_transaction(&Transaction::sign(&admin, 2, CostsOperation::StageRateCardChangeSetV1 { change_set: changeset.clone(), entries: vec![rate.clone()] })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&admin, 3, CostsOperation::ApplyRateCardChangeSetV1 { change_set: changeset, entries: vec![rate] })).await.unwrap();
        let mismatch = ledger.apply_transaction(&Transaction::sign(&ingest, 0, CostsOperation::RecordSpendBatch { records: vec![SpendRecordV1 {
            event_id: "evt_cohort_mismatch".to_string(), account_id: "account_scope_a".to_string(), event_category: "creative.action".to_string(), task_key: String::new(), quantity: 1, credits: 2, observed_at: 10, policy_version: "policy_a".to_string(), rate_version: "rate_a".to_string(), source_ref: "source_a".to_string(), lineage_ref: "lineage_a".to_string(), cohort_ref: "cohort_b".to_string(),
        }] })).await.unwrap_err();
        assert!(matches!(mismatch, CostsError::PinnedRateMismatch { .. }));
    });
}

#[test]
fn untracked_sources_never_debit_and_journal_and_finality_envelopes_are_complete() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(94);
        let billing = PrivateKey::ed25519_from_seed(95);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Billing, &address(&billing), true);
        let mut ledger = CostsLedger::new(&mut state);
        ledger.apply_transaction(&Transaction::sign(&admin, 0, onboard("account_journal"))).await.unwrap();
        let topup = Transaction::sign(&billing, 0, CostsOperation::CreditTopup { account_id: "account_journal".to_string(), credits: 25, rail_ref: "rail_journal".to_string() });
        let outcomes = ledger.apply_transaction_with_outcomes(&topup).await.unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].kind, LedgerMutationKind::BalanceChanged);
        assert!(outcomes[0].has_account);
        assert_eq!(outcomes[0].account.available_credits, 25);
        assert_eq!(ledger.journal(0, 10).await.unwrap().len(), 2);
        let source = UntrackedSourceV1 {
            source_id: "dark_complete_1".to_string(), reason_code: "shared_cost".to_string(),
            owner_ref: "owner_finance".to_string(), period_ref: "period_2026_07".to_string(),
            provenance_ref: "provider_invoice_1".to_string(), coverage_code: "cost_dark".to_string(),
            confidence_code: "unverified".to_string(), evidence_ref: "evidence_invoice_1".to_string(), cohort_ref: "cohort_dark_1".to_string(),
        };
        ledger.apply_transaction(&Transaction::sign(&admin, 1, CostsOperation::RegisterUntrackedSourceV1 { source })).await.unwrap();
        assert_eq!(ledger.account("account_journal").await.unwrap().unwrap().available_credits, 25);
        let journal = ledger.journal(0, 10).await.unwrap();
        assert!(journal.iter().any(|entry| entry.kind == LedgerMutationKind::UntrackedSourceRegistered && entry.has_untracked_source && entry.untracked_source.owner_ref == "owner_finance"));
        let finality = FinalizedOutcomeV1::from_finalized_mutation(&outcomes[0], topup.digest(), 1234);
        assert_eq!(finality.schema_version, 1);
        assert_eq!(finality.event_type, "ledger.balance_changed");
        assert_eq!(finality.account_id.as_deref(), Some("account_journal"));
        assert_eq!(finality.source_ref.as_deref(), Some("rail_journal"));
        assert_eq!(finality.finalized_at, 1234);
        assert!(finality.outbox_event_id.starts_with("ledger:"));
        let replay = ledger.apply_transaction_with_outcomes(&Transaction::sign(&billing, 1, CostsOperation::CreditTopup { account_id: "account_journal".to_string(), credits: 25, rail_ref: "rail_journal".to_string() })).await.unwrap();
        assert!(replay.is_empty(), "an idempotent replay has no journal mutation and no publishable finality event");
    });
}

#[test]
fn credits_are_idempotent_and_spend_is_deduplicated() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(1);
        let billing = PrivateKey::ed25519_from_seed(2);
        let ingest = PrivateKey::ed25519_from_seed(3);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Billing, &address(&billing), true);
        state.set_writer(WriterRole::Ingest, &address(&ingest), true);
        let mut ledger = CostsLedger::new(&mut state);

        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                0,
                onboard("account_demo"),
            ))
            .await
            .unwrap();
        let rate = RateCardEntry {
            account_id: String::new(),
            event_category: "creative.action".to_string(),
            task_key: String::new(),
            credits: 40,
            effective_at: 1,
            expires_at: 0,
            policy_version: "policy_spend_1".to_string(),
            rate_version: "rate_spend_1".to_string(),
        };
        let changeset = crate::RateCardChangeSetV1 { change_set_id: "changeset_spend_1".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_demo".to_string()], expected_target_count: 1, manifest_hash: "manifest_spend_1".to_string(), staged_entry_count: 0, approval_ref: "approval_spend_1".to_string(), audit_ref: "audit_spend_1".to_string(), activation_epoch: 1, applied: false };
        let changeset = canonical_changeset(changeset, &[rate.clone()]);
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                1,
                CostsOperation::StageRateCardChangeSetV1 { change_set: changeset.clone(),
                    entries: vec![rate.clone()],
                },
            ))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                2,
                CostsOperation::ApplyRateCardChangeSetV1 { change_set: changeset,
                    entries: vec![rate],
                },
            ))
            .await
            .unwrap();
        let topup = CostsOperation::CreditTopup {
            account_id: "account_demo".to_string(),
            credits: 100,
            rail_ref: "pi_demo_1".to_string(),
        };
        ledger
            .apply_transaction(&Transaction::sign(&billing, 0, topup.clone()))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(&billing, 1, topup))
            .await
            .unwrap();
        assert_eq!(ledger.account("account_demo").await.unwrap().unwrap().available_credits, 100);

        let spend = SpendRecordV1 {
            event_id: "usage:evt_1".to_string(),
            account_id: "account_demo".to_string(),
            event_category: "creative.action".to_string(),
            task_key: String::new(),
            quantity: 1,
            credits: 40,
            observed_at: 1,
            policy_version: "policy_spend_1".to_string(),
            rate_version: "rate_spend_1".to_string(),
            source_ref: "source_evt_1".to_string(),
            lineage_ref: "lineage_evt_1".to_string(),
            cohort_ref: String::new(),
        };
        ledger
            .apply_transaction(&Transaction::sign(
                &ingest,
                0,
                CostsOperation::RecordSpendBatch {
                    records: vec![spend.clone(), spend],
                },
            ))
            .await
            .unwrap();
        assert_eq!(ledger.account("account_demo").await.unwrap().unwrap().available_credits, 60);
    });
}

#[test]
fn suspended_account_rejects_spend_without_partial_debit() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(11);
        let billing = PrivateKey::ed25519_from_seed(12);
        let ingest = PrivateKey::ed25519_from_seed(13);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Billing, &address(&billing), true);
        state.set_writer(WriterRole::Ingest, &address(&ingest), true);
        let mut ledger = CostsLedger::new(&mut state);

        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                0,
                onboard("account_blocked"),
            ))
            .await
            .unwrap();
        let rate = RateCardEntry {
            account_id: String::new(),
            event_category: "creative.action".to_string(),
            task_key: String::new(),
            credits: 1,
            effective_at: 1,
            expires_at: 0,
            policy_version: "policy_blocked_1".to_string(),
            rate_version: "rate_blocked_1".to_string(),
        };
        let changeset = crate::RateCardChangeSetV1 { change_set_id: "changeset_blocked_1".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_blocked".to_string()], expected_target_count: 1, manifest_hash: "manifest_blocked_1".to_string(), staged_entry_count: 0, approval_ref: "approval_blocked".to_string(), audit_ref: "audit_blocked".to_string(), activation_epoch: 1, applied: false };
        let changeset = canonical_changeset(changeset, &[rate.clone()]);
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                1,
                CostsOperation::StageRateCardChangeSetV1 { change_set: changeset.clone(),
                    entries: vec![rate.clone()],
                },
            ))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                2,
                CostsOperation::ApplyRateCardChangeSetV1 { change_set: changeset,
                    entries: vec![rate],
                },
            ))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &billing,
                0,
                CostsOperation::CreditTopup {
                    account_id: "account_blocked".to_string(),
                    credits: 20,
                    rail_ref: "pi_demo_2".to_string(),
                },
            ))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                3,
                CostsOperation::SetAccountStatusV1 {
                    account_id: "account_blocked".to_string(),
                    status: AccountStatus::Suspended,
                    metadata: StatusChangeMetadataV1 { reason_code: "suspended".to_string(), changed_at: 2, approval_ref: "approval_blocked".to_string(), audit_ref: "audit_blocked".to_string() },
                },
            ))
            .await
            .unwrap();
        let error = ledger
            .apply_transaction(&Transaction::sign(
                &ingest,
                0,
                CostsOperation::RecordSpendBatch {
                    records: vec![SpendRecordV1 {
                        event_id: "usage:evt_2".to_string(),
                        account_id: "account_blocked".to_string(),
                        event_category: "creative.action".to_string(),
                        task_key: String::new(),
                        quantity: 1,
                        credits: 1,
                        observed_at: 1,
                        policy_version: "policy_blocked_1".to_string(),
                        rate_version: "rate_blocked_1".to_string(),
                        source_ref: "source_evt_2".to_string(),
                        lineage_ref: "lineage_evt_2".to_string(),
                        cohort_ref: String::new(),
                    }],
                },
            ))
            .await
            .unwrap_err();
        assert!(matches!(error, CostsError::AccountSuspended { .. }));
        assert_eq!(ledger.account("account_blocked").await.unwrap().unwrap().available_credits, 20);
    });
}

#[test]
fn reservations_adjustments_and_untracked_sources_preserve_balance_invariants() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(21);
        let billing = PrivateKey::ed25519_from_seed(22);
        let ingest = PrivateKey::ed25519_from_seed(23);
        let adjustment = PrivateKey::ed25519_from_seed(24);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Billing, &address(&billing), true);
        state.set_writer(WriterRole::Ingest, &address(&ingest), true);
        state.set_writer(WriterRole::Adjustment, &address(&adjustment), true);
        let mut ledger = CostsLedger::new(&mut state);

        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                0,
                onboard("account_reserve"),
            ))
            .await
            .unwrap();
        let rate = RateCardEntry { account_id: String::new(), event_category: "creative.render".to_string(), task_key: String::new(), credits: 1, effective_at: 1, expires_at: 0, policy_version: "policy_reserve".to_string(), rate_version: "rate_reserve".to_string() };
        let changeset = crate::RateCardChangeSetV1 { change_set_id: "reserve_rates".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_reserve".to_string()], expected_target_count: 1, manifest_hash: "reserve_manifest".to_string(), staged_entry_count: 0, approval_ref: "reserve_approval".to_string(), audit_ref: "reserve_audit".to_string(), activation_epoch: 1, applied: false };
        let changeset = canonical_changeset(changeset, &[rate.clone()]);
        ledger.apply_transaction(&Transaction::sign(&admin, 1, CostsOperation::StageRateCardChangeSetV1 { change_set: changeset.clone(), entries: vec![rate.clone()] })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&admin, 2, CostsOperation::ApplyRateCardChangeSetV1 { change_set: changeset, entries: vec![rate] })).await.unwrap();
        let quote_one = ledger.quote_request(crate::QuoteRequestV1 { account_id: "account_reserve".to_string(), event_category: "creative.render".to_string(), task_key: String::new(), quantity: 30, quoted_at: 2, expires_at: 1_800_000_000 }).await.unwrap().unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &billing,
                0,
                CostsOperation::CreditTopup {
                    account_id: "account_reserve".to_string(),
                    credits: 100,
                    rail_ref: "pi_reserve_1".to_string(),
                },
            ))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &ingest,
                0,
                CostsOperation::ReserveCreditsV1 {
                    reservation_id: "reservation_1".to_string(),
                    quote: quote_one,
                    lineage_ref: "lineage_reserve_1".to_string(), reserved_at: 3,
                },
            ))
            .await
            .unwrap();
        let account = ledger.account("account_reserve").await.unwrap().unwrap();
        assert_eq!((account.available_credits, account.reserved_credits), (70, 30));

        ledger
            .apply_transaction(&Transaction::sign(
                &ingest,
                1,
                CostsOperation::ReleaseReservationV1 {
                    reservation_id: "reservation_1".to_string(),
                    metadata: ReservationActionMetadataV1 { reason_code: "released".to_string(), occurred_at: 4, approval_ref: "reserve_approval".to_string(), audit_ref: "reserve_audit".to_string() },
                },
            ))
            .await
            .unwrap();
        let account = ledger.account("account_reserve").await.unwrap().unwrap();
        assert_eq!((account.available_credits, account.reserved_credits), (100, 0));

        let quote_two = ledger.quote_request(crate::QuoteRequestV1 { account_id: "account_reserve".to_string(), event_category: "creative.render".to_string(), task_key: String::new(), quantity: 25, quoted_at: 5, expires_at: 1_800_000_001 }).await.unwrap().unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &ingest,
                2,
                CostsOperation::ReserveCreditsV1 {
                    reservation_id: "reservation_2".to_string(),
                    quote: quote_two.clone(), lineage_ref: "lineage_reserve_2".to_string(), reserved_at: 6,
                },
            ))
            .await
            .unwrap();
        let settle = CostsOperation::SettleSpendV1 {
            reservation_id: "reservation_2".to_string(),
            event_id: "usage:reserved_event_1".to_string(),
            event_category: "creative.render".to_string(),
            task_key: String::new(), quote_id: quote_two.quote_id.clone(), snapshot_hash: quote_two.snapshot_hash.clone(), lineage_ref: "lineage_reserve_2".to_string(), metadata: ReservationActionMetadataV1 { reason_code: "settled".to_string(), occurred_at: 7, approval_ref: "reserve_approval".to_string(), audit_ref: "reserve_audit".to_string() },
        };
        ledger
            .apply_transaction(&Transaction::sign(&ingest, 3, settle.clone()))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(&ingest, 4, settle))
            .await
            .unwrap();
        let account = ledger.account("account_reserve").await.unwrap().unwrap();
        assert_eq!((account.available_credits, account.reserved_credits), (75, 0));

        let grant = CostsOperation::CreditAdjustmentV1 {
            kind: AdjustmentKind::Grant,
            account_id: "account_reserve".to_string(),
            credits: 10,
            metadata: adjustment_metadata("grant_welcome_1"),
        };
        ledger
            .apply_transaction(&Transaction::sign(&adjustment, 0, grant.clone()))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(&adjustment, 1, grant))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &adjustment,
                2,
                CostsOperation::CreditAdjustmentV1 {
                    kind: AdjustmentKind::Reversal,
                    account_id: "account_reserve".to_string(),
                    credits: 5,
                    metadata: adjustment_metadata("reversal_event_1"),
                },
            ))
            .await
            .unwrap();
        assert_eq!(ledger.account("account_reserve").await.unwrap().unwrap().available_credits, 80);

        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                3,
                CostsOperation::RegisterUntrackedSourceV1 { source: UntrackedSourceV1 {
                    source_id: "source_dark_1".to_string(),
                    reason_code: "shared_cost".to_string(),
                    owner_ref: "owner_finance_1".to_string(), period_ref: "period_2026_07".to_string(),
                    provenance_ref: "source_shared_1".to_string(), coverage_code: "cost_dark".to_string(),
                    confidence_code: "unverified".to_string(), evidence_ref: "evidence_1".to_string(), cohort_ref: String::new(),
                } },
            ))
            .await
            .unwrap();
        assert_eq!(ledger.account("account_reserve").await.unwrap().unwrap().available_credits, 80);
    });
}

#[test]
fn rate_change_sets_are_atomic_and_use_scoped_precedence() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(31);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        let mut ledger = CostsLedger::new(&mut state);

        let global_category = RateCardEntry {
            account_id: String::new(),
            event_category: "creative.render".to_string(),
            task_key: String::new(),
            credits: 2,
            effective_at: 100,
            expires_at: 0,
            policy_version: "policy_1".to_string(),
            rate_version: "rate_1".to_string(),
        };
        let global_task = RateCardEntry {
            task_key: "image_hd".to_string(),
            credits: 5,
            rate_version: "rate_2".to_string(),
            ..global_category.clone()
        };
        let account_category = RateCardEntry {
            account_id: "account_priority".to_string(),
            credits: 7,
            rate_version: "rate_3".to_string(),
            ..global_category.clone()
        };
        let all_entries = vec![
            global_category.clone(),
            global_task.clone(),
            account_category.clone(),
        ];
        let change_one = crate::RateCardChangeSetV1 { change_set_id: "changeset_1".to_string(), expected_entry_count: 3, target_account_ids: vec!["account_priority".to_string()], expected_target_count: 1, manifest_hash: "manifest_1".to_string(), staged_entry_count: 0, approval_ref: "approval_1".to_string(), audit_ref: "audit_1".to_string(), activation_epoch: 1, applied: false };
        let change_one = canonical_changeset(change_one, &all_entries);
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                0,
                CostsOperation::StageRateCardChangeSetV1 { change_set: change_one.clone(),
                    entries: vec![global_category.clone(), global_task.clone()],
                },
            ))
            .await
            .unwrap();
        let error = ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                1,
                CostsOperation::ApplyRateCardChangeSetV1 { change_set: change_one.clone(),
                    entries: all_entries.clone(),
                },
            ))
            .await
            .unwrap_err();
        assert!(matches!(error, CostsError::RateChangeSetIncomplete { .. }));

        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                1,
                CostsOperation::StageRateCardChangeSetV1 { change_set: change_one.clone(),
                    entries: vec![account_category.clone()],
                },
            ))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                2,
                CostsOperation::ApplyRateCardChangeSetV1 { change_set: change_one,
                    entries: all_entries,
                },
            ))
            .await
            .unwrap();

        assert_eq!(
            ledger
                .active_rate("account_priority", "creative.render", "image_hd", 100)
                .await
                .unwrap()
                .unwrap()
                .credits,
            7
        );
        assert_eq!(
            ledger
                .active_rate("account_new", "creative.render", "image_hd", 100)
                .await
                .unwrap()
                .unwrap()
                .credits,
            5
        );

        let account_task = RateCardEntry {
            task_key: "image_hd".to_string(),
            credits: 9,
            rate_version: "rate_4".to_string(),
            ..account_category
        };
        let change_two = crate::RateCardChangeSetV1 { change_set_id: "changeset_2".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_priority".to_string()], expected_target_count: 1, manifest_hash: "manifest_2".to_string(), staged_entry_count: 0, approval_ref: "approval_2".to_string(), audit_ref: "audit_2".to_string(), activation_epoch: 2, applied: false };
        let change_two = canonical_changeset(change_two, &[account_task.clone()]);
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                3,
                CostsOperation::StageRateCardChangeSetV1 { change_set: change_two.clone(),
                    entries: vec![account_task.clone()],
                },
            ))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                4,
                CostsOperation::ApplyRateCardChangeSetV1 { change_set: change_two,
                    entries: vec![account_task],
                },
            ))
            .await
            .unwrap();
        assert_eq!(
            ledger
                .active_rate("account_priority", "creative.render", "image_hd", 100)
                .await
                .unwrap()
                .unwrap()
                .credits,
            9
        );
    });
}

#[test]
fn suspension_blocks_a_preexisting_reservation_from_settling() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(51);
        let billing = PrivateKey::ed25519_from_seed(52);
        let ingest = PrivateKey::ed25519_from_seed(53);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Billing, &address(&billing), true);
        state.set_writer(WriterRole::Ingest, &address(&ingest), true);
        let mut ledger = CostsLedger::new(&mut state);
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                0,
                onboard("account_hold"),
            ))
            .await
            .unwrap();
        let rate = RateCardEntry { account_id: String::new(), event_category: "creative.render".to_string(), task_key: String::new(), credits: 1, effective_at: 1, expires_at: 0, policy_version: "policy_hold".to_string(), rate_version: "rate_hold".to_string() };
        let changeset = crate::RateCardChangeSetV1 { change_set_id: "hold_rates".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_hold".to_string()], expected_target_count: 1, manifest_hash: "hold_manifest".to_string(), staged_entry_count: 0, approval_ref: "hold_approval".to_string(), audit_ref: "hold_audit".to_string(), activation_epoch: 1, applied: false };
        let changeset = canonical_changeset(changeset, &[rate.clone()]);
        ledger.apply_transaction(&Transaction::sign(&admin, 1, CostsOperation::StageRateCardChangeSetV1 { change_set: changeset.clone(), entries: vec![rate.clone()] })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&admin, 2, CostsOperation::ApplyRateCardChangeSetV1 { change_set: changeset, entries: vec![rate] })).await.unwrap();
        let quote = ledger.quote_request(crate::QuoteRequestV1 { account_id: "account_hold".to_string(), event_category: "creative.render".to_string(), task_key: String::new(), quantity: 20, quoted_at: 2, expires_at: 1_900_000_000 }).await.unwrap().unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &billing,
                0,
                CostsOperation::CreditTopup {
                    account_id: "account_hold".to_string(),
                    credits: 30,
                    rail_ref: "pi_hold_1".to_string(),
                },
            ))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &ingest,
                0,
                CostsOperation::ReserveCreditsV1 {
                    reservation_id: "hold_1".to_string(),
                    quote: quote.clone(), lineage_ref: "lineage_hold".to_string(), reserved_at: 3,
                },
            ))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                3,
                CostsOperation::SetAccountStatusV1 {
                    account_id: "account_hold".to_string(),
                    status: AccountStatus::Suspended,
                    metadata: StatusChangeMetadataV1 { reason_code: "suspended".to_string(), changed_at: 4, approval_ref: "hold_approval".to_string(), audit_ref: "hold_audit".to_string() },
                },
            ))
            .await
            .unwrap();
        let error = ledger
            .apply_transaction(&Transaction::sign(
                &ingest,
                1,
                CostsOperation::SettleSpendV1 {
                    reservation_id: "hold_1".to_string(),
                    event_id: "usage:hold_1".to_string(),
                    event_category: "creative.render".to_string(),
                    task_key: String::new(), quote_id: quote.quote_id.clone(), snapshot_hash: quote.snapshot_hash.clone(), lineage_ref: "lineage_hold".to_string(), metadata: ReservationActionMetadataV1 { reason_code: "settled".to_string(), occurred_at: 5, approval_ref: "hold_approval".to_string(), audit_ref: "hold_audit".to_string() },
                },
            ))
            .await
            .unwrap_err();
        assert!(matches!(error, CostsError::ReservationAccountSuspended { .. }));
        let account = ledger.account("account_hold").await.unwrap().unwrap();
        assert_eq!((account.available_credits, account.reserved_credits), (10, 20));
        assert_eq!(
            ledger.reservation("hold_1").await.unwrap().unwrap().status,
            crate::ReservationStatus::Active
        );
    });
}

#[test]
fn changed_idempotency_replay_and_bad_pinned_rate_are_rejected() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(61);
        let billing = PrivateKey::ed25519_from_seed(62);
        let ingest = PrivateKey::ed25519_from_seed(63);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Billing, &address(&billing), true);
        state.set_writer(WriterRole::Ingest, &address(&ingest), true);
        state.set_writer(WriterRole::Adjustment, &address(&admin), true);
        let mut ledger = CostsLedger::new(&mut state);
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                0,
                onboard("account_pin"),
            ))
            .await
            .unwrap();
        let rate = RateCardEntry {
            account_id: String::new(), event_category: "creative.render".to_string(),
            task_key: String::new(), credits: 3, effective_at: 10, expires_at: 0,
            policy_version: "policy_pin_1".to_string(), rate_version: "rate_pin_1".to_string(),
        };
        let changeset = crate::RateCardChangeSetV1 { change_set_id: "cs_pin".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_pin".to_string()], expected_target_count: 1, manifest_hash: "manifest_pin".to_string(), staged_entry_count: 0, approval_ref: "approval_pin".to_string(), audit_ref: "audit_pin".to_string(), activation_epoch: 1, applied: false };
        let changeset = canonical_changeset(changeset, &[rate.clone()]);
        for (nonce, operation) in [
            (1, CostsOperation::StageRateCardChangeSetV1 { change_set: changeset.clone(), entries: vec![rate.clone()] }),
            (2, CostsOperation::ApplyRateCardChangeSetV1 { change_set: changeset, entries: vec![rate] }),
        ] {
            ledger.apply_transaction(&Transaction::sign(&admin, nonce, operation)).await.unwrap();
        }
        ledger.apply_transaction(&Transaction::sign(&billing, 0, CostsOperation::CreditTopup { account_id: "account_pin".to_string(), credits: 10, rail_ref: "pi_pin".to_string() })).await.unwrap();
        let changed_topup = ledger.apply_transaction(&Transaction::sign(&billing, 1, CostsOperation::CreditTopup { account_id: "account_pin".to_string(), credits: 9, rail_ref: "pi_pin".to_string() })).await.unwrap_err();
        assert!(matches!(changed_topup, CostsError::IdempotencyConflict { .. }));
        let bad = SpendRecordV1 { event_id: "usage:pin_1".to_string(), account_id: "account_pin".to_string(), event_category: "creative.render".to_string(), task_key: String::new(), quantity: 1, credits: 2, observed_at: 10, policy_version: "policy_pin_1".to_string(), rate_version: "rate_pin_1".to_string(), source_ref: "source_pin".to_string(), lineage_ref: "lineage_pin".to_string(), cohort_ref: "cohort_1".to_string() };
        let error = ledger.apply_transaction(&Transaction::sign(&ingest, 0, CostsOperation::RecordSpendBatch { records: vec![bad] })).await.unwrap_err();
        assert!(matches!(error, CostsError::PinnedRateMismatch { .. }));
        let valid = SpendRecordV1 { event_id: "usage:pin_duplicate".to_string(), account_id: "account_pin".to_string(), event_category: "creative.render".to_string(), task_key: String::new(), quantity: 1, credits: 3, observed_at: 10, policy_version: "policy_pin_1".to_string(), rate_version: "rate_pin_1".to_string(), source_ref: "source_pin".to_string(), lineage_ref: "lineage_pin".to_string(), cohort_ref: String::new() };
        let mut changed = valid.clone();
        changed.credits = 4;
        let error = ledger.apply_transaction(&Transaction::sign(&ingest, 0, CostsOperation::RecordSpendBatch { records: vec![valid, changed] })).await.unwrap_err();
        assert!(matches!(error, CostsError::IdempotencyConflict { .. }));
        let metadata = crate::AdjustmentMetadata { reference: "adjustment_pin_1".to_string(), reason_code: "correction".to_string(), period_ref: "period_202607".to_string(), approval_ref: "approval_1".to_string(), audit_ref: "audit_1".to_string() };
        ledger.apply_transaction(&Transaction::sign(&admin, 3, CostsOperation::CreditAdjustmentV1 { kind: crate::AdjustmentKind::Grant, account_id: "account_pin".to_string(), credits: 2, metadata: metadata.clone() })).await.unwrap();
        let error = ledger.apply_transaction(&Transaction::sign(&admin, 4, CostsOperation::CreditAdjustmentV1 { kind: crate::AdjustmentKind::Reversal, account_id: "account_pin".to_string(), credits: 2, metadata })).await.unwrap_err();
        assert!(matches!(error, CostsError::IdempotencyConflict { .. }));
        let correction = Transaction::sign(&admin, 4, CostsOperation::CreditAdjustmentV1 {
            kind: crate::AdjustmentKind::Reversal,
            account_id: "account_pin".to_string(),
            credits: 1,
            metadata: crate::AdjustmentMetadata {
                reference: "adjustment_pin_2".to_string(),
                reason_code: "correction".to_string(),
                period_ref: "period_202607".to_string(),
                approval_ref: "approval_2".to_string(),
                audit_ref: "audit_2".to_string(),
            },
        });
        ledger.apply_transaction(&correction).await.unwrap();
        assert_eq!(ledger.account("account_pin").await.unwrap().unwrap().available_credits, 11);
        let mutation = ledger.journal(0, 100).await.unwrap().pop().unwrap();
        assert_eq!(
            FinalizedOutcomeV1::from_finalized_mutation(&mutation, correction.digest(), 20).kind,
            FinalizedOutcomeKind::CreditAdjustmentApplied
        );
    });
}

#[test]
fn onboarding_rotation_private_reads_and_expiry_release_are_deterministic() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(71);
        let replacement = PrivateKey::ed25519_from_seed(72);
        let billing = PrivateKey::ed25519_from_seed(73);
        let ingest = PrivateKey::ed25519_from_seed(74);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Billing, &address(&billing), true);
        state.set_writer(WriterRole::Ingest, &address(&ingest), true);
        let mut ledger = CostsLedger::new(&mut state);
        let onboard = CostsOperation::CreateAccount {
            account_id: "account_program".to_string(),
            external_ref: "onboarding_program_1".to_string(),
            policy_ref: "policy_fixture_1".to_string(),
            cohort_ref: "cohort_fixture_1".to_string(),
            created_at: 100,
        };
        ledger
            .apply_transaction(&Transaction::sign(&admin, 0, onboard.clone()))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(&admin, 1, onboard))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                2,
                CostsOperation::RotateAdmin {
                    replacement: address(&replacement),
                },
            ))
            .await
            .unwrap();
        let rejected = ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                3,
                CostsOperation::SetAccountStatusV1 {
                    account_id: "account_program".to_string(),
                    status: AccountStatus::Suspended,
                    metadata: StatusChangeMetadataV1 { reason_code: "suspended".to_string(), changed_at: 110, approval_ref: "approval_program".to_string(), audit_ref: "audit_program".to_string() },
                },
            ))
            .await
            .unwrap_err();
        assert!(matches!(rejected, CostsError::Unauthorized { .. }));
        let rate = RateCardEntry {
            account_id: String::new(),
            event_category: "creative.render".to_string(),
            task_key: String::new(),
            credits: 5,
            effective_at: 100,
            expires_at: 150,
            policy_version: "policy_program_1".to_string(),
            rate_version: "rate_program_1".to_string(),
        };
        let changeset = crate::RateCardChangeSetV1 { change_set_id: "changeset_program_1".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_program".to_string()], expected_target_count: 1, manifest_hash: "manifest_program_1".to_string(), staged_entry_count: 0, approval_ref: "approval_program".to_string(), audit_ref: "audit_program".to_string(), activation_epoch: 1, applied: false };
        let changeset = canonical_changeset(changeset, &[rate.clone()]);
        ledger
            .apply_transaction(&Transaction::sign(
                &replacement,
                0,
                CostsOperation::StageRateCardChangeSetV1 { change_set: changeset.clone(),
                    entries: vec![rate.clone()],
                },
            ))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &replacement,
                1,
                CostsOperation::ApplyRateCardChangeSetV1 { change_set: changeset,
                    entries: vec![rate],
                },
            ))
            .await
            .unwrap();
        let quote = ledger.quote_request(crate::QuoteRequestV1 { account_id: "account_program".to_string(), event_category: "creative.render".to_string(), task_key: String::new(), quantity: 1, quoted_at: 110, expires_at: 140 }).await.unwrap().unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &billing,
                0,
                CostsOperation::CreditTopup {
                    account_id: "account_program".to_string(),
                    credits: 10,
                    rail_ref: "pi_program_1".to_string(),
                },
            ))
            .await
            .unwrap();
        let read = ledger.account_read("account_program").await.unwrap().unwrap();
        assert_eq!(read.profile.policy_ref, "policy_fixture_1");
        assert_eq!(read.profile.cohort_ref, "cohort_fixture_1");
        assert_eq!(ledger.status_history("account_program").await.unwrap().len(), 1);
        assert_eq!(
            ledger
                .quote("account_program", "creative.render", "", 100)
                .await
                .unwrap()
                .unwrap()
                .credits_per_unit,
            5
        );
        assert!(
            ledger
                .quote("account_program", "creative.render", "", 150)
                .await
                .unwrap()
                .is_none()
        );
        ledger
            .apply_transaction(&Transaction::sign(
                &ingest,
                0,
                CostsOperation::ReserveCreditsV1 {
                    reservation_id: "reservation_program_1".to_string(),
                    quote: quote.clone(), lineage_ref: "lineage_program".to_string(), reserved_at: 111,
                },
            ))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(
                &ingest,
                1,
                CostsOperation::ExpireReservationV1 {
                    reservation_id: "reservation_program_1".to_string(),
                    metadata: ReservationActionMetadataV1 { reason_code: "expired".to_string(), occurred_at: 140, approval_ref: "approval_program".to_string(), audit_ref: "audit_program".to_string() },
                },
            ))
            .await
            .unwrap();
        let account = ledger.account("account_program").await.unwrap().unwrap();
        assert_eq!((account.available_credits, account.reserved_credits), (10, 0));
        assert_eq!(
            ledger
                .reservation("reservation_program_1")
                .await
                .unwrap()
                .unwrap()
                .status,
            crate::ReservationStatus::Expired
        );
        let error = ledger
            .apply_transaction(&Transaction::sign(
                &ingest,
                2,
                CostsOperation::SettleSpendV1 {
                    reservation_id: "reservation_program_1".to_string(),
                    event_id: "usage:expired_program_1".to_string(),
                    event_category: "creative.render".to_string(),
                    task_key: String::new(), quote_id: quote.quote_id.clone(), snapshot_hash: quote.snapshot_hash.clone(), lineage_ref: "lineage_program".to_string(), metadata: ReservationActionMetadataV1 { reason_code: "settled".to_string(), occurred_at: 141, approval_ref: "approval_program".to_string(), audit_ref: "audit_program".to_string() },
                },
            ))
            .await
            .unwrap_err();
        assert!(matches!(error, CostsError::ReservationNotActive { .. } | CostsError::ReservationExpired { .. }));
    });
}

#[test]
fn replay_is_a_nonce_consuming_noop_without_duplicate_journal_entries() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(111);
        let billing = PrivateKey::ed25519_from_seed(112);
        let ingest = PrivateKey::ed25519_from_seed(113);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Billing, &address(&billing), true);
        state.set_writer(WriterRole::Ingest, &address(&ingest), true);
        let mut ledger = CostsLedger::new(&mut state);
        ledger.apply_transaction(&Transaction::sign(&admin, 0, onboard("account_replay"))).await.unwrap();
        let rate = RateCardEntry { account_id: String::new(), event_category: "sms.send".to_string(), task_key: String::new(), credits: 2, effective_at: 1, expires_at: 0, policy_version: "policy_replay".to_string(), rate_version: "rate_replay".to_string() };
        let changeset = crate::RateCardChangeSetV1 { change_set_id: "cs_replay".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_replay".to_string()], expected_target_count: 1, manifest_hash: "manifest_replay".to_string(), staged_entry_count: 0, approval_ref: "approval_replay".to_string(), audit_ref: "audit_replay".to_string(), activation_epoch: 1, applied: false };
        let changeset = canonical_changeset(changeset, &[rate.clone()]);
        ledger.apply_transaction(&Transaction::sign(&admin, 1, CostsOperation::StageRateCardChangeSetV1 { change_set: changeset.clone(), entries: vec![rate.clone()] })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&admin, 2, CostsOperation::ApplyRateCardChangeSetV1 { change_set: changeset, entries: vec![rate] })).await.unwrap();
        let first = CostsOperation::CreditTopup { account_id: "account_replay".to_string(), credits: 20, rail_ref: "rail_replay".to_string() };
        ledger.apply_transaction(&Transaction::sign(&billing, 0, first.clone())).await.unwrap();
        let before_topup_replay = ledger.journal(0, 100).await.unwrap().len();
        assert!(ledger.apply_transaction_with_outcomes(&Transaction::sign(&billing, 1, first)).await.unwrap().is_empty());
        assert_eq!(ledger.journal(0, 100).await.unwrap().len(), before_topup_replay);

        let spend = SpendRecordV1 { event_id: "evt_replay".to_string(), account_id: "account_replay".to_string(), event_category: "sms.send".to_string(), task_key: String::new(), quantity: 1, credits: 2, observed_at: 2, policy_version: "policy_replay".to_string(), rate_version: "rate_replay".to_string(), source_ref: "source_replay".to_string(), lineage_ref: "lineage_replay".to_string(), cohort_ref: String::new() };
        let outcomes = ledger.apply_transaction_with_outcomes(&Transaction::sign(&ingest, 0, CostsOperation::RecordSpendBatch { records: vec![spend.clone(), spend.clone()] })).await.unwrap();
        assert_eq!(outcomes.len(), 1, "in-batch exact duplicate has one debit and one journal event");
        let before_batch_replay = ledger.journal(0, 100).await.unwrap().len();
        assert!(ledger.apply_transaction_with_outcomes(&Transaction::sign(&ingest, 1, CostsOperation::RecordSpendBatch { records: vec![spend] })).await.unwrap().is_empty());
        assert_eq!(ledger.journal(0, 100).await.unwrap().len(), before_batch_replay);
        let conflict = ledger.apply_transaction(&Transaction::sign(&ingest, 2, CostsOperation::RecordSpendBatch { records: vec![SpendRecordV1 { credits: 4, quantity: 2, ..SpendRecordV1 { event_id: "evt_replay".to_string(), account_id: "account_replay".to_string(), event_category: "sms.send".to_string(), task_key: String::new(), quantity: 1, credits: 2, observed_at: 2, policy_version: "policy_replay".to_string(), rate_version: "rate_replay".to_string(), source_ref: "source_replay".to_string(), lineage_ref: "lineage_replay".to_string(), cohort_ref: String::new() } }] })).await.unwrap_err();
        assert!(matches!(conflict, CostsError::IdempotencyConflict { .. }));
    });
}

#[test]
fn rate_history_resolves_historical_revision_without_repricing() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(114);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        let mut ledger = CostsLedger::new(&mut state);
        let early = RateCardEntry { account_id: String::new(), event_category: "creative.render".to_string(), task_key: String::new(), credits: 3, effective_at: 10, expires_at: 0, policy_version: "policy_a".to_string(), rate_version: "global_v1".to_string() };
        let later = RateCardEntry { credits: 5, effective_at: 20, rate_version: "global_v2".to_string(), ..early.clone() };
        let scoped = RateCardEntry { account_id: "account_history".to_string(), credits: 7, effective_at: 15, rate_version: "account_v1".to_string(), ..early.clone() };
        for (nonce, id, entry) in [(0, "history_1", early.clone()), (2, "history_2", later), (4, "history_3", scoped)] {
            let targets = if entry.account_id.is_empty() { Vec::new() } else { vec![entry.account_id.clone()] };
            let change_set = crate::RateCardChangeSetV1 { change_set_id: id.to_string(), expected_entry_count: 1, expected_target_count: targets.len() as u16, target_account_ids: targets, manifest_hash: "placeholder".to_string(), staged_entry_count: 0, approval_ref: format!("approval_{id}"), audit_ref: format!("audit_{id}"), activation_epoch: nonce + 1, applied: false };
            let change_set = canonical_changeset(change_set, &[entry.clone()]);
            ledger.apply_transaction(&Transaction::sign(&admin, nonce, CostsOperation::StageRateCardChangeSetV1 { change_set: change_set.clone(), entries: vec![entry.clone()] })).await.unwrap();
            ledger.apply_transaction(&Transaction::sign(&admin, nonce + 1, CostsOperation::ApplyRateCardChangeSetV1 { change_set, entries: vec![entry] })).await.unwrap();
        }
        assert_eq!(ledger.active_rate("account_other", "creative.render", "", 12).await.unwrap().unwrap().rate_version, "global_v1");
        assert_eq!(ledger.active_rate("account_other", "creative.render", "", 22).await.unwrap().unwrap().rate_version, "global_v2");
        assert_eq!(ledger.active_rate("account_history", "creative.render", "", 12).await.unwrap().unwrap().rate_version, "global_v1");
        assert_eq!(ledger.active_rate("account_history", "creative.render", "", 16).await.unwrap().unwrap().rate_version, "account_v1");
    });
}

#[test]
fn v1_rate_manifest_binds_full_approval_payload_and_completion_is_once_only() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(141);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        let mut ledger = CostsLedger::new(&mut state);
        ledger.apply_transaction(&Transaction::sign(&admin, 0, onboard("account_manifest"))).await.unwrap();
        let rate = RateCardEntry { account_id: String::new(), event_category: "sms.send".to_string(), task_key: String::new(), credits: 3, effective_at: 10, expires_at: 0, policy_version: "policy_manifest".to_string(), rate_version: "rate_manifest".to_string() };
        let raw = crate::RateCardChangeSetV1 { change_set_id: "manifest_v1".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_manifest".to_string()], expected_target_count: 1, manifest_hash: "arbitrary".to_string(), staged_entry_count: 0, approval_ref: "approval_manifest".to_string(), audit_ref: "audit_manifest".to_string(), activation_epoch: 1, applied: false };
        assert!(matches!(ledger.apply_transaction(&Transaction::sign(&admin, 1, CostsOperation::StageRateCardChangeSetV1 { change_set: raw.clone(), entries: vec![rate.clone()] })).await, Err(CostsError::RateChangeSetConflict { .. })));
        let before_boundary = RateCardEntry { effective_at: 0, ..rate.clone() };
        let before_boundary_envelope = canonical_changeset(raw.clone(), &[before_boundary.clone()]);
        assert!(matches!(ledger.apply_transaction(&Transaction::sign(&admin, 1, CostsOperation::StageRateCardChangeSetV1 { change_set: before_boundary_envelope, entries: vec![before_boundary] })).await, Err(CostsError::InvalidField { field: "rate_effective_at_before_activation_epoch" })));
        let envelope = canonical_changeset(raw, &[rate.clone()]);
        ledger.apply_transaction(&Transaction::sign(&admin, 1, CostsOperation::StageRateCardChangeSetV1 { change_set: envelope.clone(), entries: vec![rate.clone()] })).await.unwrap();

        let mut altered_targets = envelope.clone();
        altered_targets.target_account_ids = Vec::new();
        altered_targets.expected_target_count = 0;
        altered_targets.manifest_hash = altered_targets.expected_manifest_hash(&[rate.clone()]);
        assert!(matches!(ledger.apply_transaction(&Transaction::sign(&admin, 2, CostsOperation::ApplyRateCardChangeSetV1 { change_set: altered_targets, entries: vec![rate.clone()] })).await, Err(CostsError::RateChangeSetConflict { .. })));

        let altered_entry = RateCardEntry { credits: 4, ..rate.clone() };
        let altered_entry_envelope = canonical_changeset(envelope.clone(), &[altered_entry.clone()]);
        assert!(matches!(ledger.apply_transaction(&Transaction::sign(&admin, 2, CostsOperation::ApplyRateCardChangeSetV1 { change_set: altered_entry_envelope, entries: vec![altered_entry] })).await, Err(CostsError::RateChangeSetConflict { .. })));

        let outcomes = ledger.apply_transaction_with_outcomes(&Transaction::sign(&admin, 2, CostsOperation::ApplyRateCardChangeSetV1 { change_set: envelope.clone(), entries: vec![rate] })).await.unwrap();
        let completion = outcomes.iter().filter(|outcome| outcome.kind == LedgerMutationKind::RateCardCompleted).collect::<Vec<_>>();
        assert_eq!(completion.len(), 1);
        assert!(completion[0].has_rate_card_completion);
        assert_eq!(completion[0].rate_card_completion.manifest_hash, envelope.manifest_hash);
        assert_eq!(completion[0].rate_card_completion.target_count, 1);
        assert_eq!(completion[0].rate_card_completion.affected_rates.len(), 2);
        let finality = FinalizedOutcomeV1::from_finalized_mutation(completion[0], Transaction::sign(&admin, 99, CostsOperation::RotateAdmin { replacement: address(&PrivateKey::ed25519_from_seed(143)) }).digest(), 100);
        assert_eq!(finality.event_type, "pricing.rate_card_updated");
        let finality_completion = finality.rate_card_completion.unwrap();
        assert_eq!(finality_completion.manifest_hash, envelope.manifest_hash);
        assert!(finality_completion.affected_rates.iter().any(|rate| rate.account_id == "account_manifest" && rate.rate_version == "rate_manifest"));
        assert!(ledger.apply_transaction_with_outcomes(&Transaction::sign(&admin, 3, CostsOperation::ApplyRateCardChangeSetV1 { change_set: envelope, entries: vec![RateCardEntry { account_id: String::new(), event_category: "sms.send".to_string(), task_key: String::new(), credits: 3, effective_at: 10, expires_at: 0, policy_version: "policy_manifest".to_string(), rate_version: "rate_manifest".to_string() }] })).await.unwrap().is_empty());
    });
}

#[test]
fn global_task_does_not_materialize_over_an_onboarded_account_category_and_account_task_wins() {
    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(142);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        let mut ledger = CostsLedger::new(&mut state);
        ledger.apply_transaction(&Transaction::sign(&admin, 0, onboard("account_scope_order"))).await.unwrap();
        let account_category = RateCardEntry { account_id: "account_scope_order".to_string(), event_category: "creative.render".to_string(), task_key: String::new(), credits: 7, effective_at: 10, expires_at: 0, policy_version: "policy_scope".to_string(), rate_version: "account_category".to_string() };
        let account_category_set = canonical_changeset(crate::RateCardChangeSetV1 { change_set_id: "account_category_set".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_scope_order".to_string()], expected_target_count: 1, manifest_hash: "placeholder".to_string(), staged_entry_count: 0, approval_ref: "approval_scope".to_string(), audit_ref: "audit_scope".to_string(), activation_epoch: 1, applied: false }, &[account_category.clone()]);
        ledger.apply_transaction(&Transaction::sign(&admin, 1, CostsOperation::StageRateCardChangeSetV1 { change_set: account_category_set.clone(), entries: vec![account_category.clone()] })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&admin, 2, CostsOperation::ApplyRateCardChangeSetV1 { change_set: account_category_set, entries: vec![account_category] })).await.unwrap();

        let global_task = RateCardEntry { account_id: String::new(), event_category: "creative.render".to_string(), task_key: "image_hd".to_string(), credits: 5, effective_at: 20, expires_at: 0, policy_version: "policy_scope".to_string(), rate_version: "global_task".to_string() };
        let global_set = canonical_changeset(crate::RateCardChangeSetV1 { change_set_id: "global_task_set".to_string(), expected_entry_count: 1, target_account_ids: Vec::new(), expected_target_count: 0, manifest_hash: "placeholder".to_string(), staged_entry_count: 0, approval_ref: "approval_scope".to_string(), audit_ref: "audit_scope".to_string(), activation_epoch: 3, applied: false }, &[global_task.clone()]);
        ledger.apply_transaction(&Transaction::sign(&admin, 3, CostsOperation::StageRateCardChangeSetV1 { change_set: global_set.clone(), entries: vec![global_task.clone()] })).await.unwrap();
        let outcomes = ledger.apply_transaction_with_outcomes(&Transaction::sign(&admin, 4, CostsOperation::ApplyRateCardChangeSetV1 { change_set: global_set, entries: vec![global_task] })).await.unwrap();
        assert!(!outcomes.iter().any(|outcome| outcome.kind == LedgerMutationKind::RateCardApplied && outcome.account_id == "account_scope_order"));
        assert_eq!(ledger.active_rate("account_scope_order", "creative.render", "image_hd", 20).await.unwrap().unwrap().rate_version, "account_category");

        let account_task = RateCardEntry { account_id: "account_scope_order".to_string(), event_category: "creative.render".to_string(), task_key: "image_hd".to_string(), credits: 9, effective_at: 30, expires_at: 0, policy_version: "policy_scope".to_string(), rate_version: "account_task".to_string() };
        let account_task_set = canonical_changeset(crate::RateCardChangeSetV1 { change_set_id: "account_task_set".to_string(), expected_entry_count: 1, target_account_ids: vec!["account_scope_order".to_string()], expected_target_count: 1, manifest_hash: "placeholder".to_string(), staged_entry_count: 0, approval_ref: "approval_scope".to_string(), audit_ref: "audit_scope".to_string(), activation_epoch: 5, applied: false }, &[account_task.clone()]);
        ledger.apply_transaction(&Transaction::sign(&admin, 5, CostsOperation::StageRateCardChangeSetV1 { change_set: account_task_set.clone(), entries: vec![account_task.clone()] })).await.unwrap();
        ledger.apply_transaction(&Transaction::sign(&admin, 6, CostsOperation::ApplyRateCardChangeSetV1 { change_set: account_task_set, entries: vec![account_task] })).await.unwrap();
        assert_eq!(ledger.active_rate("account_scope_order", "creative.render", "image_hd", 30).await.unwrap().unwrap().rate_version, "account_task");
    });
}

#[test]
fn grant_taxonomy_e2e_periodic_campaign_and_topup() {
    use crate::grant::{
        credit_grant_op, periodic_grant_metadata, campaign_grant_metadata, REASON_INCLUDED_CREDITS,
        REASON_PROMOTION, REASON_TOPUP,
    };

    futures::executor::block_on(async {
        let admin = PrivateKey::ed25519_from_seed(200);
        let billing = PrivateKey::ed25519_from_seed(201);
        let adjustment = PrivateKey::ed25519_from_seed(202);
        let mut state = MemoryState::default();
        state.set_writer(WriterRole::Admin, &address(&admin), true);
        state.set_writer(WriterRole::Billing, &address(&billing), true);
        state.set_writer(WriterRole::Adjustment, &address(&adjustment), true);
        let mut ledger = CostsLedger::new(&mut state);

        ledger
            .apply_transaction(&Transaction::sign(
                &admin,
                0,
                onboard("account_grants"),
            ))
            .await
            .unwrap();

        // periodic program monthly grant (idempotent)
        let periodic = credit_grant_op(
            "account_grants".to_string(),
            3_000,
            periodic_grant_metadata("account_grants", "2026-07", REASON_INCLUDED_CREDITS, "policy_auto"),
        );
        ledger
            .apply_transaction(&Transaction::sign(&adjustment, 0, periodic.clone()))
            .await
            .unwrap();
        ledger
            .apply_transaction(&Transaction::sign(&adjustment, 1, periodic))
            .await
            .unwrap();

        // Campaign campaign grant
        let campaign = credit_grant_op(
            "account_grants".to_string(),
            500,
            campaign_grant_metadata(
                "launch_2026q3",
                "account_grants",
                REASON_PROMOTION,
                "csm_approval_1",
                "audit_promo_1",
            ),
        );
        ledger
            .apply_transaction(&Transaction::sign(&adjustment, 2, campaign))
            .await
            .unwrap();

        // payment rail top-up with bonus baked into total credits
        ledger
            .apply_transaction(&Transaction::sign(
                &billing,
                0,
                CostsOperation::CreditTopup {
                    account_id: "account_grants".to_string(),
                    credits: 8_888,
                    rail_ref: "pi_showcase_bonus".to_string(),
                },
            ))
            .await
            .unwrap();

        let account = ledger.account("account_grants").await.unwrap().unwrap();
        assert_eq!(account.available_credits, 3_000 + 500 + 8_888);

        let journal = ledger.journal(0, u16::MAX).await.unwrap();
        let grant_entries: Vec<_> = journal
            .iter()
            .filter(|e| e.kind == LedgerMutationKind::BalanceChanged && e.reason_code != REASON_TOPUP)
            .collect();
        assert_eq!(grant_entries.len(), 2);
        assert_eq!(grant_entries[0].reason_code, REASON_INCLUDED_CREDITS);
        assert_eq!(grant_entries[1].reason_code, REASON_PROMOTION);

        let topup_entries: Vec<_> = journal
            .iter()
            .filter(|e| e.reason_code == REASON_TOPUP)
            .collect();
        assert_eq!(topup_entries.len(), 1);
        assert_eq!(topup_entries[0].credit_delta, 8_888);
    });
}
