use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::Operation;

use crate::{
    types::{identifier_encode_size, read_identifier, write_identifier},
    AdjustmentKind, AdjustmentMetadata, CreditGrantV2, CreditTopupV2, QuoteV1,
    RateCardChangeSetV1, RateCardEntry, RefundPaidLotV1, ReservationActionMetadataV1,
    SpendRecordV1, StatusChangeMetadataV1, StoredValueSpendV2, UntrackedSourceV1, WriterRole,
    COSTS_NAMESPACE,
};

const OP_REGISTER_SITE: u8 = 0;
const OP_SET_WRITER: u8 = 1;
const OP_CREDIT_TOPUP: u8 = 2;
const OP_RECORD_SPEND_BATCH: u8 = 3;
const OP_SET_SITE_STATUS: u8 = 4;
const OP_CREDIT_GRANT: u8 = 5;
const OP_CREDIT_REVERSAL: u8 = 6;
const OP_RESERVE_CREDITS: u8 = 7;
const OP_RELEASE_RESERVATION: u8 = 8;
const OP_SETTLE_SPEND: u8 = 9;
const OP_REGISTER_UNTRACKED_SOURCE: u8 = 10;
const OP_STAGE_RATE_CARD_ENTRIES: u8 = 11;
const OP_APPLY_RATE_CARD_CHANGE_SET: u8 = 12;
const OP_ONBOARD_SITE: u8 = 13;
const OP_ROTATE_ADMIN: u8 = 14;
const OP_EXPIRE_RESERVATION: u8 = 15;
const OP_CREDIT_ADJUSTMENT_V1: u8 = 16;
const OP_REGISTER_UNTRACKED_SOURCE_V1: u8 = 17;
const OP_SET_SITE_WRITER: u8 = 18;
const OP_SET_SITE_STATUS_V1: u8 = 19;
const OP_STAGE_RATE_CARD_CHANGE_SET_V1: u8 = 20;
const OP_APPLY_RATE_CARD_CHANGE_SET_V1: u8 = 21;
const OP_RESERVE_CREDITS_V1: u8 = 22;
const OP_SETTLE_SPEND_V1: u8 = 23;
const OP_RELEASE_RESERVATION_V1: u8 = 24;
const OP_EXPIRE_RESERVATION_V1: u8 = 25;
const OP_STORED_VALUE_TOPUP_V2: u8 = 26;
const OP_STORED_VALUE_GRANT_V2: u8 = 27;
const OP_STORED_VALUE_SPEND_V2: u8 = 28;
const OP_REFUND_PAID_LOT_V1: u8 = 29;
const OP_RESERVE_STORED_VALUE_V2: u8 = 30;
const OP_RELEASE_STORED_VALUE_RESERVATION_V2: u8 = 31;
const OP_EXPIRE_STORED_VALUE_RESERVATION_V2: u8 = 32;
const OP_SETTLE_STORED_VALUE_RESERVATION_V2: u8 = 33;

/// Signed state transitions supported by the costs module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CostsOperation {
    RegisterAccount { account_id: String },
    /// Idempotent programmatic onboarding. All fields are opaque service
    /// references and must be authorized by an administrator signer.
    CreateAccount {
        account_id: String,
        external_ref: String,
        policy_ref: String,
        cohort_ref: String,
        created_at: u64,
    },
    SetWriter { role: WriterRole, writer: nunchi_common::Address, enabled: bool },
    /// Grants/revokes a backend capability for precisely one account. Global
    /// `SetWriter` remains the break-glass system capability.
    SetAccountWriter { account_id: String, role: WriterRole, writer: nunchi_common::Address, enabled: bool },
    /// Safe capability handoff: only the current administrator can remove its
    /// own capability after enabling the replacement.
    RotateAdmin { replacement: nunchi_common::Address },
    CreditTopup { account_id: String, credits: u64, rail_ref: String },
    /// Provenance-preserving paid credit ingress. This is the clean-state
    /// stored-value command; legacy aggregate `CreditTopup` remains metering-only.
    StoredValueTopupV2 { topup: CreditTopupV2 },
    /// Immutable non-refundable grant lot with operator approval evidence.
    StoredValueGrantV2 { grant: CreditGrantV2 },
    /// Deterministic grant-first lot allocation for a finalized spend event.
    StoredValueSpendV2 { spend: StoredValueSpendV2 },
    /// Support-mediated refund of unused paid credit to its originating rail.
    RefundPaidLotV1 { refund: RefundPaidLotV1 },
    /// Grant-first lot reservation for a long-running action. The reservation
    /// is private ledger state, never a public client-side balance mutation.
    ReserveStoredValueV2 {
        reservation_id: String,
        account_id: String,
        credits: u64,
        expires_at: u64,
        reserved_at: u64,
    },
    ReleaseStoredValueReservationV2 { reservation_id: String, released_at: u64 },
    ExpireStoredValueReservationV2 { reservation_id: String, expired_at: u64 },
    SettleStoredValueReservationV2 { reservation_id: String, spend: StoredValueSpendV2 },
    RecordSpendBatch { records: Vec<SpendRecordV1> },
    SetAccountStatus { account_id: String, status: crate::AccountStatus },
    SetAccountStatusV1 { account_id: String, status: crate::AccountStatus, metadata: StatusChangeMetadataV1 },
    CreditGrant { account_id: String, credits: u64, grant_ref: String },
    CreditReversal { account_id: String, credits: u64, reversal_ref: String },
    ReserveCredits {
        reservation_id: String,
        account_id: String,
        credits: u64,
        expires_at: u64,
    },
    /// Quote-bound fixed-price hold. Quotes are immutable snapshots and do
    /// not reprice when a later card is activated.
    ReserveCreditsV1 { reservation_id: String, quote: QuoteV1, lineage_ref: String, reserved_at: u64 },
    ReleaseReservation { reservation_id: String },
    /// Authorization-layer clock input. Releases only after the reservation's
    /// immutable expiry and is idempotent after expiry.
    ExpireReservation { reservation_id: String, expired_at: u64 },
    ReleaseReservationV1 { reservation_id: String, metadata: ReservationActionMetadataV1 },
    ExpireReservationV1 { reservation_id: String, metadata: ReservationActionMetadataV1 },
    SettleSpend {
        reservation_id: String,
        event_id: String,
        event_category: String,
    },
    SettleSpendV1 { reservation_id: String, event_id: String, event_category: String, task_key: String, quote_id: String, snapshot_hash: String, lineage_ref: String, metadata: ReservationActionMetadataV1 },
    RegisterUntrackedSource { source_id: String, reason_code: String },
    RegisterUntrackedSourceV1 { source: UntrackedSourceV1 },
    CreditAdjustmentV1 {
        kind: AdjustmentKind,
        account_id: String,
        credits: u64,
        metadata: AdjustmentMetadata,
    },
    StageRateCardEntries {
        change_set_id: String,
        expected_entry_count: u16,
        manifest_hash: String,
        entries: Vec<RateCardEntry>,
    },
    ApplyRateCardChangeSet {
        change_set_id: String,
        manifest_hash: String,
        entries: Vec<RateCardEntry>,
    },
    StageRateCardChangeSetV1 { change_set: RateCardChangeSetV1, entries: Vec<RateCardEntry> },
    ApplyRateCardChangeSetV1 { change_set: RateCardChangeSetV1, entries: Vec<RateCardEntry> },
}

impl Write for CostsOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::RegisterAccount { account_id } => {
                OP_REGISTER_SITE.write(buf);
                write_identifier(account_id, buf);
            }
            Self::CreateAccount { account_id, external_ref, policy_ref, cohort_ref, created_at } => {
                OP_ONBOARD_SITE.write(buf);
                write_identifier(account_id, buf);
                write_identifier(external_ref, buf);
                write_identifier(policy_ref, buf);
                write_identifier(cohort_ref, buf);
                created_at.write(buf);
            }
            Self::SetWriter { role, writer, enabled } => {
                OP_SET_WRITER.write(buf);
                role.write(buf);
                writer.write(buf);
                enabled.write(buf);
            }
            Self::SetAccountWriter { account_id, role, writer, enabled } => {
                OP_SET_SITE_WRITER.write(buf);
                write_identifier(account_id, buf);
                role.write(buf);
                writer.write(buf);
                enabled.write(buf);
            }
            Self::RotateAdmin { replacement } => {
                OP_ROTATE_ADMIN.write(buf);
                replacement.write(buf);
            }
            Self::CreditTopup { account_id, credits, rail_ref } => {
                OP_CREDIT_TOPUP.write(buf);
                write_identifier(account_id, buf);
                credits.write(buf);
                write_identifier(rail_ref, buf);
            }
            Self::StoredValueTopupV2 { topup } => {
                OP_STORED_VALUE_TOPUP_V2.write(buf);
                topup.write(buf);
            }
            Self::StoredValueGrantV2 { grant } => {
                OP_STORED_VALUE_GRANT_V2.write(buf);
                grant.write(buf);
            }
            Self::StoredValueSpendV2 { spend } => {
                OP_STORED_VALUE_SPEND_V2.write(buf);
                spend.write(buf);
            }
            Self::RefundPaidLotV1 { refund } => {
                OP_REFUND_PAID_LOT_V1.write(buf);
                refund.write(buf);
            }
            Self::ReserveStoredValueV2 { reservation_id, account_id, credits, expires_at, reserved_at } => {
                OP_RESERVE_STORED_VALUE_V2.write(buf);
                write_identifier(reservation_id, buf);
                write_identifier(account_id, buf);
                credits.write(buf);
                expires_at.write(buf);
                reserved_at.write(buf);
            }
            Self::ReleaseStoredValueReservationV2 { reservation_id, released_at } => {
                OP_RELEASE_STORED_VALUE_RESERVATION_V2.write(buf);
                write_identifier(reservation_id, buf);
                released_at.write(buf);
            }
            Self::ExpireStoredValueReservationV2 { reservation_id, expired_at } => {
                OP_EXPIRE_STORED_VALUE_RESERVATION_V2.write(buf);
                write_identifier(reservation_id, buf);
                expired_at.write(buf);
            }
            Self::SettleStoredValueReservationV2 { reservation_id, spend } => {
                OP_SETTLE_STORED_VALUE_RESERVATION_V2.write(buf);
                write_identifier(reservation_id, buf);
                spend.write(buf);
            }
            Self::RecordSpendBatch { records } => {
                OP_RECORD_SPEND_BATCH.write(buf);
                (records.len() as u16).write(buf);
                for record in records {
                    record.write(buf);
                }
            }
            Self::SetAccountStatus { account_id, status } => {
                OP_SET_SITE_STATUS.write(buf);
                write_identifier(account_id, buf);
                status.write(buf);
            }
            Self::SetAccountStatusV1 { account_id, status, metadata } => { OP_SET_SITE_STATUS_V1.write(buf); write_identifier(account_id, buf); status.write(buf); metadata.write(buf); }
            Self::CreditGrant { account_id, credits, grant_ref } => {
                OP_CREDIT_GRANT.write(buf);
                write_identifier(account_id, buf);
                credits.write(buf);
                write_identifier(grant_ref, buf);
            }
            Self::CreditReversal { account_id, credits, reversal_ref } => {
                OP_CREDIT_REVERSAL.write(buf);
                write_identifier(account_id, buf);
                credits.write(buf);
                write_identifier(reversal_ref, buf);
            }
            Self::ReserveCredits { reservation_id, account_id, credits, expires_at } => {
                OP_RESERVE_CREDITS.write(buf);
                write_identifier(reservation_id, buf);
                write_identifier(account_id, buf);
                credits.write(buf);
                expires_at.write(buf);
            }
            Self::ReserveCreditsV1 { reservation_id, quote, lineage_ref, reserved_at } => { OP_RESERVE_CREDITS_V1.write(buf); write_identifier(reservation_id, buf); write_quote(quote, buf); write_identifier(lineage_ref, buf); reserved_at.write(buf); }
            Self::ReleaseReservation { reservation_id } => {
                OP_RELEASE_RESERVATION.write(buf);
                write_identifier(reservation_id, buf);
            }
            Self::ExpireReservation { reservation_id, expired_at } => {
                OP_EXPIRE_RESERVATION.write(buf);
                write_identifier(reservation_id, buf);
                expired_at.write(buf);
            }
            Self::ReleaseReservationV1 { reservation_id, metadata } => { OP_RELEASE_RESERVATION_V1.write(buf); write_identifier(reservation_id, buf); metadata.write(buf); }
            Self::ExpireReservationV1 { reservation_id, metadata } => { OP_EXPIRE_RESERVATION_V1.write(buf); write_identifier(reservation_id, buf); metadata.write(buf); }
            Self::SettleSpend { reservation_id, event_id, event_category } => {
                OP_SETTLE_SPEND.write(buf);
                write_identifier(reservation_id, buf);
                write_identifier(event_id, buf);
                write_identifier(event_category, buf);
            }
            Self::SettleSpendV1 { reservation_id, event_id, event_category, task_key, quote_id, snapshot_hash, lineage_ref, metadata } => { OP_SETTLE_SPEND_V1.write(buf); write_identifier(reservation_id, buf); write_identifier(event_id, buf); write_identifier(event_category, buf); write_identifier(task_key, buf); write_identifier(quote_id, buf); write_identifier(snapshot_hash, buf); write_identifier(lineage_ref, buf); metadata.write(buf); }
            Self::RegisterUntrackedSource { source_id, reason_code } => {
                OP_REGISTER_UNTRACKED_SOURCE.write(buf);
                write_identifier(source_id, buf);
                write_identifier(reason_code, buf);
            }
            Self::RegisterUntrackedSourceV1 { source } => {
                OP_REGISTER_UNTRACKED_SOURCE_V1.write(buf);
                source.write(buf);
            }
            Self::CreditAdjustmentV1 { kind, account_id, credits, metadata } => {
                OP_CREDIT_ADJUSTMENT_V1.write(buf);
                kind.write(buf);
                write_identifier(account_id, buf);
                credits.write(buf);
                metadata.write(buf);
            }
            Self::StageRateCardEntries { change_set_id, expected_entry_count, manifest_hash, entries } => {
                OP_STAGE_RATE_CARD_ENTRIES.write(buf);
                write_identifier(change_set_id, buf);
                expected_entry_count.write(buf);
                write_identifier(manifest_hash, buf);
                (entries.len() as u16).write(buf);
                for entry in entries {
                    entry.write(buf);
                }
            }
            Self::ApplyRateCardChangeSet { change_set_id, manifest_hash, entries } => {
                OP_APPLY_RATE_CARD_CHANGE_SET.write(buf);
                write_identifier(change_set_id, buf);
                write_identifier(manifest_hash, buf);
                (entries.len() as u16).write(buf);
                for entry in entries {
                    entry.write(buf);
                }
            }
            Self::StageRateCardChangeSetV1 { change_set, entries } => { OP_STAGE_RATE_CARD_CHANGE_SET_V1.write(buf); change_set.write(buf); write_entries(entries, buf); }
            Self::ApplyRateCardChangeSetV1 { change_set, entries } => { OP_APPLY_RATE_CARD_CHANGE_SET_V1.write(buf); change_set.write(buf); write_entries(entries, buf); }
        }
    }
}

impl Read for CostsOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            OP_REGISTER_SITE => Ok(Self::RegisterAccount {
                account_id: read_identifier(buf)?,
            }),
            OP_ONBOARD_SITE => Ok(Self::CreateAccount {
                account_id: read_identifier(buf)?,
                external_ref: read_identifier(buf)?,
                policy_ref: read_identifier(buf)?,
                cohort_ref: read_identifier(buf)?,
                created_at: u64::read(buf)?,
            }),
            OP_SET_WRITER => Ok(Self::SetWriter {
                role: WriterRole::read(buf)?,
                writer: nunchi_common::Address::read(buf)?,
                enabled: bool::read(buf)?,
            }),
            OP_SET_SITE_WRITER => Ok(Self::SetAccountWriter {
                account_id: read_identifier(buf)?,
                role: WriterRole::read(buf)?,
                writer: nunchi_common::Address::read(buf)?,
                enabled: bool::read(buf)?,
            }),
            OP_ROTATE_ADMIN => Ok(Self::RotateAdmin { replacement: nunchi_common::Address::read(buf)? }),
            OP_CREDIT_TOPUP => Ok(Self::CreditTopup {
                account_id: read_identifier(buf)?,
                credits: u64::read(buf)?,
                rail_ref: read_identifier(buf)?,
            }),
            OP_STORED_VALUE_TOPUP_V2 => Ok(Self::StoredValueTopupV2 {
                topup: CreditTopupV2::read(buf)?,
            }),
            OP_STORED_VALUE_GRANT_V2 => Ok(Self::StoredValueGrantV2 {
                grant: CreditGrantV2::read(buf)?,
            }),
            OP_STORED_VALUE_SPEND_V2 => Ok(Self::StoredValueSpendV2 {
                spend: StoredValueSpendV2::read(buf)?,
            }),
            OP_REFUND_PAID_LOT_V1 => Ok(Self::RefundPaidLotV1 {
                refund: RefundPaidLotV1::read(buf)?,
            }),
            OP_RESERVE_STORED_VALUE_V2 => Ok(Self::ReserveStoredValueV2 {
                reservation_id: read_identifier(buf)?,
                account_id: read_identifier(buf)?,
                credits: u64::read(buf)?,
                expires_at: u64::read(buf)?,
                reserved_at: u64::read(buf)?,
            }),
            OP_RELEASE_STORED_VALUE_RESERVATION_V2 => Ok(Self::ReleaseStoredValueReservationV2 {
                reservation_id: read_identifier(buf)?,
                released_at: u64::read(buf)?,
            }),
            OP_EXPIRE_STORED_VALUE_RESERVATION_V2 => Ok(Self::ExpireStoredValueReservationV2 {
                reservation_id: read_identifier(buf)?,
                expired_at: u64::read(buf)?,
            }),
            OP_SETTLE_STORED_VALUE_RESERVATION_V2 => Ok(Self::SettleStoredValueReservationV2 {
                reservation_id: read_identifier(buf)?,
                spend: StoredValueSpendV2::read(buf)?,
            }),
            OP_RECORD_SPEND_BATCH => {
                let len = u16::read(buf)? as usize;
                let mut records = Vec::with_capacity(len);
                for _ in 0..len {
                    records.push(SpendRecordV1::read(buf)?);
                }
                Ok(Self::RecordSpendBatch { records })
            }
            OP_SET_SITE_STATUS => Ok(Self::SetAccountStatus {
                account_id: read_identifier(buf)?,
                status: crate::AccountStatus::read(buf)?,
            }),
            OP_SET_SITE_STATUS_V1 => Ok(Self::SetAccountStatusV1 { account_id: read_identifier(buf)?, status: crate::AccountStatus::read(buf)?, metadata: StatusChangeMetadataV1::read(buf)? }),
            OP_CREDIT_GRANT => Ok(Self::CreditGrant {
                account_id: read_identifier(buf)?,
                credits: u64::read(buf)?,
                grant_ref: read_identifier(buf)?,
            }),
            OP_CREDIT_REVERSAL => Ok(Self::CreditReversal {
                account_id: read_identifier(buf)?,
                credits: u64::read(buf)?,
                reversal_ref: read_identifier(buf)?,
            }),
            OP_RESERVE_CREDITS => Ok(Self::ReserveCredits {
                reservation_id: read_identifier(buf)?,
                account_id: read_identifier(buf)?,
                credits: u64::read(buf)?,
                expires_at: u64::read(buf)?,
            }),
            OP_RESERVE_CREDITS_V1 => Ok(Self::ReserveCreditsV1 { reservation_id: read_identifier(buf)?, quote: read_quote(buf)?, lineage_ref: read_identifier(buf)?, reserved_at: u64::read(buf)? }),
            OP_RELEASE_RESERVATION => Ok(Self::ReleaseReservation {
                reservation_id: read_identifier(buf)?,
            }),
            OP_EXPIRE_RESERVATION => Ok(Self::ExpireReservation {
                reservation_id: read_identifier(buf)?,
                expired_at: u64::read(buf)?,
            }),
            OP_RELEASE_RESERVATION_V1 => Ok(Self::ReleaseReservationV1 { reservation_id: read_identifier(buf)?, metadata: ReservationActionMetadataV1::read(buf)? }),
            OP_EXPIRE_RESERVATION_V1 => Ok(Self::ExpireReservationV1 { reservation_id: read_identifier(buf)?, metadata: ReservationActionMetadataV1::read(buf)? }),
            OP_SETTLE_SPEND => Ok(Self::SettleSpend {
                reservation_id: read_identifier(buf)?,
                event_id: read_identifier(buf)?,
                event_category: read_identifier(buf)?,
            }),
            OP_SETTLE_SPEND_V1 => Ok(Self::SettleSpendV1 { reservation_id: read_identifier(buf)?, event_id: read_identifier(buf)?, event_category: read_identifier(buf)?, task_key: read_identifier(buf)?, quote_id: read_identifier(buf)?, snapshot_hash: read_identifier(buf)?, lineage_ref: read_identifier(buf)?, metadata: ReservationActionMetadataV1::read(buf)? }),
            OP_REGISTER_UNTRACKED_SOURCE => Ok(Self::RegisterUntrackedSource {
                source_id: read_identifier(buf)?,
                reason_code: read_identifier(buf)?,
            }),
            OP_REGISTER_UNTRACKED_SOURCE_V1 => Ok(Self::RegisterUntrackedSourceV1 {
                source: UntrackedSourceV1::read(buf)?,
            }),
            OP_CREDIT_ADJUSTMENT_V1 => Ok(Self::CreditAdjustmentV1 {
                kind: AdjustmentKind::read(buf)?,
                account_id: read_identifier(buf)?,
                credits: u64::read(buf)?,
                metadata: AdjustmentMetadata::read(buf)?,
            }),
            OP_STAGE_RATE_CARD_ENTRIES => {
                let change_set_id = read_identifier(buf)?;
                let expected_entry_count = u16::read(buf)?;
                let manifest_hash = read_identifier(buf)?;
                let len = u16::read(buf)? as usize;
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    entries.push(RateCardEntry::read(buf)?);
                }
                Ok(Self::StageRateCardEntries {
                    change_set_id,
                    expected_entry_count,
                    manifest_hash,
                    entries,
                })
            }
            OP_APPLY_RATE_CARD_CHANGE_SET => {
                let change_set_id = read_identifier(buf)?;
                let manifest_hash = read_identifier(buf)?;
                let len = u16::read(buf)? as usize;
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    entries.push(RateCardEntry::read(buf)?);
                }
                Ok(Self::ApplyRateCardChangeSet {
                    change_set_id,
                    manifest_hash,
                    entries,
                })
            }
            OP_STAGE_RATE_CARD_CHANGE_SET_V1 => Ok(Self::StageRateCardChangeSetV1 { change_set: RateCardChangeSetV1::read(buf)?, entries: read_entries(buf)? }),
            OP_APPLY_RATE_CARD_CHANGE_SET_V1 => Ok(Self::ApplyRateCardChangeSetV1 { change_set: RateCardChangeSetV1::read(buf)?, entries: read_entries(buf)? }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for CostsOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::RegisterAccount { account_id } => identifier_encode_size(account_id),
            Self::CreateAccount { account_id, external_ref, policy_ref, cohort_ref, created_at } => {
                identifier_encode_size(account_id) + identifier_encode_size(external_ref)
                    + identifier_encode_size(policy_ref) + identifier_encode_size(cohort_ref)
                    + created_at.encode_size()
            }
            Self::SetWriter { role, writer, enabled } => {
                role.encode_size() + writer.encode_size() + enabled.encode_size()
            }
            Self::SetAccountWriter { account_id, role, writer, enabled } => {
                identifier_encode_size(account_id) + role.encode_size() + writer.encode_size() + enabled.encode_size()
            }
            Self::RotateAdmin { replacement } => replacement.encode_size(),
            Self::CreditTopup { account_id, credits, rail_ref } => {
                identifier_encode_size(account_id) + credits.encode_size() + identifier_encode_size(rail_ref)
            }
            Self::StoredValueTopupV2 { topup } => topup.encode_size(),
            Self::StoredValueGrantV2 { grant } => grant.encode_size(),
            Self::StoredValueSpendV2 { spend } => spend.encode_size(),
            Self::RefundPaidLotV1 { refund } => refund.encode_size(),
            Self::ReserveStoredValueV2 { reservation_id, account_id, credits, expires_at, reserved_at } => {
                identifier_encode_size(reservation_id) + identifier_encode_size(account_id)
                    + credits.encode_size() + expires_at.encode_size() + reserved_at.encode_size()
            }
            Self::ReleaseStoredValueReservationV2 { reservation_id, released_at }
            | Self::ExpireStoredValueReservationV2 { reservation_id, expired_at: released_at } => {
                identifier_encode_size(reservation_id) + released_at.encode_size()
            }
            Self::SettleStoredValueReservationV2 { reservation_id, spend } => {
                identifier_encode_size(reservation_id) + spend.encode_size()
            }
            Self::RecordSpendBatch { records } => {
                2 + records.iter().map(EncodeSize::encode_size).sum::<usize>()
            }
            Self::SetAccountStatus { account_id, status } => {
                identifier_encode_size(account_id) + status.encode_size()
            }
            Self::SetAccountStatusV1 { account_id, status, metadata } => identifier_encode_size(account_id) + status.encode_size() + metadata.encode_size(),
            Self::CreditGrant { account_id, credits, grant_ref }
            | Self::CreditReversal { account_id, credits, reversal_ref: grant_ref } => {
                identifier_encode_size(account_id) + credits.encode_size() + identifier_encode_size(grant_ref)
            }
            Self::ReserveCredits { reservation_id, account_id, credits, expires_at } => {
                identifier_encode_size(reservation_id)
                    + identifier_encode_size(account_id)
                    + credits.encode_size()
                    + expires_at.encode_size()
            }
            Self::ReserveCreditsV1 { reservation_id, quote, lineage_ref, reserved_at } => identifier_encode_size(reservation_id) + quote_encode_size(quote) + identifier_encode_size(lineage_ref) + reserved_at.encode_size(),
            Self::ReleaseReservation { reservation_id } => identifier_encode_size(reservation_id),
            Self::ExpireReservation { reservation_id, expired_at } => {
                identifier_encode_size(reservation_id) + expired_at.encode_size()
            }
            Self::ReleaseReservationV1 { reservation_id, metadata } | Self::ExpireReservationV1 { reservation_id, metadata } => identifier_encode_size(reservation_id) + metadata.encode_size(),
            Self::SettleSpend { reservation_id, event_id, event_category } => {
                identifier_encode_size(reservation_id)
                    + identifier_encode_size(event_id)
                    + identifier_encode_size(event_category)
            }
            Self::SettleSpendV1 { reservation_id, event_id, event_category, task_key, quote_id, snapshot_hash, lineage_ref, metadata } => identifier_encode_size(reservation_id) + identifier_encode_size(event_id) + identifier_encode_size(event_category) + identifier_encode_size(task_key) + identifier_encode_size(quote_id) + identifier_encode_size(snapshot_hash) + identifier_encode_size(lineage_ref) + metadata.encode_size(),
            Self::RegisterUntrackedSource { source_id, reason_code } => {
                identifier_encode_size(source_id) + identifier_encode_size(reason_code)
            }
            Self::RegisterUntrackedSourceV1 { source } => source.encode_size(),
            Self::CreditAdjustmentV1 { kind, account_id, credits, metadata } => {
                kind.encode_size() + identifier_encode_size(account_id) + credits.encode_size()
                    + metadata.encode_size()
            }
            Self::StageRateCardEntries { change_set_id, expected_entry_count, manifest_hash, entries } => {
                identifier_encode_size(change_set_id)
                    + expected_entry_count.encode_size()
                    + identifier_encode_size(manifest_hash)
                    + 2
                    + entries.iter().map(EncodeSize::encode_size).sum::<usize>()
            }
            Self::ApplyRateCardChangeSet { change_set_id, manifest_hash, entries } => {
                identifier_encode_size(change_set_id)
                    + identifier_encode_size(manifest_hash)
                    + 2
                    + entries.iter().map(EncodeSize::encode_size).sum::<usize>()
            }
            Self::StageRateCardChangeSetV1 { change_set, entries } | Self::ApplyRateCardChangeSetV1 { change_set, entries } => change_set.encode_size() + 2 + entries.iter().map(EncodeSize::encode_size).sum::<usize>(),
        }
    }
}

fn write_entries(entries: &[RateCardEntry], buf: &mut impl bytes::BufMut) { (entries.len() as u16).write(buf); for entry in entries { entry.write(buf); } }
fn read_entries(buf: &mut impl bytes::Buf) -> Result<Vec<RateCardEntry>, Error> { let len = u16::read(buf)? as usize; let mut entries = Vec::with_capacity(len); for _ in 0..len { entries.push(RateCardEntry::read(buf)?); } Ok(entries) }
fn write_quote(quote: &QuoteV1, buf: &mut impl bytes::BufMut) { write_identifier(&quote.quote_id, buf); write_identifier(&quote.snapshot_hash, buf); write_identifier(&quote.account_id, buf); write_identifier(&quote.event_category, buf); write_identifier(&quote.task_key, buf); quote.quoted_at.write(buf); quote.credits_per_unit.write(buf); quote.quantity.write(buf); quote.total_credits.write(buf); write_identifier(&quote.policy_version, buf); write_identifier(&quote.rate_version, buf); quote.expires_at.write(buf); }
fn read_quote(buf: &mut impl bytes::Buf) -> Result<QuoteV1, Error> { Ok(QuoteV1 { quote_id: read_identifier(buf)?, snapshot_hash: read_identifier(buf)?, account_id: read_identifier(buf)?, event_category: read_identifier(buf)?, task_key: read_identifier(buf)?, quoted_at: u64::read(buf)?, credits_per_unit: u64::read(buf)?, quantity: u64::read(buf)?, total_credits: u64::read(buf)?, policy_version: read_identifier(buf)?, rate_version: read_identifier(buf)?, expires_at: u64::read(buf)? }) }
fn quote_encode_size(quote: &QuoteV1) -> usize { identifier_encode_size(&quote.quote_id) + identifier_encode_size(&quote.snapshot_hash) + identifier_encode_size(&quote.account_id) + identifier_encode_size(&quote.event_category) + identifier_encode_size(&quote.task_key) + quote.quoted_at.encode_size() + quote.credits_per_unit.encode_size() + quote.quantity.encode_size() + quote.total_credits.encode_size() + identifier_encode_size(&quote.policy_version) + identifier_encode_size(&quote.rate_version) + quote.expires_at.encode_size() }

impl Operation for CostsOperation {
    const NAMESPACE: &'static [u8] = COSTS_NAMESPACE;
}

pub type TransactionPayload = nunchi_common::TransactionPayload<CostsOperation>;
pub type Transaction = nunchi_common::Transaction<CostsOperation>;
