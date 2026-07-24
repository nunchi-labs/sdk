use bytes::Buf;
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{Hasher, Sha256};

const STATUS_ACTIVE: u8 = 0;
const STATUS_SUSPENDED: u8 = 1;
const ROLE_ADMIN: u8 = 0;
const ROLE_INGEST: u8 = 1;
const ROLE_BILLING: u8 = 2;
const ROLE_ADJUSTMENT: u8 = 3;
const RESERVATION_ACTIVE: u8 = 0;
const RESERVATION_RELEASED: u8 = 1;
const RESERVATION_SETTLED: u8 = 2;
const RESERVATION_EXPIRED: u8 = 3;
const ADJUSTMENT_GRANT: u8 = 0;
const ADJUSTMENT_REVERSAL: u8 = 1;
const JOURNAL_ONBOARDED: u8 = 0;
const JOURNAL_BALANCE_CHANGED: u8 = 1;
const JOURNAL_SPEND_RECORDED: u8 = 2;
const JOURNAL_STATUS_CHANGED: u8 = 3;
const JOURNAL_RESERVATION_CHANGED: u8 = 4;
const JOURNAL_RATE_STAGED: u8 = 5;
const JOURNAL_RATE_APPLIED: u8 = 6;
const JOURNAL_UNTRACKED_SOURCE_REGISTERED: u8 = 7;
const JOURNAL_RATE_GLOBAL_APPLIED: u8 = 8;
const JOURNAL_RATE_CARD_COMPLETED: u8 = 9;
const BALANCE_DIRECTION_NONE: u8 = 0;
const BALANCE_DIRECTION_CREDIT: u8 = 1;
const BALANCE_DIRECTION_DEBIT: u8 = 2;

/// The largest wire value accepted for an identifier before ledger-level policy
/// applies its tighter domain-specific limits.
const MAX_WIRE_IDENTIFIER_LEN: usize = 1024;

pub(crate) fn write_identifier(value: &str, buf: &mut impl bytes::BufMut) {
    let length = u16::try_from(value.len())
        .expect("costs identifier exceeds the u16 transaction encoding limit");
    length.write(buf);
    buf.put_slice(value.as_bytes());
}

pub(crate) fn read_identifier(buf: &mut impl bytes::Buf) -> Result<String, Error> {
    let length = u16::read(buf)? as usize;
    if length > MAX_WIRE_IDENTIFIER_LEN {
        return Err(Error::InvalidLength(length));
    }
    if buf.remaining() < length {
        return Err(Error::EndOfBuffer);
    }
    String::from_utf8(buf.copy_to_bytes(length).to_vec())
        .map_err(|_| Error::Invalid("costs identifier", "must be valid UTF-8"))
}

pub(crate) fn identifier_encode_size(value: &str) -> usize {
    u16::default().encode_size() + value.len()
}

/// Whether a account account may settle new spend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountStatus {
    Active,
    Suspended,
}

impl Write for AccountStatus {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Active => STATUS_ACTIVE.write(buf),
            Self::Suspended => STATUS_SUSPENDED.write(buf),
        }
    }
}

impl Read for AccountStatus {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            STATUS_ACTIVE => Ok(Self::Active),
            STATUS_SUSPENDED => Ok(Self::Suspended),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for AccountStatus {
    fn encode_size(&self) -> usize {
        1
    }
}

/// Backend capability required for a costs operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterRole {
    Admin,
    Ingest,
    Billing,
    /// Authorized finance service for grants and post-settlement corrections.
    Adjustment,
}

impl WriterRole {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Admin => ROLE_ADMIN,
            Self::Ingest => ROLE_INGEST,
            Self::Billing => ROLE_BILLING,
            Self::Adjustment => ROLE_ADJUSTMENT,
        }
    }
}

impl Write for WriterRole {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.tag().write(buf);
    }
}

impl Read for WriterRole {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            ROLE_ADMIN => Ok(Self::Admin),
            ROLE_INGEST => Ok(Self::Ingest),
            ROLE_BILLING => Ok(Self::Billing),
            ROLE_ADJUSTMENT => Ok(Self::Adjustment),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for WriterRole {
    fn encode_size(&self) -> usize {
        1
    }
}

/// The on-chain credit state for one opaque client account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreditAccount {
    pub status: AccountStatus,
    pub available_credits: u64,
    pub reserved_credits: u64,
}

impl CreditAccount {
    pub const fn active() -> Self {
        Self {
            status: AccountStatus::Active,
            available_credits: 0,
            reserved_credits: 0,
        }
    }
}

impl Write for CreditAccount {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.status.write(buf);
        self.available_credits.write(buf);
        self.reserved_credits.write(buf);
    }
}

impl Read for CreditAccount {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            status: AccountStatus::read(buf)?,
            available_credits: u64::read(buf)?,
            reserved_credits: u64::read(buf)?,
        })
    }
}

impl EncodeSize for CreditAccount {
    fn encode_size(&self) -> usize {
        self.status.encode_size()
            + self.available_credits.encode_size()
            + self.reserved_credits.encode_size()
    }
}

/// Lifecycle state for a hold against a account's available credit balance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationStatus {
    Active,
    Released,
    Settled,
    /// Released by an authorized expiry sweep after `expires_at`.
    Expired,
}

impl Write for ReservationStatus {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Active => RESERVATION_ACTIVE.write(buf),
            Self::Released => RESERVATION_RELEASED.write(buf),
            Self::Settled => RESERVATION_SETTLED.write(buf),
            Self::Expired => RESERVATION_EXPIRED.write(buf),
        }
    }
}

impl Read for ReservationStatus {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            RESERVATION_ACTIVE => Ok(Self::Active),
            RESERVATION_RELEASED => Ok(Self::Released),
            RESERVATION_SETTLED => Ok(Self::Settled),
            RESERVATION_EXPIRED => Ok(Self::Expired),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for ReservationStatus {
    fn encode_size(&self) -> usize {
        1
    }
}

/// A deterministic hold for a long-running priced action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reservation {
    pub reservation_id: String,
    pub account_id: String,
    /// Full immutable V1 price snapshot. A later rate activation must never
    /// alter a hold that has already been authorized.
    pub quote: QuoteV1,
    /// Opaque source lineage bound at authorization time. Settlement must
    /// present the identical lineage, preventing a quote from being reused
    /// for a different measured action.
    pub lineage_ref: String,
    pub credits: u64,
    /// Unix seconds supplied by the authorization layer; expiration is released
    /// only by an explicit, authorized transaction.
    pub expires_at: u64,
    pub status: ReservationStatus,
}

/// Immutable account-account metadata.  This is deliberately separate from the
/// balance record so that a future account-profile read model cannot mutate
/// custodial credits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountProfile {
    pub account_id: String,
    pub external_ref: String,
    /// Opaque internal program identifier; this is not an end-user identity.
    pub policy_ref: String,
    pub created_at: u64,
    pub cohort_ref: String,
    pub status_reason: String,
    pub status_changed_at: u64,
}

impl Write for AccountProfile {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        write_identifier(&self.account_id, buf);
        write_identifier(&self.external_ref, buf);
        write_identifier(&self.policy_ref, buf);
        self.created_at.write(buf);
        write_identifier(&self.cohort_ref, buf);
        write_identifier(&self.status_reason, buf);
        self.status_changed_at.write(buf);
    }
}

impl Read for AccountProfile {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            account_id: read_identifier(buf)?,
            external_ref: read_identifier(buf)?,
            policy_ref: read_identifier(buf)?,
            created_at: u64::read(buf)?,
            cohort_ref: read_identifier(buf)?,
            status_reason: read_identifier(buf)?,
            status_changed_at: u64::read(buf)?,
        })
    }
}

impl EncodeSize for AccountProfile {
    fn encode_size(&self) -> usize {
        identifier_encode_size(&self.account_id)
            + identifier_encode_size(&self.external_ref)
            + identifier_encode_size(&self.policy_ref)
            + self.created_at.encode_size()
            + identifier_encode_size(&self.cohort_ref)
            + identifier_encode_size(&self.status_reason)
            + self.status_changed_at.encode_size()
    }
}

/// Append-only account-status history item. Reasons are opaque policy codes,
/// never employee names or free-form client data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusHistoryEntry {
    pub sequence: u64,
    pub status: AccountStatus,
    pub reason_code: String,
    pub changed_at: u64,
    pub approval_ref: String,
    pub audit_ref: String,
}

/// PII-safe control-plane evidence required for a V1 account-status change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusChangeMetadataV1 {
    pub reason_code: String,
    pub changed_at: u64,
    pub approval_ref: String,
    pub audit_ref: String,
}

/// Evidence for a V1 reservation lifecycle mutation. The chain stores only
/// opaque control-plane references; approval detail remains off-chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationActionMetadataV1 {
    pub reason_code: String,
    pub occurred_at: u64,
    pub approval_ref: String,
    pub audit_ref: String,
}

impl Write for ReservationActionMetadataV1 {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        write_identifier(&self.reason_code, buf);
        self.occurred_at.write(buf);
        write_identifier(&self.approval_ref, buf);
        write_identifier(&self.audit_ref, buf);
    }
}
impl Read for ReservationActionMetadataV1 {
    type Cfg = ();
    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self { reason_code: read_identifier(buf)?, occurred_at: u64::read(buf)?, approval_ref: read_identifier(buf)?, audit_ref: read_identifier(buf)? })
    }
}
impl EncodeSize for ReservationActionMetadataV1 {
    fn encode_size(&self) -> usize {
        identifier_encode_size(&self.reason_code) + self.occurred_at.encode_size()
            + identifier_encode_size(&self.approval_ref) + identifier_encode_size(&self.audit_ref)
    }
}

impl Write for StatusChangeMetadataV1 {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        write_identifier(&self.reason_code, buf);
        self.changed_at.write(buf);
        write_identifier(&self.approval_ref, buf);
        write_identifier(&self.audit_ref, buf);
    }
}
impl Read for StatusChangeMetadataV1 {
    type Cfg = ();
    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self { reason_code: read_identifier(buf)?, changed_at: u64::read(buf)?, approval_ref: read_identifier(buf)?, audit_ref: read_identifier(buf)? })
    }
}
impl EncodeSize for StatusChangeMetadataV1 {
    fn encode_size(&self) -> usize { identifier_encode_size(&self.reason_code) + self.changed_at.encode_size() + identifier_encode_size(&self.approval_ref) + identifier_encode_size(&self.audit_ref) }
}

/// Credit adjustment direction. Grants add credits; reversals debit only
/// available credits and can never consume a separate reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdjustmentKind {
    Grant,
    Reversal,
}

impl Write for AdjustmentKind {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Grant => ADJUSTMENT_GRANT.write(buf),
            Self::Reversal => ADJUSTMENT_REVERSAL.write(buf),
        }
    }
}

impl Read for AdjustmentKind {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            ADJUSTMENT_GRANT => Ok(Self::Grant),
            ADJUSTMENT_REVERSAL => Ok(Self::Reversal),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for AdjustmentKind {
    fn encode_size(&self) -> usize { 1 }
}

/// PII-safe, auditable metadata attached to an idempotent credit adjustment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdjustmentMetadata {
    pub reference: String,
    pub reason_code: String,
    pub period_ref: String,
    /// Off-chain approval and audit correlation identifiers. They are opaque
    /// references only; employee approval state remains outside the chain.
    pub approval_ref: String,
    pub audit_ref: String,
}

impl Write for AdjustmentMetadata {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        write_identifier(&self.reference, buf);
        write_identifier(&self.reason_code, buf);
        write_identifier(&self.period_ref, buf);
        write_identifier(&self.approval_ref, buf);
        write_identifier(&self.audit_ref, buf);
    }
}

impl Read for AdjustmentMetadata {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            reference: read_identifier(buf)?,
            reason_code: read_identifier(buf)?,
            period_ref: read_identifier(buf)?,
            approval_ref: read_identifier(buf)?,
            audit_ref: read_identifier(buf)?,
        })
    }
}

impl EncodeSize for AdjustmentMetadata {
    fn encode_size(&self) -> usize {
        identifier_encode_size(&self.reference)
            + identifier_encode_size(&self.reason_code)
            + identifier_encode_size(&self.period_ref)
            + identifier_encode_size(&self.approval_ref)
            + identifier_encode_size(&self.audit_ref)
    }
}

/// A coverage-only record for shared or dark cost. It cannot debit a client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrackedSourceV1 {
    pub source_id: String,
    pub reason_code: String,
    pub owner_ref: String,
    pub period_ref: String,
    pub provenance_ref: String,
    /// Coverage and confidence are controlled opaque taxonomy codes such as
    /// `cost_dark` and `unverified`; evidence remains an opaque reference.
    pub coverage_code: String,
    pub confidence_code: String,
    pub evidence_ref: String,
    pub cohort_ref: String,
}

/// Client-safe, private account read returned to an authorized backend/BFF.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountReadV1 {
    pub account: CreditAccount,
    pub profile: AccountProfile,
}

/// A credit-only quote resolved from an applied rate card. It contains no
/// provider COGS, margin, confidence, or approval metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuoteV1 {
    pub quote_id: String,
    pub snapshot_hash: String,
    pub account_id: String,
    pub event_category: String,
    pub task_key: String,
    pub quoted_at: u64,
    pub credits_per_unit: u64,
    pub quantity: u64,
    pub total_credits: u64,
    pub policy_version: String,
    pub rate_version: String,
    pub expires_at: u64,
}

pub(crate) fn write_quote_snapshot(quote: &QuoteV1, buf: &mut impl bytes::BufMut) {
    write_identifier(&quote.quote_id, buf);
    write_identifier(&quote.snapshot_hash, buf);
    write_identifier(&quote.account_id, buf);
    write_identifier(&quote.event_category, buf);
    write_identifier(&quote.task_key, buf);
    quote.quoted_at.write(buf);
    quote.credits_per_unit.write(buf);
    quote.quantity.write(buf);
    quote.total_credits.write(buf);
    write_identifier(&quote.policy_version, buf);
    write_identifier(&quote.rate_version, buf);
    quote.expires_at.write(buf);
}

pub(crate) fn read_quote_snapshot(buf: &mut impl bytes::Buf) -> Result<QuoteV1, Error> {
    Ok(QuoteV1 {
        quote_id: read_identifier(buf)?, snapshot_hash: read_identifier(buf)?,
        account_id: read_identifier(buf)?, event_category: read_identifier(buf)?,
        task_key: read_identifier(buf)?, quoted_at: u64::read(buf)?,
        credits_per_unit: u64::read(buf)?, quantity: u64::read(buf)?,
        total_credits: u64::read(buf)?, policy_version: read_identifier(buf)?,
        rate_version: read_identifier(buf)?, expires_at: u64::read(buf)?,
    })
}

pub(crate) fn quote_snapshot_encode_size(quote: &QuoteV1) -> usize {
    identifier_encode_size(&quote.quote_id) + identifier_encode_size(&quote.snapshot_hash)
        + identifier_encode_size(&quote.account_id) + identifier_encode_size(&quote.event_category)
        + identifier_encode_size(&quote.task_key) + quote.quoted_at.encode_size()
        + quote.credits_per_unit.encode_size() + quote.quantity.encode_size()
        + quote.total_credits.encode_size() + identifier_encode_size(&quote.policy_version)
        + identifier_encode_size(&quote.rate_version) + quote.expires_at.encode_size()
}

/// A private request to price a specific quantity. The client receives only
/// the resulting credit quote, not COGS or policy approval detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuoteRequestV1 {
    pub account_id: String,
    pub event_category: String,
    pub task_key: String,
    pub quantity: u64,
    pub quoted_at: u64,
    pub expires_at: u64,
}

/// The typed category of a persisted, post-state ledger mutation. This is a
/// private read contract for the finality sink and operational projections;
/// it is never an input transaction and cannot authorize a debit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerMutationKind {
    AccountOnboarded,
    BalanceChanged,
    SpendRecorded,
    AccountStatusChanged,
    ReservationChanged,
    RateCardStaged,
    RateCardApplied,
    RateCardGlobalApplied,
    RateCardCompleted,
    UntrackedSourceRegistered,
}

/// Explicit financial direction for a persisted balance mutation. A finality
/// sink must consume this field rather than infer a debit/credit from the
/// transaction that happened to produce the mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BalanceMutationDirection { None, Credit, Debit }

impl Write for BalanceMutationDirection { fn write(&self, buf: &mut impl bytes::BufMut) { match self { Self::None => BALANCE_DIRECTION_NONE, Self::Credit => BALANCE_DIRECTION_CREDIT, Self::Debit => BALANCE_DIRECTION_DEBIT }.write(buf); } }
impl Read for BalanceMutationDirection { type Cfg = (); fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> { match u8::read(buf)? { BALANCE_DIRECTION_NONE => Ok(Self::None), BALANCE_DIRECTION_CREDIT => Ok(Self::Credit), BALANCE_DIRECTION_DEBIT => Ok(Self::Debit), tag => Err(Error::InvalidEnum(tag)) } } }
impl EncodeSize for BalanceMutationDirection { fn encode_size(&self) -> usize { 1 } }

impl Write for LedgerMutationKind {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::AccountOnboarded => JOURNAL_ONBOARDED.write(buf),
            Self::BalanceChanged => JOURNAL_BALANCE_CHANGED.write(buf),
            Self::SpendRecorded => JOURNAL_SPEND_RECORDED.write(buf),
            Self::AccountStatusChanged => JOURNAL_STATUS_CHANGED.write(buf),
            Self::ReservationChanged => JOURNAL_RESERVATION_CHANGED.write(buf),
            Self::RateCardStaged => JOURNAL_RATE_STAGED.write(buf),
            Self::RateCardApplied => JOURNAL_RATE_APPLIED.write(buf),
            Self::RateCardGlobalApplied => JOURNAL_RATE_GLOBAL_APPLIED.write(buf),
            Self::RateCardCompleted => JOURNAL_RATE_CARD_COMPLETED.write(buf),
            Self::UntrackedSourceRegistered => JOURNAL_UNTRACKED_SOURCE_REGISTERED.write(buf),
        }
    }
}

impl Read for LedgerMutationKind {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            JOURNAL_ONBOARDED => Ok(Self::AccountOnboarded),
            JOURNAL_BALANCE_CHANGED => Ok(Self::BalanceChanged),
            JOURNAL_SPEND_RECORDED => Ok(Self::SpendRecorded),
            JOURNAL_STATUS_CHANGED => Ok(Self::AccountStatusChanged),
            JOURNAL_RESERVATION_CHANGED => Ok(Self::ReservationChanged),
            JOURNAL_RATE_STAGED => Ok(Self::RateCardStaged),
            JOURNAL_RATE_APPLIED => Ok(Self::RateCardApplied),
            JOURNAL_RATE_GLOBAL_APPLIED => Ok(Self::RateCardGlobalApplied),
            JOURNAL_RATE_CARD_COMPLETED => Ok(Self::RateCardCompleted),
            JOURNAL_UNTRACKED_SOURCE_REGISTERED => Ok(Self::UntrackedSourceRegistered),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for LedgerMutationKind {
    fn encode_size(&self) -> usize { 1 }
}

/// Append-only, ledger-generated post-state record. Empty values mean that a
/// field does not apply to this mutation; `has_*` flags distinguish absence
/// from a valid zero balance. The record contains only opaque references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerMutationV1 {
    pub sequence: u64,
    pub transaction_id: String,
    pub kind: LedgerMutationKind,
    pub account_id: String,
    pub has_account: bool,
    pub account: CreditAccount,
    pub cohort_ref: String,
    pub source_ref: String,
    pub balance_direction: BalanceMutationDirection,
    /// Absolute credit movement for a balance mutation; zero when this journal
    /// entry is not a balance-changing operation.
    pub credit_delta: u64,
    /// Finance-close period associated with a grant or reversal.
    pub period_ref: String,
    /// Control-plane evidence for status, reservation, and rate lifecycle
    /// records. Empty only when the mutation category does not require it.
    pub reason_code: String,
    pub occurred_at: u64,
    pub approval_ref: String,
    pub audit_ref: String,
    pub has_reservation: bool,
    pub reservation: Reservation,
    pub rate_change_set_id: String,
    pub has_rate: bool,
    pub rate: RateCardEntry,
    pub has_untracked_source: bool,
    pub untracked_source: UntrackedSourceV1,
    pub has_rate_card_completion: bool,
    pub rate_card_completion: RateCardCompletionV1,
}

impl Write for LedgerMutationV1 {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.sequence.write(buf);
        write_identifier(&self.transaction_id, buf);
        self.kind.write(buf);
        write_identifier(&self.account_id, buf);
        self.has_account.write(buf);
        self.account.write(buf);
        write_identifier(&self.cohort_ref, buf);
        write_identifier(&self.source_ref, buf);
        self.balance_direction.write(buf);
        self.credit_delta.write(buf);
        write_identifier(&self.period_ref, buf);
        write_identifier(&self.reason_code, buf);
        self.occurred_at.write(buf);
        write_identifier(&self.approval_ref, buf);
        write_identifier(&self.audit_ref, buf);
        self.has_reservation.write(buf);
        self.reservation.write(buf);
        write_identifier(&self.rate_change_set_id, buf);
        self.has_rate.write(buf);
        self.rate.write(buf);
        self.has_untracked_source.write(buf);
        self.untracked_source.write(buf);
        self.has_rate_card_completion.write(buf);
        self.rate_card_completion.write(buf);
    }
}

impl Read for LedgerMutationV1 {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            sequence: u64::read(buf)?, transaction_id: read_identifier(buf)?,
            kind: LedgerMutationKind::read(buf)?, account_id: read_identifier(buf)?,
            has_account: bool::read(buf)?, account: CreditAccount::read(buf)?,
            cohort_ref: read_identifier(buf)?, source_ref: read_identifier(buf)?,
            balance_direction: BalanceMutationDirection::read(buf)?, credit_delta: u64::read(buf)?, period_ref: read_identifier(buf)?,
            reason_code: read_identifier(buf)?, occurred_at: u64::read(buf)?,
            approval_ref: read_identifier(buf)?, audit_ref: read_identifier(buf)?,
            has_reservation: bool::read(buf)?, reservation: Reservation::read(buf)?,
            rate_change_set_id: read_identifier(buf)?, has_rate: bool::read(buf)?,
            rate: RateCardEntry::read(buf)?, has_untracked_source: bool::read(buf)?,
            untracked_source: UntrackedSourceV1::read(buf)?,
            has_rate_card_completion: bool::read(buf)?, rate_card_completion: RateCardCompletionV1::read(buf)?,
        })
    }
}

impl EncodeSize for LedgerMutationV1 {
    fn encode_size(&self) -> usize {
        self.sequence.encode_size() + identifier_encode_size(&self.transaction_id)
            + self.kind.encode_size() + identifier_encode_size(&self.account_id)
            + self.has_account.encode_size() + self.account.encode_size()
            + identifier_encode_size(&self.cohort_ref) + identifier_encode_size(&self.source_ref)
            + self.balance_direction.encode_size() + self.credit_delta.encode_size() + identifier_encode_size(&self.period_ref)
            + identifier_encode_size(&self.reason_code) + self.occurred_at.encode_size()
            + identifier_encode_size(&self.approval_ref) + identifier_encode_size(&self.audit_ref)
            + self.has_reservation.encode_size() + self.reservation.encode_size()
            + identifier_encode_size(&self.rate_change_set_id) + self.has_rate.encode_size()
            + self.rate.encode_size() + self.has_untracked_source.encode_size()
            + self.untracked_source.encode_size() + self.has_rate_card_completion.encode_size()
            + self.rate_card_completion.encode_size()
    }
}

impl Write for UntrackedSourceV1 {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        write_identifier(&self.source_id, buf);
        write_identifier(&self.reason_code, buf);
        write_identifier(&self.owner_ref, buf);
        write_identifier(&self.period_ref, buf);
        write_identifier(&self.provenance_ref, buf);
        write_identifier(&self.coverage_code, buf);
        write_identifier(&self.confidence_code, buf);
        write_identifier(&self.evidence_ref, buf);
        write_identifier(&self.cohort_ref, buf);
    }
}

impl Read for UntrackedSourceV1 {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            source_id: read_identifier(buf)?,
            reason_code: read_identifier(buf)?,
            owner_ref: read_identifier(buf)?,
            period_ref: read_identifier(buf)?,
            provenance_ref: read_identifier(buf)?,
            coverage_code: read_identifier(buf)?,
            confidence_code: read_identifier(buf)?,
            evidence_ref: read_identifier(buf)?,
            cohort_ref: read_identifier(buf)?,
        })
    }
}

impl EncodeSize for UntrackedSourceV1 {
    fn encode_size(&self) -> usize {
        identifier_encode_size(&self.source_id)
            + identifier_encode_size(&self.reason_code)
            + identifier_encode_size(&self.owner_ref)
            + identifier_encode_size(&self.period_ref)
            + identifier_encode_size(&self.provenance_ref)
            + identifier_encode_size(&self.coverage_code)
            + identifier_encode_size(&self.confidence_code)
            + identifier_encode_size(&self.evidence_ref)
            + identifier_encode_size(&self.cohort_ref)
    }
}

impl Write for Reservation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        write_identifier(&self.reservation_id, buf);
        write_identifier(&self.account_id, buf);
        write_quote_snapshot(&self.quote, buf);
        write_identifier(&self.lineage_ref, buf);
        self.credits.write(buf);
        self.expires_at.write(buf);
        self.status.write(buf);
    }
}

impl Read for Reservation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            reservation_id: read_identifier(buf)?,
            account_id: read_identifier(buf)?,
            quote: read_quote_snapshot(buf)?,
            lineage_ref: read_identifier(buf)?,
            credits: u64::read(buf)?,
            expires_at: u64::read(buf)?,
            status: ReservationStatus::read(buf)?,
        })
    }
}

impl EncodeSize for Reservation {
    fn encode_size(&self) -> usize {
        identifier_encode_size(&self.reservation_id)
            + identifier_encode_size(&self.account_id)
            + quote_snapshot_encode_size(&self.quote)
            + identifier_encode_size(&self.lineage_ref)
            + self.credits.encode_size()
            + self.expires_at.encode_size()
            + self.status.encode_size()
    }
}

impl Write for StatusHistoryEntry {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.sequence.write(buf); self.status.write(buf); write_identifier(&self.reason_code, buf);
        self.changed_at.write(buf); write_identifier(&self.approval_ref, buf); write_identifier(&self.audit_ref, buf);
    }
}
impl Read for StatusHistoryEntry {
    type Cfg = ();
    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self { sequence: u64::read(buf)?, status: AccountStatus::read(buf)?, reason_code: read_identifier(buf)?, changed_at: u64::read(buf)?, approval_ref: read_identifier(buf)?, audit_ref: read_identifier(buf)? })
    }
}
impl EncodeSize for StatusHistoryEntry {
    fn encode_size(&self) -> usize { self.sequence.encode_size() + self.status.encode_size() + identifier_encode_size(&self.reason_code) + self.changed_at.encode_size() + identifier_encode_size(&self.approval_ref) + identifier_encode_size(&self.audit_ref) }
}

/// One effective-at credit rate. Empty `account_id` denotes a global default and
/// empty `task_key` denotes a category-level default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateCardEntry {
    pub account_id: String,
    pub event_category: String,
    pub task_key: String,
    pub credits: u64,
    pub effective_at: u64,
    /// Zero denotes no expiry.
    pub expires_at: u64,
    pub policy_version: String,
    pub rate_version: String,
}

impl Write for RateCardEntry {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        write_identifier(&self.account_id, buf);
        write_identifier(&self.event_category, buf);
        write_identifier(&self.task_key, buf);
        self.credits.write(buf);
        self.effective_at.write(buf);
        self.expires_at.write(buf);
        write_identifier(&self.policy_version, buf);
        write_identifier(&self.rate_version, buf);
    }
}

impl Read for RateCardEntry {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            account_id: read_identifier(buf)?,
            event_category: read_identifier(buf)?,
            task_key: read_identifier(buf)?,
            credits: u64::read(buf)?,
            effective_at: u64::read(buf)?,
            expires_at: u64::read(buf)?,
            policy_version: read_identifier(buf)?,
            rate_version: read_identifier(buf)?,
        })
    }
}

impl EncodeSize for RateCardEntry {
    fn encode_size(&self) -> usize {
        identifier_encode_size(&self.account_id)
            + identifier_encode_size(&self.event_category)
            + identifier_encode_size(&self.task_key)
            + self.credits.encode_size()
            + self.effective_at.encode_size()
            + self.expires_at.encode_size()
            + identifier_encode_size(&self.policy_version)
            + identifier_encode_size(&self.rate_version)
    }
}

/// Metadata for a staged, finance-approved atomic rate change set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateCardChangeSet {
    pub change_set_id: String,
    pub expected_entry_count: u16,
    pub target_account_ids: Vec<String>,
    pub expected_target_count: u16,
    pub manifest_hash: String,
    pub staged_entry_count: u16,
    /// Opaque finance approval correlation. This is required before a staged
    /// card may be activated; the detailed approval record stays off-chain.
    pub approval_ref: String,
    /// Required append-only audit correlation for both staging and apply.
    pub audit_ref: String,
    /// Monotonic activation epoch supplied by the control plane.
    pub activation_epoch: u64,
    /// Makes exact activation replay a no-op and prevents historical rewrite.
    pub applied: bool,
}

/// Explicit V1 name for the finance-approved, atomic rate-card envelope.
pub type RateCardChangeSetV1 = RateCardChangeSet;

impl RateCardChangeSet {
    /// Compute the only valid V1 manifest hash. This hashes finance evidence
    /// and the complete approved payload, not a caller-provided label.
    #[allow(clippy::too_many_arguments)] // public, explicit approval-envelope inputs
    pub fn canonical_manifest_hash(
        change_set_id: &str,
        approval_ref: &str,
        audit_ref: &str,
        activation_epoch: u64,
        expected_entry_count: u16,
        target_account_ids: &[String],
        expected_target_count: u16,
        entries: &[RateCardEntry],
    ) -> String {
        const DOMAIN: &[u8] = b"_NUNCHI_COSTS_RATE_CARD_CHANGE_SET_V1_MANIFEST\0";
        let mut bytes = DOMAIN.to_vec();
        write_manifest_string(&mut bytes, change_set_id);
        write_manifest_string(&mut bytes, approval_ref);
        write_manifest_string(&mut bytes, audit_ref);
        bytes.extend_from_slice(&activation_epoch.to_be_bytes());
        bytes.extend_from_slice(&expected_entry_count.to_be_bytes());

        let mut targets = target_account_ids.to_vec();
        targets.sort();
        bytes.extend_from_slice(&(targets.len() as u32).to_be_bytes());
        for target in targets { write_manifest_string(&mut bytes, &target); }
        bytes.extend_from_slice(&expected_target_count.to_be_bytes());

        let mut entries = entries.to_vec();
        entries.sort_by(|left, right| rate_card_sort_key(left).cmp(&rate_card_sort_key(right)));
        bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for entry in entries {
            write_manifest_string(&mut bytes, &entry.account_id);
            write_manifest_string(&mut bytes, &entry.event_category);
            write_manifest_string(&mut bytes, &entry.task_key);
            bytes.extend_from_slice(&entry.credits.to_be_bytes());
            bytes.extend_from_slice(&entry.effective_at.to_be_bytes());
            bytes.extend_from_slice(&entry.expires_at.to_be_bytes());
            write_manifest_string(&mut bytes, &entry.policy_version);
            write_manifest_string(&mut bytes, &entry.rate_version);
        }
        Sha256::hash(&bytes).to_string()
    }

    pub fn expected_manifest_hash(&self, entries: &[RateCardEntry]) -> String {
        Self::canonical_manifest_hash(
            &self.change_set_id, &self.approval_ref, &self.audit_ref, self.activation_epoch,
            self.expected_entry_count, &self.target_account_ids,
            self.expected_target_count, entries,
        )
    }
}

fn write_manifest_string(bytes: &mut Vec<u8>, value: &str) {
    let length = u32::try_from(value.len()).expect("manifest field exceeds u32 encoding limit");
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn rate_card_sort_key(entry: &RateCardEntry) -> (&str, &str, &str, u64, u64, u64, &str, &str) {
    (&entry.account_id, &entry.event_category, &entry.task_key, entry.credits, entry.effective_at,
        entry.expires_at, &entry.policy_version, &entry.rate_version)
}

/// One durable completion record for a successfully activated approved card.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateCardCompletionV1 {
    pub change_set_id: String,
    pub manifest_hash: String,
    pub entry_count: u16,
    pub target_count: u16,
    pub activation_epoch: u64,
    pub approval_ref: String,
    pub audit_ref: String,
    /// Exact base and materialized target revisions activated by this card.
    /// These carry only credits and opaque policy/rate versions, never COGS.
    pub affected_rates: Vec<RateCardEntry>,
}

impl Write for RateCardCompletionV1 {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        write_identifier(&self.change_set_id, buf); write_identifier(&self.manifest_hash, buf);
        self.entry_count.write(buf); self.target_count.write(buf); self.activation_epoch.write(buf);
        write_identifier(&self.approval_ref, buf); write_identifier(&self.audit_ref, buf);
        (self.affected_rates.len() as u16).write(buf);
        for rate in &self.affected_rates { rate.write(buf); }
    }
}
impl Read for RateCardCompletionV1 {
    type Cfg = ();
    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self { change_set_id: read_identifier(buf)?, manifest_hash: read_identifier(buf)?,
            entry_count: u16::read(buf)?, target_count: u16::read(buf)?, activation_epoch: u64::read(buf)?,
            approval_ref: read_identifier(buf)?, audit_ref: read_identifier(buf)?,
            affected_rates: { let count = u16::read(buf)? as usize; let mut rates = Vec::with_capacity(count); for _ in 0..count { rates.push(RateCardEntry::read(buf)?); } rates }, })
    }
}
impl EncodeSize for RateCardCompletionV1 {
    fn encode_size(&self) -> usize {
        identifier_encode_size(&self.change_set_id) + identifier_encode_size(&self.manifest_hash)
            + self.entry_count.encode_size() + self.target_count.encode_size() + self.activation_epoch.encode_size()
            + identifier_encode_size(&self.approval_ref) + identifier_encode_size(&self.audit_ref)
            + u16::default().encode_size() + self.affected_rates.iter().map(EncodeSize::encode_size).sum::<usize>()
    }
}

impl Write for RateCardChangeSet {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        write_identifier(&self.change_set_id, buf);
        self.expected_entry_count.write(buf);
        (self.target_account_ids.len() as u16).write(buf);
        for account_id in &self.target_account_ids { write_identifier(account_id, buf); }
        self.expected_target_count.write(buf);
        write_identifier(&self.manifest_hash, buf);
        self.staged_entry_count.write(buf);
        write_identifier(&self.approval_ref, buf);
        write_identifier(&self.audit_ref, buf);
        self.activation_epoch.write(buf);
        self.applied.write(buf);
    }
}

impl Read for RateCardChangeSet {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            change_set_id: read_identifier(buf)?,
            expected_entry_count: u16::read(buf)?,
            target_account_ids: { let count = u16::read(buf)? as usize; let mut accounts = Vec::with_capacity(count); for _ in 0..count { accounts.push(read_identifier(buf)?); } accounts },
            expected_target_count: u16::read(buf)?,
            manifest_hash: read_identifier(buf)?,
            staged_entry_count: u16::read(buf)?,
            approval_ref: read_identifier(buf)?,
            audit_ref: read_identifier(buf)?,
            activation_epoch: u64::read(buf)?,
            applied: bool::read(buf)?,
        })
    }
}

impl EncodeSize for RateCardChangeSet {
    fn encode_size(&self) -> usize {
        identifier_encode_size(&self.change_set_id)
            + self.expected_entry_count.encode_size()
            + u16::default().encode_size() + self.target_account_ids.iter().map(|account_id| identifier_encode_size(account_id)).sum::<usize>() + self.expected_target_count.encode_size()
            + identifier_encode_size(&self.manifest_hash)
            + self.staged_entry_count.encode_size()
            + identifier_encode_size(&self.approval_ref)
            + identifier_encode_size(&self.audit_ref)
            + self.activation_epoch.encode_size()
            + self.applied.encode_size()
    }
}

/// A normalized, PII-free metered debit input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendRecordV1 {
    pub event_id: String,
    pub account_id: String,
    pub event_category: String,
    /// Empty only for legacy fixture records. Real records use the exact
    /// rate-card task key and are validated against the pinned snapshot.
    pub task_key: String,
    pub quantity: u64,
    pub credits: u64,
    pub observed_at: u64,
    pub policy_version: String,
    pub rate_version: String,
    /// Opaque, non-PII source and lineage identifiers for reconciliation.
    pub source_ref: String,
    pub lineage_ref: String,
    /// Optional application cohort used by finality consumers to isolate
    /// exports; it does not change the account's debit semantics.
    pub cohort_ref: String,
}

impl Write for SpendRecordV1 {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        write_identifier(&self.event_id, buf);
        write_identifier(&self.account_id, buf);
        write_identifier(&self.event_category, buf);
        write_identifier(&self.task_key, buf);
        self.quantity.write(buf);
        self.credits.write(buf);
        self.observed_at.write(buf);
        write_identifier(&self.policy_version, buf);
        write_identifier(&self.rate_version, buf);
        write_identifier(&self.source_ref, buf);
        write_identifier(&self.lineage_ref, buf);
        write_identifier(&self.cohort_ref, buf);
    }
}

impl Read for SpendRecordV1 {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            event_id: read_identifier(buf)?,
            account_id: read_identifier(buf)?,
            event_category: read_identifier(buf)?,
            task_key: read_identifier(buf)?,
            quantity: u64::read(buf)?,
            credits: u64::read(buf)?,
            observed_at: u64::read(buf)?,
            policy_version: read_identifier(buf)?,
            rate_version: read_identifier(buf)?,
            source_ref: read_identifier(buf)?,
            lineage_ref: read_identifier(buf)?,
            cohort_ref: read_identifier(buf)?,
        })
    }
}

impl EncodeSize for SpendRecordV1 {
    fn encode_size(&self) -> usize {
        identifier_encode_size(&self.event_id)
            + identifier_encode_size(&self.account_id)
            + identifier_encode_size(&self.event_category)
            + identifier_encode_size(&self.task_key)
            + self.quantity.encode_size()
            + self.credits.encode_size()
            + self.observed_at.encode_size()
            + identifier_encode_size(&self.policy_version)
            + identifier_encode_size(&self.rate_version)
            + identifier_encode_size(&self.source_ref)
            + identifier_encode_size(&self.lineage_ref)
            + identifier_encode_size(&self.cohort_ref)
    }
}
