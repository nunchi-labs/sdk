//! Clean-state V2 provenance ledger for refundable B2B stored value.
//!
//! Paid lots refund only to their original rail; grant lots are non-refundable;
//! spend deterministically consumes grants before paid credit.

use std::collections::BTreeMap;
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::types::{identifier_encode_size, read_identifier, write_identifier};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum CreditLotKind { Grant, Paid }

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CreditLotV2 { lot_id: String, account_id: String, kind: CreditLotKind, remaining: u64, reserved: u64, issued_at: u64, expires_at: u64, period_ref: String, amount_usd_cents: u64, base_credits: u64, bonus_credits: u64, terms_version: String, reason_code: String }

/// Immutable paid purchase. `rail_ref` is both idempotency key and lot ID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreditTopupV2 { pub account_id: String, pub rail_ref: String, pub amount_usd_cents: u64, pub base_credits: u64, pub bonus_credits: u64, pub purchased_at: u64, pub terms_version: String }

/// Immutable non-refundable periodic program/campaign grant with a policy-defined expiry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreditGrantV2 { pub account_id: String, pub reference: String, pub credits: u64, pub reason_code: String, pub period_ref: String, pub issued_at: u64, pub expires_at: u64, pub approval_ref: String, pub audit_ref: String }

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredValueSpendV2 { pub event_id: String, pub account_id: String, pub credits: u64, pub occurred_at: u64 }

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LotAllocationV1 { pub lot_id: String, pub kind: CreditLotKind, pub credits: u64 }

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum StoredValueReservationStatus { Active, Released, Settled, Expired }

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredValueReservationV1 { pub reservation_id: String, pub account_id: String, pub credits: u64, pub expires_at: u64, pub allocations: Vec<LotAllocationV1>, pub status: StoredValueReservationStatus }

/// Support-mediated reversal of unused paid credit to the original rail.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RefundPaidLotV1 { pub account_id: String, pub rail_ref: String, pub refund_rail_ref: String, pub credits: u64, pub requested_at: u64, pub reason_code: String, pub approval_ref: String, pub audit_ref: String }

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredValueAccountReadV1 { pub account_id: String, pub paid_available_credits: u64, pub grant_available_credits: u64, pub reserved_credits: u64, pub refundable_paid_credits: u64, pub included_period_consumed: u64, pub reset_at: u64 }

/// Immutable ledger payload retained in chain state for a finality adapter.
/// It is never a transaction input and is published only after the containing
/// transaction reaches chain finality.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum StoredValueFinalityPayloadV1 {
    Topup(CreditTopupV2),
    Grant(CreditGrantV2),
    Spend { spend: StoredValueSpendV2, allocations: Vec<LotAllocationV1> },
    Refund(RefundPaidLotV1),
}

/// Append-only bridge from the V2 chain ledger to post-finality downstream warehouse, accounting export,
/// and client-safe projections. This is state output, not a chain command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredValueFinalityEventV1 {
    pub sequence: u64,
    pub event_key: String,
    pub transaction_id: String,
    pub account_id: String,
    pub payload: StoredValueFinalityPayloadV1,
}

/// Private BFF/sink lot history. It contains no payment credentials or PII.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredValueLotReadV1 { pub lot_id: String, pub account_id: String, pub kind: CreditLotKind, pub amount_usd_cents: u64, pub base_credits: u64, pub bonus_credits: u64, pub remaining_credits: u64, pub reserved_credits: u64, pub issued_at: u64, pub expires_at: u64, pub terms_version: String, pub reason_code: String, pub period_ref: String }

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum StoredValueError {
    #[error("invalid {0}")] Invalid(&'static str),
    #[error("account {0} was not initialized for stored value")] AccountNotFound(String),
    #[error("idempotency conflict for {0}")] IdempotencyConflict(String),
    #[error("insufficient credits: available {available}, required {required}")] InsufficientCredits { available: u64, required: u64 },
    #[error("paid lot {0} was not found")] PaidLotNotFound(String),
    #[error("paid lot {0} has reserved credits")] PaidLotReserved(String),
    #[error("refund {refund_id} exceeds unused paid credit in {rail_ref}")] RefundExceedsUnused { refund_id: String, rail_ref: String },
    #[error("reservation {0} was not found")] ReservationNotFound(String),
    #[error("reservation {0} is not active")] ReservationNotActive(String),
    #[error("reservation {0} expired")] ReservationExpired(String),
    #[error("arithmetic overflow")] Overflow,
}

/// Deterministic V2 economic state. Network, signer, downstream warehouse, and UI adapters are
/// deliberately outside this state machine.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StoredValueLedger {
    accounts: BTreeMap<String, ()>, lots: BTreeMap<String, CreditLotV2>,
    spends: BTreeMap<String, (StoredValueSpendV2, Vec<LotAllocationV1>)>,
    reservations: BTreeMap<String, StoredValueReservationV1>,
    refunds: BTreeMap<String, RefundPaidLotV1>, consumed_by_lot: BTreeMap<String, u64>,
    finality_events: Vec<StoredValueFinalityEventV1>,
}

impl Write for CreditTopupV2 { fn write(&self, buf: &mut impl bytes::BufMut) { write_identifier(&self.account_id, buf); write_identifier(&self.rail_ref, buf); self.amount_usd_cents.write(buf); self.base_credits.write(buf); self.bonus_credits.write(buf); self.purchased_at.write(buf); write_identifier(&self.terms_version, buf); } }
impl Read for CreditTopupV2 { type Cfg = (); fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> { Ok(Self { account_id: read_identifier(buf)?, rail_ref: read_identifier(buf)?, amount_usd_cents: u64::read(buf)?, base_credits: u64::read(buf)?, bonus_credits: u64::read(buf)?, purchased_at: u64::read(buf)?, terms_version: read_identifier(buf)? }) } }
impl EncodeSize for CreditTopupV2 { fn encode_size(&self) -> usize { identifier_encode_size(&self.account_id) + identifier_encode_size(&self.rail_ref) + self.amount_usd_cents.encode_size() + self.base_credits.encode_size() + self.bonus_credits.encode_size() + self.purchased_at.encode_size() + identifier_encode_size(&self.terms_version) } }

impl Write for CreditGrantV2 { fn write(&self, buf: &mut impl bytes::BufMut) { write_identifier(&self.account_id, buf); write_identifier(&self.reference, buf); self.credits.write(buf); write_identifier(&self.reason_code, buf); write_identifier(&self.period_ref, buf); self.issued_at.write(buf); self.expires_at.write(buf); write_identifier(&self.approval_ref, buf); write_identifier(&self.audit_ref, buf); } }
impl Read for CreditGrantV2 { type Cfg = (); fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> { Ok(Self { account_id: read_identifier(buf)?, reference: read_identifier(buf)?, credits: u64::read(buf)?, reason_code: read_identifier(buf)?, period_ref: read_identifier(buf)?, issued_at: u64::read(buf)?, expires_at: u64::read(buf)?, approval_ref: read_identifier(buf)?, audit_ref: read_identifier(buf)? }) } }
impl EncodeSize for CreditGrantV2 { fn encode_size(&self) -> usize { identifier_encode_size(&self.account_id) + identifier_encode_size(&self.reference) + self.credits.encode_size() + identifier_encode_size(&self.reason_code) + identifier_encode_size(&self.period_ref) + self.issued_at.encode_size() + self.expires_at.encode_size() + identifier_encode_size(&self.approval_ref) + identifier_encode_size(&self.audit_ref) } }

impl Write for StoredValueSpendV2 { fn write(&self, buf: &mut impl bytes::BufMut) { write_identifier(&self.event_id, buf); write_identifier(&self.account_id, buf); self.credits.write(buf); self.occurred_at.write(buf); } }
impl Read for StoredValueSpendV2 { type Cfg = (); fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> { Ok(Self { event_id: read_identifier(buf)?, account_id: read_identifier(buf)?, credits: u64::read(buf)?, occurred_at: u64::read(buf)? }) } }
impl EncodeSize for StoredValueSpendV2 { fn encode_size(&self) -> usize { identifier_encode_size(&self.event_id) + identifier_encode_size(&self.account_id) + self.credits.encode_size() + self.occurred_at.encode_size() } }

impl Write for RefundPaidLotV1 { fn write(&self, buf: &mut impl bytes::BufMut) { write_identifier(&self.account_id, buf); write_identifier(&self.rail_ref, buf); write_identifier(&self.refund_rail_ref, buf); self.credits.write(buf); self.requested_at.write(buf); write_identifier(&self.reason_code, buf); write_identifier(&self.approval_ref, buf); write_identifier(&self.audit_ref, buf); } }
impl Read for RefundPaidLotV1 { type Cfg = (); fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> { Ok(Self { account_id: read_identifier(buf)?, rail_ref: read_identifier(buf)?, refund_rail_ref: read_identifier(buf)?, credits: u64::read(buf)?, requested_at: u64::read(buf)?, reason_code: read_identifier(buf)?, approval_ref: read_identifier(buf)?, audit_ref: read_identifier(buf)? }) } }
impl EncodeSize for RefundPaidLotV1 { fn encode_size(&self) -> usize { identifier_encode_size(&self.account_id) + identifier_encode_size(&self.rail_ref) + identifier_encode_size(&self.refund_rail_ref) + self.credits.encode_size() + self.requested_at.encode_size() + identifier_encode_size(&self.reason_code) + identifier_encode_size(&self.approval_ref) + identifier_encode_size(&self.audit_ref) } }

impl StoredValueLedger {
    pub fn onboard(&mut self, account_id: &str) -> Result<(), StoredValueError> { validate(account_id, "account_id")?; self.accounts.insert(account_id.into(), ()); Ok(()) }

    pub fn credit_topup(&mut self, topup: CreditTopupV2) -> Result<(), StoredValueError> {
        self.require_account(&topup.account_id)?; validate(&topup.rail_ref, "rail_ref")?; validate(&topup.terms_version, "terms_version")?;
        if topup.amount_usd_cents == 0 || topup.purchased_at == 0 { return Err(StoredValueError::Invalid("purchase_amount_or_time")); }
        let total = topup.base_credits.checked_add(topup.bonus_credits).ok_or(StoredValueError::Overflow)?;
        if total == 0 { return Err(StoredValueError::Invalid("total_credits")); }
        self.insert_lot(topup.rail_ref.clone(), CreditLotV2 { lot_id: topup.rail_ref, account_id: topup.account_id, kind: CreditLotKind::Paid, remaining: total, reserved: 0, issued_at: topup.purchased_at, expires_at: 0, period_ref: String::new(), amount_usd_cents: topup.amount_usd_cents, base_credits: topup.base_credits, bonus_credits: topup.bonus_credits, terms_version: topup.terms_version, reason_code: "topup".into() })
    }

    pub fn credit_grant(&mut self, grant: CreditGrantV2) -> Result<(), StoredValueError> {
        self.require_account(&grant.account_id)?;
        for (value, field) in [(&grant.reference, "grant_reference"), (&grant.reason_code, "grant_reason"), (&grant.period_ref, "grant_period"), (&grant.approval_ref, "approval_ref"), (&grant.audit_ref, "audit_ref")] { validate(value, field)?; }
        if grant.credits == 0 || grant.issued_at == 0 || grant.expires_at <= grant.issued_at { return Err(StoredValueError::Invalid("grant_credits_or_expiry")); }
        self.insert_lot(grant.reference.clone(), CreditLotV2 { lot_id: grant.reference, account_id: grant.account_id, kind: CreditLotKind::Grant, remaining: grant.credits, reserved: 0, issued_at: grant.issued_at, expires_at: grant.expires_at, period_ref: grant.period_ref, amount_usd_cents: 0, base_credits: grant.credits, bonus_credits: 0, terms_version: String::new(), reason_code: grant.reason_code })
    }

    pub fn record_spend(&mut self, spend: StoredValueSpendV2) -> Result<Vec<LotAllocationV1>, StoredValueError> {
        self.require_account(&spend.account_id)?; validate(&spend.event_id, "event_id")?;
        if spend.credits == 0 || spend.occurred_at == 0 { return Err(StoredValueError::Invalid("spend_credits_or_time")); }
        if let Some((existing, allocations)) = self.spends.get(&spend.event_id) { return if existing == &spend { Ok(allocations.clone()) } else { Err(StoredValueError::IdempotencyConflict(spend.event_id)) }; }
        let allocations = self.allocate(&spend.account_id, spend.credits, spend.occurred_at)?;
        self.consume(&allocations)?; self.spends.insert(spend.event_id.clone(), (spend, allocations.clone())); Ok(allocations)
    }

    pub fn reserve(&mut self, reservation_id: &str, account_id: &str, credits: u64, expires_at: u64, now: u64) -> Result<StoredValueReservationV1, StoredValueError> {
        self.require_account(account_id)?; validate(reservation_id, "reservation_id")?;
        if credits == 0 || expires_at <= now { return Err(StoredValueError::Invalid("reservation_credits_or_expiry")); }
        if let Some(existing) = self.reservations.get(reservation_id) { return if existing.account_id == account_id && existing.credits == credits && existing.expires_at == expires_at { Ok(existing.clone()) } else { Err(StoredValueError::IdempotencyConflict(reservation_id.into())) }; }
        let allocations = self.allocate(account_id, credits, now)?;
        for allocation in &allocations { let lot = self.lots.get_mut(&allocation.lot_id).expect("allocated lot"); lot.remaining -= allocation.credits; lot.reserved += allocation.credits; }
        let reservation = StoredValueReservationV1 { reservation_id: reservation_id.into(), account_id: account_id.into(), credits, expires_at, allocations, status: StoredValueReservationStatus::Active };
        self.reservations.insert(reservation_id.into(), reservation.clone()); Ok(reservation)
    }

    pub fn release_reservation(&mut self, reservation_id: &str, now: u64) -> Result<(), StoredValueError> {
        let reservation = self.reservations.get(reservation_id).cloned().ok_or_else(|| StoredValueError::ReservationNotFound(reservation_id.into()))?;
        if reservation.status != StoredValueReservationStatus::Active { return Err(StoredValueError::ReservationNotActive(reservation_id.into())); }
        self.return_reserved(&reservation)?;
        self.reservations.get_mut(reservation_id).expect("reservation").status = if now >= reservation.expires_at { StoredValueReservationStatus::Expired } else { StoredValueReservationStatus::Released }; Ok(())
    }

    /// Deterministically expire a still-active reservation. A clock caller
    /// cannot release a valid hold early by calling the expiry operation.
    pub fn expire_reservation(&mut self, reservation_id: &str, now: u64) -> Result<(), StoredValueError> {
        let reservation = self.reservations.get(reservation_id).cloned().ok_or_else(|| StoredValueError::ReservationNotFound(reservation_id.into()))?;
        if reservation.status == StoredValueReservationStatus::Expired { return Ok(()); }
        if reservation.status != StoredValueReservationStatus::Active { return Err(StoredValueError::ReservationNotActive(reservation_id.into())); }
        if now < reservation.expires_at { return Err(StoredValueError::ReservationExpired(reservation_id.into())); }
        self.return_reserved(&reservation)?;
        self.reservations.get_mut(reservation_id).expect("reservation").status = StoredValueReservationStatus::Expired;
        Ok(())
    }

    pub fn settle_reservation(&mut self, reservation_id: &str, spend: StoredValueSpendV2) -> Result<Vec<LotAllocationV1>, StoredValueError> {
        let reservation = self.reservations.get(reservation_id).cloned().ok_or_else(|| StoredValueError::ReservationNotFound(reservation_id.into()))?;
        if reservation.status != StoredValueReservationStatus::Active { return Err(StoredValueError::ReservationNotActive(reservation_id.into())); }
        if spend.account_id != reservation.account_id || spend.credits != reservation.credits { return Err(StoredValueError::Invalid("reservation_spend_terms")); }
        if spend.occurred_at >= reservation.expires_at { return Err(StoredValueError::ReservationExpired(reservation_id.into())); }
        if let Some((existing, allocations)) = self.spends.get(&spend.event_id) { return if existing == &spend { Ok(allocations.clone()) } else { Err(StoredValueError::IdempotencyConflict(spend.event_id)) }; }
        for allocation in &reservation.allocations { let lot = self.lots.get_mut(&allocation.lot_id).expect("reserved lot"); lot.reserved -= allocation.credits; *self.consumed_by_lot.entry(allocation.lot_id.clone()).or_default() += allocation.credits; }
        self.spends.insert(spend.event_id.clone(), (spend, reservation.allocations.clone())); self.reservations.get_mut(reservation_id).expect("reservation").status = StoredValueReservationStatus::Settled; Ok(reservation.allocations)
    }

    pub fn refund_paid_lot(&mut self, refund: RefundPaidLotV1) -> Result<(), StoredValueError> {
        self.require_account(&refund.account_id)?;
        for (value, field) in [(&refund.refund_rail_ref, "refund_rail_ref"), (&refund.rail_ref, "rail_ref"), (&refund.reason_code, "refund_reason"), (&refund.approval_ref, "approval_ref"), (&refund.audit_ref, "audit_ref")] { validate(value, field)?; }
        if refund.credits == 0 || refund.requested_at == 0 { return Err(StoredValueError::Invalid("refund_credits_or_time")); }
        if let Some(existing) = self.refunds.get(&refund.refund_rail_ref) { return if existing == &refund { Ok(()) } else { Err(StoredValueError::IdempotencyConflict(refund.refund_rail_ref)) }; }
        let lot = self.lots.get_mut(&refund.rail_ref).ok_or_else(|| StoredValueError::PaidLotNotFound(refund.rail_ref.clone()))?;
        if lot.kind != CreditLotKind::Paid || lot.account_id != refund.account_id { return Err(StoredValueError::PaidLotNotFound(refund.rail_ref)); }
        if lot.reserved != 0 { return Err(StoredValueError::PaidLotReserved(lot.lot_id.clone())); }
        if lot.remaining < refund.credits { return Err(StoredValueError::RefundExceedsUnused { refund_id: refund.refund_rail_ref.clone(), rail_ref: refund.rail_ref.clone() }); }
        lot.remaining -= refund.credits; self.refunds.insert(refund.refund_rail_ref.clone(), refund); Ok(())
    }

    pub fn account_read(&self, account_id: &str, now: u64, period_ref: &str, reset_at: u64) -> Result<StoredValueAccountReadV1, StoredValueError> {
        self.require_account(account_id)?; let mut paid: u64 = 0; let mut grant: u64 = 0; let mut reserved: u64 = 0; let mut included: u64 = 0;
        for lot in self.lots.values().filter(|lot| lot.account_id == account_id) { reserved = reserved.checked_add(lot.reserved).ok_or(StoredValueError::Overflow)?; match lot.kind { CreditLotKind::Paid => paid = paid.checked_add(lot.remaining).ok_or(StoredValueError::Overflow)?, CreditLotKind::Grant if lot.expires_at > now => { grant = grant.checked_add(lot.remaining).ok_or(StoredValueError::Overflow)?; if lot.period_ref == period_ref { included = included.checked_add(*self.consumed_by_lot.get(&lot.lot_id).unwrap_or(&0)).ok_or(StoredValueError::Overflow)?; } }, CreditLotKind::Grant => {} } }
        Ok(StoredValueAccountReadV1 { account_id: account_id.into(), paid_available_credits: paid, grant_available_credits: grant, reserved_credits: reserved, refundable_paid_credits: paid, included_period_consumed: included, reset_at })
    }

    pub fn lots_for_account(&self, account_id: &str) -> Result<Vec<StoredValueLotReadV1>, StoredValueError> {
        self.require_account(account_id)?;
        Ok(self.lots.values().filter(|lot| lot.account_id == account_id).map(|lot| StoredValueLotReadV1 { lot_id: lot.lot_id.clone(), account_id: lot.account_id.clone(), kind: lot.kind, amount_usd_cents: lot.amount_usd_cents, base_credits: lot.base_credits, bonus_credits: lot.bonus_credits, remaining_credits: lot.remaining, reserved_credits: lot.reserved, issued_at: lot.issued_at, expires_at: lot.expires_at, terms_version: lot.terms_version.clone(), reason_code: lot.reason_code.clone(), period_ref: lot.period_ref.clone() }).collect())
    }

    pub fn reservation(&self, reservation_id: &str) -> Option<&StoredValueReservationV1> {
        self.reservations.get(reservation_id)
    }

    /// Persist exactly one post-state projection input for an idempotent V2
    /// operation. The caller must publish it only after chain finality.
    pub fn append_finality_event(&mut self, event_key: String, transaction_id: String, account_id: String, payload: StoredValueFinalityPayloadV1) -> Result<(), StoredValueError> {
        validate(&event_key, "finality_event_key")?;
        validate(&transaction_id, "transaction_id")?;
        self.require_account(&account_id)?;
        if let Some(existing) = self.finality_events.iter().find(|event| event.event_key == event_key) {
            if existing.account_id == account_id && existing.payload == payload { return Ok(()); }
            return Err(StoredValueError::IdempotencyConflict(event_key));
        }
        let sequence = u64::try_from(self.finality_events.len()).map_err(|_| StoredValueError::Overflow)?;
        self.finality_events.push(StoredValueFinalityEventV1 { sequence, event_key, transaction_id, account_id, payload });
        Ok(())
    }

    pub fn finality_events(&self, from_sequence: u64, limit: u16) -> Vec<StoredValueFinalityEventV1> {
        let end = from_sequence.saturating_add(u64::from(limit)).min(self.finality_events.len() as u64);
        self.finality_events[from_sequence as usize..end as usize].to_vec()
    }

    fn insert_lot(&mut self, key: String, lot: CreditLotV2) -> Result<(), StoredValueError> { match self.lots.get(&key) { None => { self.lots.insert(key, lot); Ok(()) }, Some(existing) if existing == &lot => Ok(()), Some(_) => Err(StoredValueError::IdempotencyConflict(key)) } }
    fn allocate(&self, account_id: &str, credits: u64, now: u64) -> Result<Vec<LotAllocationV1>, StoredValueError> { let mut lots = self.lots.values().filter(|lot| lot.account_id == account_id && (lot.kind == CreditLotKind::Paid || lot.expires_at > now)).collect::<Vec<_>>(); lots.sort_by_key(|lot| (lot.kind, if lot.expires_at == 0 { u64::MAX } else { lot.expires_at }, lot.issued_at, lot.lot_id.clone())); let available = lots.iter().try_fold(0u64, |total, lot| total.checked_add(lot.remaining).ok_or(StoredValueError::Overflow))?; if available < credits { return Err(StoredValueError::InsufficientCredits { available, required: credits }); } let mut left = credits; let mut allocations = Vec::new(); for lot in lots { if left == 0 { break; } let used = left.min(lot.remaining); if used > 0 { allocations.push(LotAllocationV1 { lot_id: lot.lot_id.clone(), kind: lot.kind, credits: used }); left -= used; } } Ok(allocations) }
    fn consume(&mut self, allocations: &[LotAllocationV1]) -> Result<(), StoredValueError> { for allocation in allocations { let lot = self.lots.get_mut(&allocation.lot_id).expect("allocated lot"); lot.remaining = lot.remaining.checked_sub(allocation.credits).ok_or(StoredValueError::Overflow)?; *self.consumed_by_lot.entry(allocation.lot_id.clone()).or_default() += allocation.credits; } Ok(()) }
    fn return_reserved(&mut self, reservation: &StoredValueReservationV1) -> Result<(), StoredValueError> { for allocation in &reservation.allocations { let lot = self.lots.get_mut(&allocation.lot_id).expect("reserved lot"); lot.reserved = lot.reserved.checked_sub(allocation.credits).ok_or(StoredValueError::Overflow)?; lot.remaining = lot.remaining.checked_add(allocation.credits).ok_or(StoredValueError::Overflow)?; } Ok(()) }
    fn require_account(&self, account_id: &str) -> Result<(), StoredValueError> { if self.accounts.contains_key(account_id) { Ok(()) } else { Err(StoredValueError::AccountNotFound(account_id.into())) } }
}

fn validate(value: &str, field: &'static str) -> Result<(), StoredValueError> { if value.is_empty() || value.len() > 128 || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')) { Err(StoredValueError::Invalid(field)) } else { Ok(()) } }

#[cfg(test)]
mod tests {
    use super::*;
    fn topup() -> CreditTopupV2 { CreditTopupV2 { account_id: "account_demo".into(), rail_ref: "pi_paid_1".into(), amount_usd_cents: 100_000, base_credits: 8_000, bonus_credits: 888, purchased_at: 100, terms_version: "terms_v1".into() } }
    fn grant() -> CreditGrantV2 { CreditGrantV2 { account_id: "account_demo".into(), reference: "grant_account_demo_2026_07".into(), credits: 3_000, reason_code: "included_credits".into(), period_ref: "2026-07".into(), issued_at: 100, expires_at: 200, approval_ref: "policy_auto".into(), audit_ref: "audit_1".into() } }
    fn ready() -> StoredValueLedger { let mut ledger = StoredValueLedger::default(); ledger.onboard("account_demo").unwrap(); ledger.credit_topup(topup()).unwrap(); ledger.credit_grant(grant()).unwrap(); ledger }
    fn refund(credits: u64, id: &str) -> RefundPaidLotV1 { RefundPaidLotV1 { account_id: "account_demo".into(), rail_ref: "pi_paid_1".into(), refund_rail_ref: id.into(), credits, requested_at: 150, reason_code: "charge.refunded".into(), approval_ref: "support_1".into(), audit_ref: "audit_2".into() } }
    #[test] fn grant_first_spend_preserves_paid_value() { let mut ledger = ready(); let allocations = ledger.record_spend(StoredValueSpendV2 { event_id: "event_1".into(), account_id: "account_demo".into(), credits: 3_100, occurred_at: 150 }).unwrap(); assert_eq!(allocations[0].kind, CreditLotKind::Grant); assert_eq!(allocations[1].kind, CreditLotKind::Paid); assert_eq!(ledger.account_read("account_demo", 150, "2026-07", 200).unwrap().refundable_paid_credits, 8_788); }
    #[test] fn reservation_prevents_refund_until_release() { let mut ledger = ready(); ledger.record_spend(StoredValueSpendV2 { event_id: "event_1".into(), account_id: "account_demo".into(), credits: 3_000, occurred_at: 150 }).unwrap(); ledger.reserve("res_1", "account_demo", 100, 180, 151).unwrap(); assert!(matches!(ledger.refund_paid_lot(refund(100, "re_1")), Err(StoredValueError::PaidLotReserved(_)))); ledger.release_reservation("res_1", 152).unwrap(); }
    #[test] fn partial_refund_is_idempotent_and_lot_bound() { let mut ledger = ready(); ledger.refund_paid_lot(refund(888, "re_1")).unwrap(); ledger.refund_paid_lot(refund(888, "re_1")).unwrap(); assert_eq!(ledger.account_read("account_demo", 150, "2026-07", 200).unwrap().paid_available_credits, 8_000); let mut bad = refund(1, "re_bad"); bad.rail_ref = "grant_account_demo_2026_07".into(); assert!(matches!(ledger.refund_paid_lot(bad), Err(StoredValueError::PaidLotNotFound(_)))); }
    #[test] fn expired_grant_does_not_fund_spend() { let mut ledger = ready(); assert!(matches!(ledger.record_spend(StoredValueSpendV2 { event_id: "event_expired".into(), account_id: "account_demo".into(), credits: 9_000, occurred_at: 201 }), Err(StoredValueError::InsufficientCredits { .. }))); }
}
