use crate::{
    BatchIntent, BatchOutcome, BatchParams, BatchResult, CbcDB, CbcOperation, ClearingFill,
    IntentId, IntentStatus, MarketClearingState, Transaction, MAX_CLEARING_MARKETS,
    MAX_PENDING_INTENTS,
};
use nunchi_clob::{MarketId, Side};
use nunchi_common::{Address, RuntimeContext};
use nunchi_crypto::SignatureError;
use nunchi_house::{
    authorized_submitter, release_clearing_quote, reserve_clearing_quote, settle_clearing_fill,
    validate_clearing_fill, HouseDB, HouseError, Mode, VaultId, BPS_DENOMINATOR,
};
use thiserror::Error;

/// Deterministic CBC state-machine errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CbcError {
    #[error("bad CBC transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("market already registered")]
    MarketAlreadyRegistered,
    #[error("market not registered")]
    MarketNotRegistered,
    #[error("clearing market index is full")]
    MarketIndexFull,
    #[error("pending intent queue is full")]
    PendingIntentsFull,
    #[error("intent not found")]
    IntentNotFound,
    #[error("intent is not open")]
    IntentClosed,
    #[error("cannot cancel intent for another vault")]
    UnauthorizedCancel,
    #[error("signer is not an authorized submitter for the vault")]
    UnauthorizedSubmitter,
    #[error("signer is not the clearing keeper")]
    UnauthorizedKeeper,
    #[error("signer is not the market admin")]
    UnauthorizedAdmin,
    #[error("invalid params: {0}")]
    InvalidParams(&'static str),
    #[error("invalid intent: {0}")]
    InvalidIntent(&'static str),
    #[error("intent notional overflow")]
    NotionalOverflow,
    #[error("submitter notional cap exceeded")]
    SubmitterNotionalExceeded,
    #[error("batch notional cap exceeded")]
    BatchNotionalExceeded,
    #[error("market clearing is halted")]
    MarketHalted,
    #[error("frozen market accepts reduce-only intents")]
    FrozenRequiresReduceOnly,
    #[error("clearing cadence has not elapsed")]
    CadenceNotElapsed,
    #[error("price arithmetic overflow")]
    PriceOverflow,
    #[error("house: {0}")]
    House(#[from] HouseError),
    #[error("state storage error: {0}")]
    Storage(String),
}

/// Deterministic state machine for cooperative batch clearing.
///
/// The ledger composes house vault state through the [`HouseDB`] view of the
/// same underlying state store: authorization, reservations, and settlement
/// all route through the house module's checked clearing API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CbcLedger<D> {
    pub(crate) db: D,
}

struct WalkIntent {
    intent: BatchIntent,
    effective: u128,
    filled: u128,
}

impl<D: CbcDB + HouseDB> CbcLedger<D> {
    /// Wrap a database backend as a CBC ledger.
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

    pub async fn nonce(&self, account: &Address) -> Result<u64, CbcError> {
        self.db.cbc_nonce(account).await
    }

    pub async fn params(&self, market: &MarketId) -> Result<Option<BatchParams>, CbcError> {
        self.db.params(market).await
    }

    pub async fn markets(&self) -> Result<Vec<MarketId>, CbcError> {
        self.db.market_index().await
    }

    pub async fn clearing_state(
        &self,
        market: &MarketId,
    ) -> Result<MarketClearingState, CbcError> {
        self.db.clearing_state(market).await
    }

    pub async fn intent(&self, id: &IntentId) -> Result<Option<BatchIntent>, CbcError> {
        self.db.intent(id).await
    }

    pub async fn pending_intents(&self, market: &MarketId) -> Result<Vec<BatchIntent>, CbcError> {
        let ids = self.db.pending_intents(market).await?;
        let mut intents = Vec::with_capacity(ids.len());
        for id in ids {
            intents.push(self.db.intent(&id).await?.ok_or(CbcError::IntentNotFound)?);
        }
        Ok(intents)
    }

    pub async fn batch_result(
        &self,
        market: &MarketId,
        batch_number: u64,
    ) -> Result<Option<BatchResult>, CbcError> {
        self.db.batch_result(market, batch_number).await
    }

    /// Validate and apply a signed CBC transaction.
    pub async fn apply_transaction(
        &mut self,
        tx: &Transaction,
        context: RuntimeContext,
    ) -> Result<(), CbcError> {
        tx.verify()?;

        let expected = self.db.cbc_nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(CbcError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        self.apply_operation(tx, context).await?;
        let next_nonce = expected.checked_add(1).ok_or(CbcError::NonceOverflow)?;
        self.db.set_cbc_nonce(&tx.account_id, next_nonce);
        Ok(())
    }

    async fn apply_operation(
        &mut self,
        tx: &Transaction,
        context: RuntimeContext,
    ) -> Result<(), CbcError> {
        match &tx.payload.operation {
            CbcOperation::RegisterMarket { market, params } => {
                self.register_market(&tx.account_id, market, params.clone())
                    .await
            }
            CbcOperation::SetClearingMode { market, mode } => {
                self.set_clearing_mode(&tx.account_id, market, *mode).await
            }
            CbcOperation::SubmitIntent {
                market,
                vault,
                side,
                limit_price,
                base_quantity,
                reduce_only,
                expiry_height,
            } => {
                self.submit_intent(
                    &tx.account_id,
                    IntentId(tx.digest()),
                    market,
                    vault,
                    *side,
                    *limit_price,
                    *base_quantity,
                    *reduce_only,
                    *expiry_height,
                    context,
                )
                .await
            }
            CbcOperation::CancelIntent { intent } => {
                self.cancel_intent(&tx.account_id, intent).await
            }
            CbcOperation::CloseAndClearBatch {
                market,
                oracle_price,
            } => {
                self.close_and_clear(&tx.account_id, market, *oracle_price, context)
                    .await
            }
        }
    }

    async fn register_market(
        &mut self,
        signer: &Address,
        market: &MarketId,
        params: BatchParams,
    ) -> Result<(), CbcError> {
        validate_params(&params)?;
        if params.admin != *signer {
            return Err(CbcError::UnauthorizedAdmin);
        }
        if self.db.params(market).await?.is_some() {
            return Err(CbcError::MarketAlreadyRegistered);
        }

        let mut markets = self.db.market_index().await?;
        if markets.len() == MAX_CLEARING_MARKETS {
            return Err(CbcError::MarketIndexFull);
        }

        self.db.set_params(market, &params);
        self.db
            .set_clearing_state(market, &MarketClearingState::new());
        markets.push(*market);
        self.db.set_market_index(&markets);
        Ok(())
    }

    async fn set_clearing_mode(
        &mut self,
        signer: &Address,
        market: &MarketId,
        mode: Mode,
    ) -> Result<(), CbcError> {
        let params = self
            .db
            .params(market)
            .await?
            .ok_or(CbcError::MarketNotRegistered)?;
        if params.admin != *signer {
            return Err(CbcError::UnauthorizedAdmin);
        }
        let mut state = self.db.clearing_state(market).await?;
        state.mode = mode;
        self.db.set_clearing_state(market, &state);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn submit_intent(
        &mut self,
        signer: &Address,
        id: IntentId,
        market: &MarketId,
        vault: &VaultId,
        side: Side,
        limit_price: u128,
        base_quantity: u128,
        reduce_only: bool,
        expiry_height: u64,
        context: RuntimeContext,
    ) -> Result<(), CbcError> {
        let params = self
            .db
            .params(market)
            .await?
            .ok_or(CbcError::MarketNotRegistered)?;
        let mut state = self.db.clearing_state(market).await?;
        match state.mode {
            Mode::Halt => return Err(CbcError::MarketHalted),
            Mode::Frozen if !reduce_only => return Err(CbcError::FrozenRequiresReduceOnly),
            _ => {}
        }

        if !authorized_submitter(&self.db, vault, signer).await? {
            return Err(CbcError::UnauthorizedSubmitter);
        }
        validate_intent_shape(&params, limit_price, base_quantity, expiry_height, context)?;
        if self.db.intent(&id).await?.is_some() {
            return Err(CbcError::InvalidIntent("duplicate intent id"));
        }

        let vault_state = self
            .db
            .vault(vault)
            .await
            .map_err(CbcError::House)?
            .ok_or(CbcError::House(HouseError::VaultNotFound))?;
        if !reduce_only && !vault_state.policy.allows_market(market) {
            return Err(CbcError::InvalidIntent(
                "market not allowed by vault policy",
            ));
        }

        let notional = limit_price
            .checked_mul(base_quantity)
            .ok_or(CbcError::NotionalOverflow)?;
        let vault_notional = self.db.vault_notional(vault, market).await?;
        let next_vault_notional = vault_notional
            .checked_add(notional)
            .ok_or(CbcError::NotionalOverflow)?;
        if next_vault_notional > params.max_submitter_notional {
            return Err(CbcError::SubmitterNotionalExceeded);
        }
        let next_pending_notional = state
            .pending_notional
            .checked_add(notional)
            .ok_or(CbcError::NotionalOverflow)?;
        if next_pending_notional > params.max_batch_notional {
            return Err(CbcError::BatchNotionalExceeded);
        }

        let mut pending = self.db.pending_intents(market).await?;
        if pending.len() == MAX_PENDING_INTENTS {
            return Err(CbcError::PendingIntentsFull);
        }

        if side == Side::Bid {
            reserve_clearing_quote(&mut self.db, vault, market, notional).await?;
        }

        let intent = BatchIntent {
            id,
            market: *market,
            vault: *vault,
            submitter: signer.clone(),
            side,
            limit_price,
            original_base: base_quantity,
            remaining_base: base_quantity,
            filled_base: 0,
            reduce_only,
            expiry_height,
            sequence: state.sequence,
            status: IntentStatus::Pending,
            submitted_at_height: context.height,
            submitted_at_ms: context.timestamp_ms,
        };
        state.sequence = state.sequence.checked_add(1).ok_or(CbcError::NonceOverflow)?;
        state.pending_notional = next_pending_notional;

        self.db.set_intent(&intent);
        pending.push(id);
        self.db.set_pending_intents(market, &pending);
        self.db
            .set_vault_notional(vault, market, next_vault_notional);
        self.db.set_clearing_state(market, &state);
        Ok(())
    }

    async fn cancel_intent(&mut self, signer: &Address, id: &IntentId) -> Result<(), CbcError> {
        let intent = self
            .db
            .intent(id)
            .await?
            .ok_or(CbcError::IntentNotFound)?;
        if !intent.status.is_open() {
            return Err(CbcError::IntentClosed);
        }

        if intent.submitter != *signer {
            let vault_state = self
                .db
                .vault(&intent.vault)
                .await
                .map_err(CbcError::House)?
                .ok_or(CbcError::House(HouseError::VaultNotFound))?;
            if vault_state.owner != *signer {
                return Err(CbcError::UnauthorizedCancel);
            }
        }

        let market = intent.market;
        let mut state = self.db.clearing_state(&market).await?;
        let mut pending = self.db.pending_intents(&market).await?;
        pending.retain(|entry| entry != id);
        self.retire_intent(intent, IntentStatus::Cancelled, &mut state)
            .await?;
        self.db.set_pending_intents(&market, &pending);
        self.db.set_clearing_state(&market, &state);
        Ok(())
    }

    /// Close the market's open batch and clear it at one uniform price.
    async fn close_and_clear(
        &mut self,
        signer: &Address,
        market: &MarketId,
        oracle_price: u128,
        context: RuntimeContext,
    ) -> Result<(), CbcError> {
        let params = self
            .db
            .params(market)
            .await?
            .ok_or(CbcError::MarketNotRegistered)?;
        if params.keeper != *signer {
            return Err(CbcError::UnauthorizedKeeper);
        }
        if oracle_price == 0 {
            return Err(CbcError::InvalidParams("oracle price must be non-zero"));
        }
        let mut state = self.db.clearing_state(market).await?;
        if state.mode == Mode::Halt {
            return Err(CbcError::MarketHalted);
        }
        let due_height = state
            .last_clear_height
            .checked_add(params.cadence_blocks)
            .ok_or(CbcError::PriceOverflow)?;
        if context.height < due_height {
            return Err(CbcError::CadenceNotElapsed);
        }

        let pending_ids = self.db.pending_intents(market).await?;
        let mut live: Vec<WalkIntent> = Vec::with_capacity(pending_ids.len());
        let mut rejected: Vec<IntentId> = Vec::new();
        for id in &pending_ids {
            let intent = self
                .db
                .intent(id)
                .await?
                .ok_or(CbcError::IntentNotFound)?;
            if intent.expiry_height <= context.height {
                self.retire_intent(intent, IntentStatus::Expired, &mut state)
                    .await?;
                rejected.push(*id);
                continue;
            }
            let vault_state = match self.db.vault(&intent.vault).await? {
                Some(vault_state) => vault_state,
                None => {
                    self.retire_intent(intent, IntentStatus::Rejected, &mut state)
                        .await?;
                    rejected.push(*id);
                    continue;
                }
            };
            if vault_state.mode == Mode::Halt {
                self.retire_intent(intent, IntentStatus::Rejected, &mut state)
                    .await?;
                rejected.push(*id);
                continue;
            }
            let constrained = intent.reduce_only || vault_state.mode == Mode::Frozen;
            let effective = if constrained {
                let inventory = self.db.inventory(&intent.vault, market).await?;
                inventory
                    .reducing_capacity(intent.side)
                    .min(intent.remaining_base)
            } else {
                intent.remaining_base
            };
            if effective == 0 {
                self.retire_intent(intent, IntentStatus::Rejected, &mut state)
                    .await?;
                rejected.push(*id);
                continue;
            }
            live.push(WalkIntent {
                intent,
                effective,
                filled: 0,
            });
        }

        let discovered = discover_price(&live, oracle_price);
        let mut outcome = BatchOutcome::NoCross;
        let mut clearing_price = 0;
        let mut total_base = 0;
        let mut fills: Vec<ClearingFill> = Vec::new();

        if let Some((price, executable)) = discovered {
            if executable >= params.min_clearing_qty.max(1) {
                if outside_band(price, oracle_price, params.oracle_band_bps)? {
                    outcome = BatchOutcome::OutsideBand;
                } else {
                    let matched = self
                        .allocate_and_settle(market, &mut live, price, oracle_price)
                        .await?;
                    total_base = matched;
                    if matched > 0 {
                        outcome = BatchOutcome::Cleared;
                        clearing_price = price;
                        for entry in &live {
                            if entry.filled == 0 {
                                continue;
                            }
                            let quote = price
                                .checked_mul(entry.filled)
                                .ok_or(CbcError::PriceOverflow)?;
                            fills.push(ClearingFill {
                                intent: entry.intent.id,
                                vault: entry.intent.vault,
                                side: entry.intent.side,
                                base_quantity: entry.filled,
                                quote_quantity: quote,
                            });
                        }
                    }
                }
            }
        }

        let mut next_pending: Vec<IntentId> = Vec::new();
        for entry in &mut live {
            if entry.filled > 0 {
                let consumed_notional = entry
                    .intent
                    .limit_price
                    .checked_mul(entry.filled)
                    .ok_or(CbcError::PriceOverflow)?;
                entry.intent.remaining_base -= entry.filled;
                entry.intent.filled_base += entry.filled;
                state.pending_notional = state.pending_notional.saturating_sub(consumed_notional);
                let vault_notional = self
                    .db
                    .vault_notional(&entry.intent.vault, market)
                    .await?
                    .saturating_sub(consumed_notional);
                self.db
                    .set_vault_notional(&entry.intent.vault, market, vault_notional);
            }
            if entry.intent.remaining_base == 0 {
                entry.intent.status = IntentStatus::Filled;
            } else if entry.intent.filled_base > 0 {
                entry.intent.status = IntentStatus::PartiallyFilled;
            }
            if entry.intent.status.is_open() {
                next_pending.push(entry.intent.id);
            }
            self.db.set_intent(&entry.intent);
        }
        self.db.set_pending_intents(market, &next_pending);

        let result = BatchResult {
            market: *market,
            batch_number: state.batch_number,
            outcome,
            oracle_price,
            clearing_price,
            total_base,
            fills,
            rejected,
            cleared_at_height: context.height,
            cleared_at_ms: context.timestamp_ms,
        };
        self.db.set_batch_result(&result);
        state.batch_number = state
            .batch_number
            .checked_add(1)
            .ok_or(CbcError::NonceOverflow)?;
        state.last_clear_height = context.height;
        self.db.set_clearing_state(market, &state);
        Ok(())
    }

    /// Walk crossing intents in submission order, settling each matched chunk
    /// through the house module immediately after validating both sides.
    ///
    /// An intent whose side fails validation is skipped for this batch and
    /// remains pending; skipping is conservative but deterministic.
    async fn allocate_and_settle(
        &mut self,
        market: &MarketId,
        live: &mut [WalkIntent],
        price: u128,
        oracle_price: u128,
    ) -> Result<u128, CbcError> {
        let mut bid_order: Vec<usize> = Vec::new();
        let mut ask_order: Vec<usize> = Vec::new();
        for (idx, entry) in live.iter().enumerate() {
            match entry.intent.side {
                Side::Bid if entry.intent.limit_price >= price => bid_order.push(idx),
                Side::Ask if entry.intent.limit_price <= price => ask_order.push(idx),
                _ => {}
            }
        }

        let mut total = 0_u128;
        let mut bid_cursor = 0;
        let mut ask_cursor = 0;
        while bid_cursor < bid_order.len() && ask_cursor < ask_order.len() {
            let bid_idx = bid_order[bid_cursor];
            let ask_idx = ask_order[ask_cursor];
            let bid_remaining = live[bid_idx].effective - live[bid_idx].filled;
            let ask_remaining = live[ask_idx].effective - live[ask_idx].filled;
            if bid_remaining == 0 {
                bid_cursor += 1;
                continue;
            }
            if ask_remaining == 0 {
                ask_cursor += 1;
                continue;
            }

            let chunk = bid_remaining.min(ask_remaining);
            let quote = price.checked_mul(chunk).ok_or(CbcError::PriceOverflow)?;
            let bid_release = live[bid_idx]
                .intent
                .limit_price
                .checked_mul(chunk)
                .ok_or(CbcError::PriceOverflow)?;

            if !self
                .chunk_side_valid(market, &live[bid_idx].intent, chunk, quote, bid_release, oracle_price)
                .await?
            {
                bid_cursor += 1;
                continue;
            }
            if !self
                .chunk_side_valid(market, &live[ask_idx].intent, chunk, quote, 0, oracle_price)
                .await?
            {
                ask_cursor += 1;
                continue;
            }

            settle_clearing_fill(
                &mut self.db,
                &live[bid_idx].intent.vault,
                market,
                Side::Bid,
                chunk,
                quote,
                bid_release,
                oracle_price,
            )
            .await?;
            settle_clearing_fill(
                &mut self.db,
                &live[ask_idx].intent.vault,
                market,
                Side::Ask,
                chunk,
                quote,
                0,
                oracle_price,
            )
            .await?;

            live[bid_idx].filled += chunk;
            live[ask_idx].filled += chunk;
            total = total.checked_add(chunk).ok_or(CbcError::PriceOverflow)?;
        }
        Ok(total)
    }

    /// Whether one side of a matched chunk passes house validation against
    /// current state.
    async fn chunk_side_valid(
        &self,
        market: &MarketId,
        intent: &BatchIntent,
        chunk: u128,
        quote: u128,
        reservation_release: u128,
        oracle_price: u128,
    ) -> Result<bool, CbcError> {
        let vault_state = match self.db.vault(&intent.vault).await? {
            Some(vault_state) => vault_state,
            None => return Ok(false),
        };
        let inventory = self.db.inventory(&intent.vault, market).await?;
        if intent.side == Side::Bid {
            let reserved = self.db.reserved(&intent.vault, market).await?;
            if reserved < reservation_release {
                return Ok(false);
            }
        }
        if (intent.reduce_only || vault_state.mode == Mode::Frozen)
            && inventory.reducing_capacity(intent.side) < chunk
        {
            return Ok(false);
        }
        Ok(validate_clearing_fill(
            &vault_state,
            market,
            inventory,
            intent.side,
            chunk,
            quote,
            reservation_release,
            oracle_price,
        )
        .is_ok())
    }

    /// Release remaining reservations and record a terminal intent status.
    async fn retire_intent(
        &mut self,
        mut intent: BatchIntent,
        status: IntentStatus,
        state: &mut MarketClearingState,
    ) -> Result<(), CbcError> {
        let remaining_notional = intent
            .remaining_notional()
            .ok_or(CbcError::NotionalOverflow)?;
        if intent.side == Side::Bid && remaining_notional > 0 {
            release_clearing_quote(
                &mut self.db,
                &intent.vault,
                &intent.market,
                remaining_notional,
            )
            .await?;
        }
        state.pending_notional = state.pending_notional.saturating_sub(remaining_notional);
        let vault_notional = self
            .db
            .vault_notional(&intent.vault, &intent.market)
            .await?
            .saturating_sub(remaining_notional);
        self.db
            .set_vault_notional(&intent.vault, &intent.market, vault_notional);
        intent.status = status;
        self.db.set_intent(&intent);
        Ok(())
    }
}

pub(crate) fn validate_params(params: &BatchParams) -> Result<(), CbcError> {
    if params.cadence_blocks == 0 {
        return Err(CbcError::InvalidParams("cadence must be non-zero"));
    }
    if params.price_tick == 0 {
        return Err(CbcError::InvalidParams("price tick must be non-zero"));
    }
    if params.size_tick == 0 {
        return Err(CbcError::InvalidParams("size tick must be non-zero"));
    }
    Ok(())
}

fn validate_intent_shape(
    params: &BatchParams,
    limit_price: u128,
    base_quantity: u128,
    expiry_height: u64,
    context: RuntimeContext,
) -> Result<(), CbcError> {
    if limit_price == 0 {
        return Err(CbcError::InvalidIntent("limit price must be non-zero"));
    }
    if base_quantity == 0 {
        return Err(CbcError::InvalidIntent("quantity must be non-zero"));
    }
    if !limit_price.is_multiple_of(params.price_tick) {
        return Err(CbcError::InvalidIntent("price is not on the market tick"));
    }
    if !base_quantity.is_multiple_of(params.size_tick) {
        return Err(CbcError::InvalidIntent("quantity is not on the size tick"));
    }
    if expiry_height <= context.height {
        return Err(CbcError::InvalidIntent("intent is already expired"));
    }
    Ok(())
}

/// Find the uniform price maximizing executable volume.
///
/// Candidates are the intent limit prices plus the oracle price, so the batch
/// clears exactly at oracle whenever oracle sits inside the volume-maximizing
/// range. Ties break toward the oracle price, then toward the lower price.
/// Effective quantities already account for reduce-only caps against
/// pre-batch inventory; exact caps re-apply chunk by chunk during allocation.
fn discover_price(live: &[WalkIntent], oracle_price: u128) -> Option<(u128, u128)> {
    let mut candidates: Vec<u128> = live.iter().map(|entry| entry.intent.limit_price).collect();
    candidates.push(oracle_price);
    candidates.sort_unstable();
    candidates.dedup();

    let mut best: Option<(u128, u128)> = None;
    for price in candidates {
        let mut bid_volume = 0_u128;
        let mut ask_volume = 0_u128;
        for entry in live {
            match entry.intent.side {
                Side::Bid if entry.intent.limit_price >= price => {
                    bid_volume = bid_volume.saturating_add(entry.effective);
                }
                Side::Ask if entry.intent.limit_price <= price => {
                    ask_volume = ask_volume.saturating_add(entry.effective);
                }
                _ => {}
            }
        }
        let executable = bid_volume.min(ask_volume);
        if executable == 0 {
            continue;
        }
        best = match best {
            None => Some((price, executable)),
            Some((best_price, best_executable)) => {
                if executable > best_executable
                    || (executable == best_executable
                        && price.abs_diff(oracle_price) < best_price.abs_diff(oracle_price))
                {
                    Some((price, executable))
                } else {
                    Some((best_price, best_executable))
                }
            }
        };
    }
    best
}

/// Whether `price` falls outside the allowed band around `oracle_price`.
fn outside_band(price: u128, oracle_price: u128, band_bps: u32) -> Result<bool, CbcError> {
    let distance = price.abs_diff(oracle_price);
    let scaled_distance = distance
        .checked_mul(BPS_DENOMINATOR)
        .ok_or(CbcError::PriceOverflow)?;
    let allowed = oracle_price
        .checked_mul(band_bps as u128)
        .ok_or(CbcError::PriceOverflow)?;
    Ok(scaled_distance > allowed)
}
