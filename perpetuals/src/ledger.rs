use crate::{
    derive_market_id, derive_position_id, Address, Authorization, Market, MarketId,
    OraclePricePayload, PerpetualDB, PerpetualOperation, Position, PositionId, Side, Transaction,
    BPS_DENOMINATOR, MAX_PRICE_DECIMALS, PRICE_SCALE,
};
use commonware_codec::ReadExt;
use commonware_cryptography::sha256::Digest;
use nunchi_coins::CoinId;
use nunchi_common::{CommitState, RuntimeContext, StateStore};
use nunchi_crypto::SignatureError;
use nunchi_oracle::{IntervalKey, NamespaceId, OracleError, OracleLedger, OracleRecord};
use thiserror::Error;

/// Deterministic perpetuals state-machine errors.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum PerpetualError {
    #[error("bad perpetual transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("market nonce overflow")]
    MarketNonceOverflow,
    #[error("position nonce overflow")]
    PositionNonceOverflow,
    #[error("invalid zero collateral")]
    InvalidCollateral,
    #[error("invalid oracle price")]
    InvalidOraclePrice,
    #[error("invalid leverage")]
    InvalidLeverage,
    #[error("invalid maintenance margin")]
    InvalidMaintenanceMargin,
    #[error("invalid oracle interval")]
    InvalidOracleInterval,
    #[error("invalid oracle staleness threshold")]
    InvalidOracleStaleness,
    #[error("invalid funding interval")]
    InvalidFundingInterval,
    #[error("invalid funding rate")]
    InvalidFundingRate,
    #[error("invalid price decimals")]
    InvalidPriceDecimals,
    #[error("market has no fresh oracle price")]
    MarketNotReady,
    #[error("missing oracle price")]
    MissingOraclePrice,
    #[error("stale oracle price")]
    StaleOraclePrice,
    #[error("oracle payload decode failed: {0}")]
    OraclePayload(String),
    #[error("oracle module error: {0}")]
    Oracle(#[from] OracleError),
    #[error("unknown market {0:?}")]
    UnknownMarket(MarketId),
    #[error("duplicate market {0:?}")]
    DuplicateMarket(MarketId),
    #[error("unknown position {0:?}")]
    UnknownPosition(PositionId),
    #[error("unauthorized perpetual operation")]
    Unauthorized,
    #[error("max leverage exceeded: max {max}, requested {requested}")]
    MaxLeverageExceeded { max: u32, requested: u32 },
    #[error("position is not liquidatable")]
    PositionNotLiquidatable,
    #[error("position is underwater {0:?}")]
    PositionUnderwater(PositionId),
    #[error("collateral reduction exceeds available balance")]
    CollateralUnderflow,
    #[error("collateral reduction would push position into liquidatable territory")]
    CollateralReductionWouldCauseLiquidation,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("state storage error: {0}")]
    Storage(String),
}

/// Perpetuals ledger over a shared SDK state backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerpetualLedger<D> {
    db: D,
}

impl<D: PerpetualDB + StateStore + Send + Sync> PerpetualLedger<D> {
    /// Wrap a database backend as a perpetuals ledger.
    pub fn new(db: D) -> Self {
        Self { db }
    }

    /// Borrow the underlying database.
    pub fn db(&self) -> &D {
        &self.db
    }

    #[cfg(test)]
    pub(crate) fn db_mut(&mut self) -> &mut D {
        &mut self.db
    }

    /// Consume the ledger, returning the underlying database.
    pub fn into_inner(self) -> D {
        self.db
    }

    pub async fn nonce(&self, id: &Address) -> Result<u64, PerpetualError> {
        self.db.nonce(id).await
    }

    pub async fn market(&self, id: &MarketId) -> Result<Option<Market>, PerpetualError> {
        self.db.market(id).await
    }

    pub async fn position(&self, id: &PositionId) -> Result<Option<Position>, PerpetualError> {
        self.db.position(id).await
    }

    /// Validate and apply a signed perpetuals transaction.
    pub async fn apply_transaction(
        &mut self,
        tx: &Transaction,
        context: RuntimeContext,
    ) -> Result<(), PerpetualError> {
        self.ensure_authorized(tx)?;

        let expected = self.db.nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(PerpetualError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        self.apply_operation(&tx.account_id, &tx.payload.operation, context)
            .await?;
        let next_nonce = expected
            .checked_add(1)
            .ok_or(PerpetualError::NonceOverflow)?;
        self.db.set_nonce(&tx.account_id, next_nonce);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_market(
        &mut self,
        base_asset: CoinId,
        quote_asset: CoinId,
        collateral_asset: CoinId,
        oracle_namespace: NamespaceId,
        oracle_interval_ms: u64,
        max_oracle_staleness_ms: u64,
        price_decimals: u8,
        max_leverage_bps: u32,
        maintenance_margin_bps: u32,
        funding_interval_ms: u64,
        max_funding_rate_bps: u32,
    ) -> Result<MarketId, PerpetualError> {
        validate_market_params(
            oracle_interval_ms,
            max_oracle_staleness_ms,
            price_decimals,
            max_leverage_bps,
            maintenance_margin_bps,
            funding_interval_ms,
            max_funding_rate_bps,
        )?;
        let nonce = self.db.market_nonce().await?;
        let market_id = derive_market_id(base_asset, quote_asset, collateral_asset, nonce);
        if self.db.market(&market_id).await?.is_some() {
            return Err(PerpetualError::DuplicateMarket(market_id));
        }
        let market = Market {
            id: market_id,
            base_asset,
            quote_asset,
            collateral_asset,
            oracle_namespace,
            oracle_interval_ms,
            max_oracle_staleness_ms,
            price_decimals,
            max_leverage_bps,
            maintenance_margin_bps,
            funding_interval_ms,
            max_funding_rate_bps,
            mark_price: 0,
            index_price: 0,
            open_interest: 0,
            last_oracle_interval: 0,
            last_oracle_update_ms: 0,
            last_funding_ms: 0,
            cumulative_funding_long: 0,
            cumulative_funding_short: 0,
        };
        self.db.set_market(&market);
        self.db.set_market_nonce(
            nonce
                .checked_add(1)
                .ok_or(PerpetualError::MarketNonceOverflow)?,
        );
        Ok(market_id)
    }

    /// Pull and decode the latest valid opaque Oracle record for a market.
    pub async fn refresh_market_from_oracle(
        &mut self,
        market_id: MarketId,
        context: RuntimeContext,
    ) -> Result<(), PerpetualError> {
        let mut market = self
            .db
            .market(&market_id)
            .await?
            .ok_or(PerpetualError::UnknownMarket(market_id))?;
        self.settle_market_funding(&mut market, context.timestamp_ms)?;

        let current_interval = context.timestamp_ms / market.oracle_interval_ms;
        let start = IntervalKey::new(current_interval.saturating_sub(1));
        let end = IntervalKey::new(current_interval);
        let records = {
            let oracle = OracleLedger::new(&mut self.db);
            oracle
                .records_by_namespace(&market.oracle_namespace, start, end)
                .await?
        };
        let (record, payload) = latest_payload_for_market(&market, &records, context)?;
        let price = scale_price(payload.price, payload.price_decimals, market.price_decimals)?;

        market.index_price = price;
        market.mark_price = price;
        market.last_oracle_interval = record.interval.bucket;
        market.last_oracle_update_ms = record.written_at_ms;
        self.db.set_market(&market);
        Ok(())
    }

    pub async fn settle_funding(
        &mut self,
        market_id: MarketId,
        context: RuntimeContext,
    ) -> Result<(), PerpetualError> {
        let mut market = self
            .db
            .market(&market_id)
            .await?
            .ok_or(PerpetualError::UnknownMarket(market_id))?;
        self.ensure_market_ready(&market, context.timestamp_ms)?;
        self.settle_market_funding(&mut market, context.timestamp_ms)?;
        self.db.set_market(&market);
        Ok(())
    }

    pub async fn open_position(
        &mut self,
        owner: Address,
        market_id: MarketId,
        side: Side,
        collateral: u128,
        leverage_bps: u32,
        context: RuntimeContext,
    ) -> Result<PositionId, PerpetualError> {
        if collateral == 0 {
            return Err(PerpetualError::InvalidCollateral);
        }
        let mut market = self
            .db
            .market(&market_id)
            .await?
            .ok_or(PerpetualError::UnknownMarket(market_id))?;
        self.ensure_market_ready(&market, context.timestamp_ms)?;
        self.settle_market_funding(&mut market, context.timestamp_ms)?;
        if leverage_bps < BPS_DENOMINATOR {
            return Err(PerpetualError::InvalidLeverage);
        }
        if leverage_bps > market.max_leverage_bps {
            return Err(PerpetualError::MaxLeverageExceeded {
                max: market.max_leverage_bps,
                requested: leverage_bps,
            });
        }
        let quantity = quantity_from_collateral(collateral, leverage_bps, market.mark_price)?;
        let nonce = self.db.position_nonce().await?;
        let position_id = derive_position_id(&owner, &market_id, nonce);
        let position = Position {
            id: position_id,
            market: market_id,
            owner,
            side,
            quantity,
            entry_price: market.mark_price,
            collateral,
            entry_funding_index: funding_index_for_side(&market, side),
        };
        market.open_interest = market
            .open_interest
            .checked_add(quantity)
            .ok_or(PerpetualError::ArithmeticOverflow)?;
        self.db.set_market(&market);
        self.db.set_position(&position);
        self.db.set_position_nonce(
            nonce
                .checked_add(1)
                .ok_or(PerpetualError::PositionNonceOverflow)?,
        );
        Ok(position_id)
    }

    pub async fn add_collateral(
        &mut self,
        owner: &Address,
        position_id: PositionId,
        amount: u128,
    ) -> Result<(), PerpetualError> {
        if amount == 0 {
            return Err(PerpetualError::InvalidCollateral);
        }
        let mut position = self
            .db
            .position(&position_id)
            .await?
            .ok_or(PerpetualError::UnknownPosition(position_id))?;
        if &position.owner != owner {
            return Err(PerpetualError::Unauthorized);
        }
        position.collateral = position
            .collateral
            .checked_add(amount)
            .ok_or(PerpetualError::ArithmeticOverflow)?;
        self.db.set_position(&position);
        Ok(())
    }

    pub async fn reduce_collateral(
        &mut self,
        owner: &Address,
        position_id: PositionId,
        amount: u128,
        context: RuntimeContext,
    ) -> Result<(), PerpetualError> {
        if amount == 0 {
            return Err(PerpetualError::InvalidCollateral);
        }
        let mut position = self
            .db
            .position(&position_id)
            .await?
            .ok_or(PerpetualError::UnknownPosition(position_id))?;
        if &position.owner != owner {
            return Err(PerpetualError::Unauthorized);
        }
        let mut market = self
            .db
            .market(&position.market)
            .await?
            .ok_or(PerpetualError::UnknownMarket(position.market))?;
        self.ensure_market_ready(&market, context.timestamp_ms)?;
        self.settle_market_funding(&mut market, context.timestamp_ms)?;
        let new_collateral = position
            .collateral
            .checked_sub(amount)
            .ok_or(PerpetualError::CollateralUnderflow)?;
        let temp = Position {
            collateral: new_collateral,
            ..position.clone()
        };
        if self.is_liquidatable_with_market(&temp, &market)? {
            return Err(PerpetualError::CollateralReductionWouldCauseLiquidation);
        }
        position.collateral = new_collateral;
        self.db.set_market(&market);
        self.db.set_position(&position);
        Ok(())
    }

    pub async fn close_position(
        &mut self,
        owner: &Address,
        position_id: PositionId,
        context: RuntimeContext,
    ) -> Result<u128, PerpetualError> {
        let position = self
            .db
            .position(&position_id)
            .await?
            .ok_or(PerpetualError::UnknownPosition(position_id))?;
        if &position.owner != owner {
            return Err(PerpetualError::Unauthorized);
        }
        let mut market = self
            .db
            .market(&position.market)
            .await?
            .ok_or(PerpetualError::UnknownMarket(position.market))?;
        self.ensure_market_ready(&market, context.timestamp_ms)?;
        self.settle_market_funding(&mut market, context.timestamp_ms)?;
        let equity = position_equity(&position, &market)?;
        if equity <= 0 {
            return Err(PerpetualError::PositionUnderwater(position_id));
        }
        market.open_interest = market
            .open_interest
            .checked_sub(position.quantity)
            .ok_or(PerpetualError::ArithmeticOverflow)?;
        self.db.set_market(&market);
        self.db.remove_position(&position_id);
        u128::try_from(equity).map_err(|_| PerpetualError::ArithmeticOverflow)
    }

    pub async fn liquidate(
        &mut self,
        position_id: PositionId,
        context: RuntimeContext,
    ) -> Result<(), PerpetualError> {
        let position = self
            .db
            .position(&position_id)
            .await?
            .ok_or(PerpetualError::UnknownPosition(position_id))?;
        let mut market = self
            .db
            .market(&position.market)
            .await?
            .ok_or(PerpetualError::UnknownMarket(position.market))?;
        self.ensure_market_ready(&market, context.timestamp_ms)?;
        self.settle_market_funding(&mut market, context.timestamp_ms)?;
        if !self.is_liquidatable_with_market(&position, &market)? {
            return Err(PerpetualError::PositionNotLiquidatable);
        }
        market.open_interest = market
            .open_interest
            .checked_sub(position.quantity)
            .ok_or(PerpetualError::ArithmeticOverflow)?;
        self.db.set_market(&market);
        self.db.remove_position(&position_id);
        Ok(())
    }

    fn ensure_authorized(&self, tx: &Transaction) -> Result<(), PerpetualError> {
        tx.verify()?;
        match &tx.authorization {
            Authorization::Single { .. } => Ok(()),
            Authorization::Multisig { .. } => Err(PerpetualError::Unauthorized),
        }
    }

    async fn apply_operation(
        &mut self,
        signer: &Address,
        operation: &PerpetualOperation,
        context: RuntimeContext,
    ) -> Result<(), PerpetualError> {
        match operation {
            PerpetualOperation::CreateMarket {
                base_asset,
                quote_asset,
                collateral_asset,
                oracle_namespace,
                oracle_interval_ms,
                max_oracle_staleness_ms,
                price_decimals,
                max_leverage_bps,
                maintenance_margin_bps,
                funding_interval_ms,
                max_funding_rate_bps,
            } => {
                self.create_market(
                    *base_asset,
                    *quote_asset,
                    *collateral_asset,
                    *oracle_namespace,
                    *oracle_interval_ms,
                    *max_oracle_staleness_ms,
                    *price_decimals,
                    *max_leverage_bps,
                    *maintenance_margin_bps,
                    *funding_interval_ms,
                    *max_funding_rate_bps,
                )
                .await?;
            }
            PerpetualOperation::RefreshMarketFromOracle { market } => {
                self.refresh_market_from_oracle(*market, context).await?;
            }
            PerpetualOperation::SettleFunding { market } => {
                self.settle_funding(*market, context).await?;
            }
            PerpetualOperation::OpenPosition {
                market,
                side,
                collateral,
                leverage_bps,
            } => {
                self.open_position(
                    signer.clone(),
                    *market,
                    *side,
                    *collateral,
                    *leverage_bps,
                    context,
                )
                .await?;
            }
            PerpetualOperation::AddCollateral { position, amount } => {
                self.add_collateral(signer, *position, *amount).await?;
            }
            PerpetualOperation::ReduceCollateral { position, amount } => {
                self.reduce_collateral(signer, *position, *amount, context)
                    .await?;
            }
            PerpetualOperation::ClosePosition { position } => {
                self.close_position(signer, *position, context).await?;
            }
            PerpetualOperation::Liquidate { position } => {
                self.liquidate(*position, context).await?;
            }
        }
        Ok(())
    }

    fn ensure_market_ready(&self, market: &Market, now_ms: u64) -> Result<(), PerpetualError> {
        if market.mark_price == 0 || market.index_price == 0 {
            return Err(PerpetualError::MarketNotReady);
        }
        let age = now_ms
            .checked_sub(market.last_oracle_update_ms)
            .ok_or(PerpetualError::StaleOraclePrice)?;
        if age > market.max_oracle_staleness_ms {
            return Err(PerpetualError::StaleOraclePrice);
        }
        Ok(())
    }

    fn settle_market_funding(
        &self,
        market: &mut Market,
        now_ms: u64,
    ) -> Result<(), PerpetualError> {
        if market.mark_price == 0 || market.index_price == 0 {
            market.last_funding_ms = now_ms;
            return Ok(());
        }
        if market.last_funding_ms == 0 {
            market.last_funding_ms = now_ms;
            return Ok(());
        }
        let elapsed = now_ms
            .checked_sub(market.last_funding_ms)
            .ok_or(PerpetualError::ArithmeticOverflow)?;
        let intervals = elapsed / market.funding_interval_ms;
        if intervals == 0 {
            return Ok(());
        }

        let rate_bps = funding_rate_bps(market)?;
        let mark = i128_from_u128(market.mark_price)?;
        let delta_per_interval = mark
            .checked_mul(i128::from(rate_bps))
            .ok_or(PerpetualError::ArithmeticOverflow)?
            / i128::from(BPS_DENOMINATOR);
        let delta = delta_per_interval
            .checked_mul(i128::from(intervals))
            .ok_or(PerpetualError::ArithmeticOverflow)?;
        market.cumulative_funding_long = market
            .cumulative_funding_long
            .checked_add(delta)
            .ok_or(PerpetualError::ArithmeticOverflow)?;
        market.cumulative_funding_short = market
            .cumulative_funding_short
            .checked_sub(delta)
            .ok_or(PerpetualError::ArithmeticOverflow)?;
        market.last_funding_ms = market
            .last_funding_ms
            .checked_add(
                intervals
                    .checked_mul(market.funding_interval_ms)
                    .ok_or(PerpetualError::ArithmeticOverflow)?,
            )
            .ok_or(PerpetualError::ArithmeticOverflow)?;
        Ok(())
    }

    fn is_liquidatable_with_market(
        &self,
        position: &Position,
        market: &Market,
    ) -> Result<bool, PerpetualError> {
        let equity = position_equity(position, market)?;
        if equity <= 0 {
            return Ok(true);
        }
        let maintenance = maintenance_margin(position.quantity, market)?;
        let equity = u128::try_from(equity).map_err(|_| PerpetualError::ArithmeticOverflow)?;
        Ok(equity <= maintenance)
    }
}

impl<D: PerpetualDB + StateStore + CommitState + Send + Sync> PerpetualLedger<D> {
    pub async fn commit(&mut self) -> Result<Digest, PerpetualError> {
        self.db
            .commit()
            .await
            .map_err(|err| PerpetualError::Storage(err.to_string()))
    }

    pub fn root(&self) -> Digest {
        self.db.root()
    }
}

fn latest_payload_for_market(
    market: &Market,
    records: &[OracleRecord],
    context: RuntimeContext,
) -> Result<(OracleRecord, OraclePricePayload), PerpetualError> {
    let mut latest: Option<(OracleRecord, OraclePricePayload)> = None;
    for record in records {
        let payload = decode_oracle_payload(&record.payload)?;
        if payload.market != market.id {
            continue;
        }
        if payload.source_timestamp_ms > context.timestamp_ms {
            continue;
        }
        let record_age = context
            .timestamp_ms
            .checked_sub(record.written_at_ms)
            .ok_or(PerpetualError::StaleOraclePrice)?;
        let source_age = context
            .timestamp_ms
            .checked_sub(payload.source_timestamp_ms)
            .ok_or(PerpetualError::StaleOraclePrice)?;
        if record_age > market.max_oracle_staleness_ms
            || source_age > market.max_oracle_staleness_ms
        {
            continue;
        }
        if latest
            .as_ref()
            .is_none_or(|(current, _)| record.written_at_ms > current.written_at_ms)
        {
            latest = Some((record.clone(), payload));
        }
    }
    latest.ok_or(PerpetualError::MissingOraclePrice)
}

fn decode_oracle_payload(bytes: &[u8]) -> Result<OraclePricePayload, PerpetualError> {
    let mut buf = bytes;
    OraclePricePayload::read(&mut buf).map_err(|err| PerpetualError::OraclePayload(err.to_string()))
}

fn validate_market_params(
    oracle_interval_ms: u64,
    max_oracle_staleness_ms: u64,
    price_decimals: u8,
    max_leverage_bps: u32,
    maintenance_margin_bps: u32,
    funding_interval_ms: u64,
    max_funding_rate_bps: u32,
) -> Result<(), PerpetualError> {
    if oracle_interval_ms == 0 {
        return Err(PerpetualError::InvalidOracleInterval);
    }
    if max_oracle_staleness_ms == 0 {
        return Err(PerpetualError::InvalidOracleStaleness);
    }
    if price_decimals > MAX_PRICE_DECIMALS {
        return Err(PerpetualError::InvalidPriceDecimals);
    }
    if max_leverage_bps < BPS_DENOMINATOR {
        return Err(PerpetualError::InvalidLeverage);
    }
    if maintenance_margin_bps == 0 || maintenance_margin_bps >= BPS_DENOMINATOR {
        return Err(PerpetualError::InvalidMaintenanceMargin);
    }
    if funding_interval_ms == 0 {
        return Err(PerpetualError::InvalidFundingInterval);
    }
    if max_funding_rate_bps > BPS_DENOMINATOR {
        return Err(PerpetualError::InvalidFundingRate);
    }
    Ok(())
}

fn scale_price(price: u128, from_decimals: u8, to_decimals: u8) -> Result<u128, PerpetualError> {
    if price == 0 {
        return Err(PerpetualError::InvalidOraclePrice);
    }
    if from_decimals > MAX_PRICE_DECIMALS || to_decimals > MAX_PRICE_DECIMALS {
        return Err(PerpetualError::InvalidPriceDecimals);
    }
    let scaled = if from_decimals > to_decimals {
        let factor = pow10(from_decimals - to_decimals)?;
        price / factor
    } else {
        let factor = pow10(to_decimals - from_decimals)?;
        price
            .checked_mul(factor)
            .ok_or(PerpetualError::ArithmeticOverflow)?
    };
    if scaled == 0 {
        return Err(PerpetualError::InvalidOraclePrice);
    }
    Ok(scaled)
}

fn pow10(exp: u8) -> Result<u128, PerpetualError> {
    let mut value = 1u128;
    for _ in 0..exp {
        value = value
            .checked_mul(10)
            .ok_or(PerpetualError::ArithmeticOverflow)?;
    }
    Ok(value)
}

fn quantity_from_collateral(
    collateral: u128,
    leverage_bps: u32,
    mark_price: u128,
) -> Result<u128, PerpetualError> {
    let notional = collateral
        .checked_mul(u128::from(leverage_bps))
        .ok_or(PerpetualError::ArithmeticOverflow)?
        / u128::from(BPS_DENOMINATOR);
    let quantity = notional
        .checked_mul(PRICE_SCALE)
        .ok_or(PerpetualError::ArithmeticOverflow)?
        / mark_price;
    if quantity == 0 {
        return Err(PerpetualError::InvalidCollateral);
    }
    Ok(quantity)
}

fn notional(quantity: u128, mark_price: u128) -> Result<u128, PerpetualError> {
    quantity
        .checked_mul(mark_price)
        .ok_or(PerpetualError::ArithmeticOverflow)
        .map(|value| value / PRICE_SCALE)
}

fn pnl(position: &Position, mark_price: u128) -> Result<i128, PerpetualError> {
    let entry = i128_from_u128(notional(position.quantity, position.entry_price)?)?;
    let current = i128_from_u128(notional(position.quantity, mark_price)?)?;
    match position.side {
        Side::Long => current
            .checked_sub(entry)
            .ok_or(PerpetualError::ArithmeticOverflow),
        Side::Short => entry
            .checked_sub(current)
            .ok_or(PerpetualError::ArithmeticOverflow),
    }
}

fn position_equity(position: &Position, market: &Market) -> Result<i128, PerpetualError> {
    let collateral = i128_from_u128(position.collateral)?;
    let pnl = pnl(position, market.mark_price)?;
    let funding = funding_payment(position, market)?;
    collateral
        .checked_add(pnl)
        .and_then(|value| value.checked_sub(funding))
        .ok_or(PerpetualError::ArithmeticOverflow)
}

fn maintenance_margin(quantity: u128, market: &Market) -> Result<u128, PerpetualError> {
    notional(quantity, market.mark_price)?
        .checked_mul(u128::from(market.maintenance_margin_bps))
        .ok_or(PerpetualError::ArithmeticOverflow)
        .map(|value| value / u128::from(BPS_DENOMINATOR))
}

fn funding_index_for_side(market: &Market, side: Side) -> i128 {
    match side {
        Side::Long => market.cumulative_funding_long,
        Side::Short => market.cumulative_funding_short,
    }
}

fn funding_payment(position: &Position, market: &Market) -> Result<i128, PerpetualError> {
    let current = funding_index_for_side(market, position.side);
    let delta = current
        .checked_sub(position.entry_funding_index)
        .ok_or(PerpetualError::ArithmeticOverflow)?;
    let quantity = i128_from_u128(position.quantity)?;
    quantity
        .checked_mul(delta)
        .ok_or(PerpetualError::ArithmeticOverflow)
        .map(|value| value / i128_from_u128(PRICE_SCALE).expect("PRICE_SCALE fits i128"))
}

fn funding_rate_bps(market: &Market) -> Result<i32, PerpetualError> {
    if market.index_price == 0 {
        return Err(PerpetualError::MarketNotReady);
    }
    let diff_abs = market.mark_price.abs_diff(market.index_price);
    let raw = diff_abs
        .checked_mul(u128::from(BPS_DENOMINATOR))
        .ok_or(PerpetualError::ArithmeticOverflow)?
        / market.index_price;
    let capped = raw.min(u128::from(market.max_funding_rate_bps));
    let capped = i32::try_from(capped).map_err(|_| PerpetualError::ArithmeticOverflow)?;
    if market.mark_price >= market.index_price {
        Ok(capped)
    } else {
        capped
            .checked_neg()
            .ok_or(PerpetualError::ArithmeticOverflow)
    }
}

fn i128_from_u128(value: u128) -> Result<i128, PerpetualError> {
    i128::try_from(value).map_err(|_| PerpetualError::ArithmeticOverflow)
}

#[cfg(test)]
mod math_tests {
    use super::*;

    #[test]
    fn scale_price_truncates_to_consumer_decimals() {
        assert_eq!(scale_price(50_000_123_456, 6, 2).unwrap(), 5_000_012);
        assert_eq!(scale_price(50_000, 0, 2).unwrap(), 5_000_000);
    }
}
