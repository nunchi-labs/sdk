use crate::{
    derive_market_id, derive_position_id, Address, Authorization, CoinId, Market, MarketId,
    PerpetualDB, PerpetualOperation, Position, PositionId, Side, Transaction, BPS_DENOMINATOR,
    PRICE_SCALE,
};
use commonware_cryptography::sha256::Digest;
use nunchi_common::CommitState;
use nunchi_crypto::SignatureError;
use thiserror::Error;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum LedgerError {
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
    #[error("invalid mark price")]
    InvalidPrice,
    #[error("invalid leverage")]
    InvalidLeverage,
    #[error("invalid maintenance margin")]
    InvalidMaintenanceMargin,
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
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("state storage error: {0}")]
    Storage(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerpetualLedger<D> {
    db: D,
}

impl<D: PerpetualDB> PerpetualLedger<D> {
    pub fn new(db: D) -> Self {
        Self { db }
    }

    pub fn db(&self) -> &D {
        &self.db
    }

    pub fn into_inner(self) -> D {
        self.db
    }

    pub async fn nonce(&self, id: &Address) -> Result<u64, LedgerError> {
        self.db.nonce(id).await
    }

    pub async fn market(&self, id: &MarketId) -> Result<Option<Market>, LedgerError> {
        self.db.market(id).await
    }

    pub async fn position(&self, id: &PositionId) -> Result<Option<Position>, LedgerError> {
        self.db.position(id).await
    }

    pub async fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), LedgerError> {
        self.ensure_authorized(tx)?;

        let expected = self.db.nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(LedgerError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        self.apply_operation(&tx.account_id, &tx.payload.operation)
            .await?;
        let next_nonce = expected.checked_add(1).ok_or(LedgerError::NonceOverflow)?;
        self.db.set_nonce(&tx.account_id, next_nonce);
        Ok(())
    }

    pub async fn create_market(
        &mut self,
        base_asset: CoinId,
        quote_asset: CoinId,
        collateral_asset: CoinId,
        max_leverage_bps: u32,
        maintenance_margin_bps: u32,
        mark_price: u128,
    ) -> Result<MarketId, LedgerError> {
        validate_market_params(max_leverage_bps, maintenance_margin_bps, mark_price)?;
        let nonce = self.db.market_nonce().await?;
        let market_id = derive_market_id(base_asset, quote_asset, collateral_asset, nonce);
        if self.db.market(&market_id).await?.is_some() {
            return Err(LedgerError::DuplicateMarket(market_id));
        }
        let market = Market {
            id: market_id,
            base_asset,
            quote_asset,
            collateral_asset,
            max_leverage_bps,
            maintenance_margin_bps,
            mark_price,
            open_interest: 0,
        };
        self.db.set_market(&market);
        self.db.set_market_nonce(
            nonce
                .checked_add(1)
                .ok_or(LedgerError::MarketNonceOverflow)?,
        );
        Ok(market_id)
    }

    pub async fn update_mark_price(
        &mut self,
        market_id: MarketId,
        mark_price: u128,
    ) -> Result<(), LedgerError> {
        if mark_price == 0 {
            return Err(LedgerError::InvalidPrice);
        }
        let mut market = self
            .db
            .market(&market_id)
            .await?
            .ok_or(LedgerError::UnknownMarket(market_id))?;
        market.mark_price = mark_price;
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
    ) -> Result<PositionId, LedgerError> {
        if collateral == 0 {
            return Err(LedgerError::InvalidCollateral);
        }
        let mut market = self
            .db
            .market(&market_id)
            .await?
            .ok_or(LedgerError::UnknownMarket(market_id))?;
        if leverage_bps < BPS_DENOMINATOR {
            return Err(LedgerError::InvalidLeverage);
        }
        if leverage_bps > market.max_leverage_bps {
            return Err(LedgerError::MaxLeverageExceeded {
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
        };
        market.open_interest = market
            .open_interest
            .checked_add(quantity)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        self.db.set_market(&market);
        self.db.set_position(&position);
        self.db.set_position_nonce(
            nonce
                .checked_add(1)
                .ok_or(LedgerError::PositionNonceOverflow)?,
        );
        Ok(position_id)
    }

    pub async fn add_collateral(
        &mut self,
        owner: &Address,
        position_id: PositionId,
        amount: u128,
    ) -> Result<(), LedgerError> {
        if amount == 0 {
            return Err(LedgerError::InvalidCollateral);
        }
        let mut position = self
            .db
            .position(&position_id)
            .await?
            .ok_or(LedgerError::UnknownPosition(position_id))?;
        if &position.owner != owner {
            return Err(LedgerError::Unauthorized);
        }
        position.collateral = position
            .collateral
            .checked_add(amount)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        self.db.set_position(&position);
        Ok(())
    }

    pub async fn close_position(
        &mut self,
        owner: &Address,
        position_id: PositionId,
    ) -> Result<u128, LedgerError> {
        let position = self
            .db
            .position(&position_id)
            .await?
            .ok_or(LedgerError::UnknownPosition(position_id))?;
        if &position.owner != owner {
            return Err(LedgerError::Unauthorized);
        }
        let mut market = self
            .db
            .market(&position.market)
            .await?
            .ok_or(LedgerError::UnknownMarket(position.market))?;
        let equity = self.position_equity(&position, market.mark_price)?;
        if equity <= 0 {
            return Err(LedgerError::PositionUnderwater(position_id));
        }
        market.open_interest = market
            .open_interest
            .checked_sub(position.quantity)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        self.db.set_market(&market);
        self.db.remove_position(&position_id);
        u128::try_from(equity).map_err(|_| LedgerError::ArithmeticOverflow)
    }

    pub async fn liquidate(&mut self, position_id: PositionId) -> Result<(), LedgerError> {
        let position = self
            .db
            .position(&position_id)
            .await?
            .ok_or(LedgerError::UnknownPosition(position_id))?;
        let mut market = self
            .db
            .market(&position.market)
            .await?
            .ok_or(LedgerError::UnknownMarket(position.market))?;
        if !self.is_liquidatable(&position, &market).await? {
            return Err(LedgerError::PositionNotLiquidatable);
        }
        market.open_interest = market
            .open_interest
            .checked_sub(position.quantity)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        self.db.set_market(&market);
        self.db.remove_position(&position_id);
        Ok(())
    }

    pub async fn is_liquidatable(
        &self,
        position: &Position,
        market: &Market,
    ) -> Result<bool, LedgerError> {
        let notional = notional(position.quantity, market.mark_price)?;
        let maintenance = notional
            .checked_mul(market.maintenance_margin_bps as u128)
            .ok_or(LedgerError::ArithmeticOverflow)?
            / BPS_DENOMINATOR as u128;
        let equity = self.position_equity(position, market.mark_price)?;
        Ok(equity <= to_i128(maintenance)?)
    }

    pub fn position_equity(
        &self,
        position: &Position,
        mark_price: u128,
    ) -> Result<i128, LedgerError> {
        let collateral = to_i128(position.collateral)?;
        let pnl = pnl(
            position.side,
            position.quantity,
            position.entry_price,
            mark_price,
        )?;
        collateral
            .checked_add(pnl)
            .ok_or(LedgerError::ArithmeticOverflow)
    }

    fn ensure_authorized(&self, tx: &Transaction) -> Result<(), LedgerError> {
        tx.verify()?;
        match &tx.authorization {
            Authorization::Single { .. } => Ok(()),
            Authorization::Multisig { .. } => Err(LedgerError::Unauthorized),
        }
    }

    async fn apply_operation(
        &mut self,
        signer: &Address,
        operation: &PerpetualOperation,
    ) -> Result<(), LedgerError> {
        match operation {
            PerpetualOperation::CreateMarket {
                base_asset,
                quote_asset,
                collateral_asset,
                max_leverage_bps,
                maintenance_margin_bps,
                mark_price,
            } => {
                self.create_market(
                    *base_asset,
                    *quote_asset,
                    *collateral_asset,
                    *max_leverage_bps,
                    *maintenance_margin_bps,
                    *mark_price,
                )
                .await?;
            }
            PerpetualOperation::UpdateMarketPrice { market, mark_price } => {
                self.update_mark_price(*market, *mark_price).await?;
            }
            PerpetualOperation::OpenPosition {
                market,
                side,
                collateral,
                leverage_bps,
            } => {
                self.open_position(signer.clone(), *market, *side, *collateral, *leverage_bps)
                    .await?;
            }
            PerpetualOperation::AddCollateral { position, amount } => {
                self.add_collateral(signer, *position, *amount).await?;
            }
            PerpetualOperation::ClosePosition { position } => {
                self.close_position(signer, *position).await?;
            }
            PerpetualOperation::Liquidate { position } => {
                self.liquidate(*position).await?;
            }
        }
        Ok(())
    }
}

impl<D: PerpetualDB + CommitState> PerpetualLedger<D> {
    pub async fn commit(&mut self) -> Result<Digest, LedgerError> {
        self.db
            .commit()
            .await
            .map_err(|err| LedgerError::Storage(err.to_string()))
    }

    pub fn root(&self) -> Digest {
        self.db.root()
    }
}

fn validate_market_params(
    max_leverage_bps: u32,
    maintenance_margin_bps: u32,
    mark_price: u128,
) -> Result<(), LedgerError> {
    if max_leverage_bps < BPS_DENOMINATOR {
        return Err(LedgerError::InvalidLeverage);
    }
    if maintenance_margin_bps == 0 || maintenance_margin_bps >= BPS_DENOMINATOR {
        return Err(LedgerError::InvalidMaintenanceMargin);
    }
    if mark_price == 0 {
        return Err(LedgerError::InvalidPrice);
    }
    Ok(())
}

fn quantity_from_collateral(
    collateral: u128,
    leverage_bps: u32,
    mark_price: u128,
) -> Result<u128, LedgerError> {
    let notional = collateral
        .checked_mul(leverage_bps as u128)
        .ok_or(LedgerError::ArithmeticOverflow)?
        / BPS_DENOMINATOR as u128;
    let quantity = notional
        .checked_mul(PRICE_SCALE)
        .ok_or(LedgerError::ArithmeticOverflow)?
        / mark_price;
    if quantity == 0 {
        return Err(LedgerError::InvalidCollateral);
    }
    Ok(quantity)
}

fn notional(quantity: u128, mark_price: u128) -> Result<u128, LedgerError> {
    quantity
        .checked_mul(mark_price)
        .ok_or(LedgerError::ArithmeticOverflow)
        .map(|value| value / PRICE_SCALE)
}

fn pnl(
    side: Side,
    quantity: u128,
    entry_price: u128,
    mark_price: u128,
) -> Result<i128, LedgerError> {
    let (positive, diff) = match side {
        Side::Long if mark_price >= entry_price => (true, mark_price - entry_price),
        Side::Long => (false, entry_price - mark_price),
        Side::Short if entry_price >= mark_price => (true, entry_price - mark_price),
        Side::Short => (false, mark_price - entry_price),
    };
    let value = quantity
        .checked_mul(diff)
        .ok_or(LedgerError::ArithmeticOverflow)?
        / PRICE_SCALE;
    let signed = to_i128(value)?;
    if positive {
        Ok(signed)
    } else {
        signed.checked_neg().ok_or(LedgerError::ArithmeticOverflow)
    }
}

fn to_i128(value: u128) -> Result<i128, LedgerError> {
    i128::try_from(value).map_err(|_| LedgerError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
    use nunchi_common::QmdbState;
    use nunchi_crypto::PrivateKey;

    async fn ledger(
        context: deterministic::Context,
    ) -> PerpetualLedger<QmdbState<deterministic::Context>> {
        let db = QmdbState::init(context, "perpetuals-test")
            .await
            .expect("init state db");
        PerpetualLedger::new(db)
    }

    fn coin(label: &[u8]) -> CoinId {
        CoinId(Sha256::hash(label))
    }

    fn address(seed: u64) -> Address {
        Address::external(&PrivateKey::ed25519_from_seed(seed).public_key())
    }

    async fn create_market(
        ledger: &mut PerpetualLedger<QmdbState<deterministic::Context>>,
    ) -> MarketId {
        ledger
            .create_market(
                coin(b"BTC"),
                coin(b"USD"),
                coin(b"USDC"),
                50_000,
                500,
                50_000 * PRICE_SCALE,
            )
            .await
            .expect("create market")
    }

    #[test]
    fn create_market_and_open_position() {
        deterministic::Runner::default().start(|context| async move {
            let mut ledger = ledger(context).await;
            let market_id = create_market(&mut ledger).await;
            let alice = address(1);

            let position_id = ledger
                .open_position(alice.clone(), market_id, Side::Long, 1_000, 20_000)
                .await
                .expect("open position");

            let market = ledger.market(&market_id).await.unwrap().unwrap();
            let position = ledger.position(&position_id).await.unwrap().unwrap();
            assert_eq!(position.owner, alice);
            assert_eq!(position.entry_price, 50_000 * PRICE_SCALE);
            assert_eq!(market.open_interest, position.quantity);
        });
    }

    #[test]
    fn signed_transactions_bump_nonce() {
        deterministic::Runner::default().start(|context| async move {
            let mut ledger = ledger(context).await;
            let market_id = create_market(&mut ledger).await;
            let alice_key = PrivateKey::ed25519_from_seed(7);
            let alice = Address::external(&alice_key.public_key());

            let tx = Transaction::sign(
                &alice_key,
                0,
                PerpetualOperation::OpenPosition {
                    market: market_id,
                    side: Side::Long,
                    collateral: 2_000,
                    leverage_bps: 15_000,
                },
            );
            ledger.apply_transaction(&tx).await.expect("apply tx");

            assert_eq!(ledger.nonce(&alice).await.unwrap(), 1);
        });
    }

    #[test]
    fn close_position_realizes_profit() {
        deterministic::Runner::default().start(|context| async move {
            let mut ledger = ledger(context).await;
            let market_id = create_market(&mut ledger).await;
            let alice = address(2);

            let position_id = ledger
                .open_position(alice.clone(), market_id, Side::Long, 1_000, 20_000)
                .await
                .expect("open position");
            ledger
                .update_mark_price(market_id, 60_000 * PRICE_SCALE)
                .await
                .expect("update price");
            let settled = ledger
                .close_position(&alice, position_id)
                .await
                .expect("close position");

            assert!(settled > 1_000);
            assert!(ledger.position(&position_id).await.unwrap().is_none());
        });
    }

    #[test]
    fn rejects_leverage_above_market_limit() {
        deterministic::Runner::default().start(|context| async move {
            let mut ledger = ledger(context).await;
            let market_id = create_market(&mut ledger).await;
            let err = ledger
                .open_position(address(3), market_id, Side::Short, 1_000, 60_000)
                .await
                .unwrap_err();
            assert_eq!(
                err,
                LedgerError::MaxLeverageExceeded {
                    max: 50_000,
                    requested: 60_000,
                }
            );
        });
    }

    #[test]
    fn liquidates_underwater_position() {
        deterministic::Runner::default().start(|context| async move {
            let mut ledger = ledger(context).await;
            let market_id = create_market(&mut ledger).await;
            let bob = address(4);
            let position_id = ledger
                .open_position(bob, market_id, Side::Long, 1_000, 50_000)
                .await
                .expect("open position");

            ledger
                .update_mark_price(market_id, 48_000 * PRICE_SCALE)
                .await
                .expect("update price");
            ledger.liquidate(position_id).await.expect("liquidate");

            assert!(ledger.position(&position_id).await.unwrap().is_none());
        });
    }
}
