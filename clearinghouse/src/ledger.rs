use crate::{
    derive_settlement_market_id, ClearinghouseDB, ClearinghouseOperation, SettlementDomain,
    SettlementMarket, SettlementMarketId, Transaction,
};
use nunchi_clob::{ClobDB, ClobError, ClobLedger, Fill, FillId, Side as ClobSide};
use nunchi_common::{Address, Authorization, RuntimeContext, StateStore};
use nunchi_crypto::SignatureError;
use nunchi_perpetuals::{PerpetualDB, PerpetualError, Side as PerpsSide};
use thiserror::Error;

/// Deterministic clearinghouse state-machine errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ClearinghouseError {
    #[error("bad clearinghouse transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("settlement market already registered for clob market {0:?}")]
    DuplicateSettlementMarket(nunchi_clob::MarketId),
    #[error("settlement market not found")]
    SettlementMarketNotFound,
    #[error("fill not found")]
    FillNotFound,
    #[error("fill already settled")]
    FillAlreadySettled,
    #[error("unauthorized clearinghouse operation")]
    Unauthorized,
    #[error("clob module error: {0}")]
    Clob(#[from] ClobError),
    #[error("perpetuals module error: {0}")]
    Perpetuals(#[from] PerpetualError),
    #[error("invalid fill quantity")]
    InvalidFillQuantity,
    #[error("state storage error: {0}")]
    Storage(String),
}

/// Settlement ledger routing CLOB fills to consumer modules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClearinghouseLedger<D> {
    db: D,
}

impl<D> ClearinghouseLedger<D> {
    /// Wrap a database backend as a clearinghouse ledger.
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
}

impl<D: ClearinghouseDB + ClobDB + PerpetualDB + StateStore + Send + Sync> ClearinghouseLedger<D> {
    pub async fn nonce(&self, id: &Address) -> Result<u64, ClearinghouseError> {
        ClearinghouseDB::nonce(&self.db, id).await
    }

    /// Validate and apply a signed clearinghouse transaction.
    pub async fn apply_transaction(
        &mut self,
        tx: &Transaction,
        context: RuntimeContext,
    ) -> Result<(), ClearinghouseError> {
        self.ensure_authorized(tx)?;
        let expected = ClearinghouseDB::nonce(&self.db, &tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(ClearinghouseError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }
        self.apply_operation(&tx.payload.operation, context).await?;
        let next_nonce = expected
            .checked_add(1)
            .ok_or(ClearinghouseError::NonceOverflow)?;
        ClearinghouseDB::set_nonce(&mut self.db, &tx.account_id, next_nonce);
        Ok(())
    }

    pub async fn register_perps_market(
        &mut self,
        clob_market: nunchi_clob::MarketId,
        perps_market: nunchi_perpetuals::MarketId,
    ) -> Result<SettlementMarketId, ClearinghouseError> {
        if self
            .db
            .settlement_market_for_clob(&clob_market)
            .await?
            .is_some()
        {
            return Err(ClearinghouseError::DuplicateSettlementMarket(clob_market));
        }
        let domain = SettlementDomain::Perps(perps_market);
        let id = derive_settlement_market_id(&clob_market, &domain);
        let market = SettlementMarket {
            id,
            clob_market,
            domain,
        };
        self.db.set_settlement_market(&market);
        self.db.set_clob_market_index(&clob_market, &id);
        Ok(id)
    }

    pub async fn settle_fill(
        &mut self,
        fill_id: FillId,
        context: RuntimeContext,
    ) -> Result<(), ClearinghouseError> {
        if self.db.is_fill_settled(&fill_id).await? {
            return Err(ClearinghouseError::FillAlreadySettled);
        }
        let fill = self
            .db
            .fill(&fill_id)
            .await?
            .ok_or(ClearinghouseError::FillNotFound)?;
        if fill.base_quantity == 0 {
            return Err(ClearinghouseError::InvalidFillQuantity);
        }
        let settlement = self
            .db
            .settlement_market_for_clob(&fill.market)
            .await?
            .ok_or(ClearinghouseError::SettlementMarketNotFound)?;
        match settlement.domain {
            SettlementDomain::Perps(perps_market) => {
                self.settle_perps_fill(&fill, perps_market, context)
                    .await?;
            }
        }
        self.db.mark_fill_settled(&fill_id);
        Ok(())
    }

    pub async fn commit_and_settle_fill(
        &mut self,
        fill: Fill,
        context: RuntimeContext,
    ) -> Result<(), ClearinghouseError> {
        let fill_id = fill.id;
        ClobLedger::new(&mut self.db)
            .record_fill(&fill)
            .await?;
        self.settle_fill(fill_id, context).await
    }

    async fn settle_perps_fill(
        &mut self,
        fill: &Fill,
        perps_market: nunchi_perpetuals::MarketId,
        context: RuntimeContext,
    ) -> Result<(), ClearinghouseError> {
        let maker_side = clob_side_to_perps_side(fill.taker_side.opposite());
        let taker_side = clob_side_to_perps_side(fill.taker_side);
        nunchi_perpetuals::apply_fill_settlement(
            &mut self.db,
            fill.maker.clone(),
            perps_market,
            maker_side,
            fill.price,
            fill.base_quantity,
            context,
        )
        .await?;
        nunchi_perpetuals::apply_fill_settlement(
            &mut self.db,
            fill.taker.clone(),
            perps_market,
            taker_side,
            fill.price,
            fill.base_quantity,
            context,
        )
        .await?;
        Ok(())
    }

    async fn apply_operation(
        &mut self,
        operation: &ClearinghouseOperation,
        context: RuntimeContext,
    ) -> Result<(), ClearinghouseError> {
        match operation {
            ClearinghouseOperation::RegisterPerpsMarket {
                clob_market,
                perps_market,
            } => {
                self.register_perps_market(*clob_market, *perps_market)
                    .await?;
            }
            ClearinghouseOperation::SettleFill { fill } => {
                self.settle_fill(*fill, context).await?;
            }
            ClearinghouseOperation::CommitAndSettleFill { fill } => {
                self.commit_and_settle_fill(fill.as_ref().clone(), context).await?;
            }
        }
        Ok(())
    }

    fn ensure_authorized(&self, tx: &Transaction) -> Result<(), ClearinghouseError> {
        tx.verify()?;
        match &tx.authorization {
            Authorization::Single { .. } => Ok(()),
            Authorization::Multisig { .. } => Err(ClearinghouseError::Unauthorized),
        }
    }
}

fn clob_side_to_perps_side(side: ClobSide) -> PerpsSide {
    match side {
        ClobSide::Bid => PerpsSide::Long,
        ClobSide::Ask => PerpsSide::Short,
    }
}
