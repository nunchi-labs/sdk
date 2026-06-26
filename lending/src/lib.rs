//! Minimal collateralized lending primitives over Nunchi coin balances.
//!
//! This module composes with `nunchi-coins` by keeping lending markets and
//! positions in its own namespace while moving collateral and borrowed assets
//! through the shared coin balance database. The first version models a fixed
//! collateral-factor market with `ISFR + utilization_rate` borrow quotes.

use async_trait::async_trait;
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_coins::{Address, CoinDB, CoinId, LedgerError};
use nunchi_common::{Namespace, Operation, StateStore};
use nunchi_crypto::SignatureError;
use serde::Deserialize;
use thiserror::Error;

/// Domain separator used for lending transaction signatures and state keys.
pub const LENDING_NAMESPACE: &[u8] = b"_NUNCHI_LENDING";
const BPS_DENOMINATOR: u128 = 10_000;
const MAX_COLLATERAL_FACTOR_BPS: u16 = 10_000;
const DIGEST_LENGTH: usize = 32;
const MARKET_DERIVATION_DOMAIN: &[u8] = b"nunchi/lending/market/v1";
const RESERVE_DERIVATION_DOMAIN: &[u8] = b"nunchi/lending/reserve/v1";
const NS: Namespace = Namespace::new(LENDING_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    Market = 0,
    Position = 1,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

/// A deterministic identifier for a lending market.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MarketId(pub Digest);

impl Write for MarketId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for MarketId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(Digest::read(buf)?))
    }
}

impl EncodeSize for MarketId {
    fn encode_size(&self) -> usize {
        DIGEST_LENGTH
    }
}

/// Floating-rate benchmark used by lending markets.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateBenchmark {
    /// Interchain Secured Funding Rate. Used like the `L` leg in `L + spread`.
    Isfr = 0,
}

impl Write for RateBenchmark {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        (*self as u8).write(buf);
    }
}

impl Read for RateBenchmark {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Isfr),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for RateBenchmark {
    fn encode_size(&self) -> usize {
        1
    }
}

/// Aave-style variable borrow rate strategy, expressed in basis points.
///
/// The market borrow rate is quoted as `live ISFR + utilization_rate_bps`.
/// Utilization rate follows the common two-slope kinked curve:
///
/// - below `optimal_utilization_bps`: `base_rate_bps + slope1 * U / optimal`
/// - above `optimal_utilization_bps`: `base_rate_bps + slope1 + slope2 * excess / (1 - optimal)`
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterestRateModel {
    pub benchmark: RateBenchmark,
    pub optimal_utilization_bps: u16,
    pub base_rate_bps: i64,
    pub slope1_bps: i64,
    pub slope2_bps: i64,
    pub reserve_factor_bps: u16,
}

impl InterestRateModel {
    pub fn isfr_aave_style(
        optimal_utilization_bps: u16,
        base_rate_bps: i64,
        slope1_bps: i64,
        slope2_bps: i64,
        reserve_factor_bps: u16,
    ) -> Result<Self, LendingError> {
        if optimal_utilization_bps == 0 || optimal_utilization_bps >= 10_000 {
            return Err(LendingError::InvalidInterestRateModel);
        }
        if reserve_factor_bps > 10_000 {
            return Err(LendingError::InvalidInterestRateModel);
        }
        if base_rate_bps < 0 || slope1_bps < 0 || slope2_bps < 0 {
            return Err(LendingError::InvalidInterestRateModel);
        }

        Ok(Self {
            benchmark: RateBenchmark::Isfr,
            optimal_utilization_bps,
            base_rate_bps,
            slope1_bps,
            slope2_bps,
            reserve_factor_bps,
        })
    }

    pub fn utilization_rate_bps(&self, utilization_bps: u16) -> Result<i64, LendingError> {
        let utilization = u128::from(utilization_bps);
        let optimal = u128::from(self.optimal_utilization_bps);

        if utilization <= optimal {
            return checked_rate_add(
                self.base_rate_bps,
                checked_rate_mul_div(self.slope1_bps, utilization, optimal)?,
            );
        }

        let excess = utilization - optimal;
        let excess_denominator = BPS_DENOMINATOR - optimal;
        checked_rate_add(
            checked_rate_add(self.base_rate_bps, self.slope1_bps)?,
            checked_rate_mul_div(self.slope2_bps, excess, excess_denominator)?,
        )
    }

    pub fn borrow_rate_bps(
        &self,
        benchmark_rate_bps: i64,
        utilization_bps: u16,
    ) -> Result<i64, LendingError> {
        checked_rate_add(
            benchmark_rate_bps,
            self.utilization_rate_bps(utilization_bps)?,
        )
    }

    pub fn supply_rate_bps(
        &self,
        borrow_rate_bps: i64,
        utilization_bps: u16,
    ) -> Result<i64, LendingError> {
        let after_utilization = checked_rate_mul_div(
            borrow_rate_bps,
            u128::from(utilization_bps),
            BPS_DENOMINATOR,
        )?;
        checked_rate_mul_div(
            after_utilization,
            BPS_DENOMINATOR - u128::from(self.reserve_factor_bps),
            BPS_DENOMINATOR,
        )
    }

    fn validate(&self) -> Result<(), LendingError> {
        if self.benchmark != RateBenchmark::Isfr {
            return Err(LendingError::InvalidInterestRateModel);
        }
        if self.optimal_utilization_bps == 0 || self.optimal_utilization_bps >= 10_000 {
            return Err(LendingError::InvalidInterestRateModel);
        }
        if self.reserve_factor_bps > 10_000 {
            return Err(LendingError::InvalidInterestRateModel);
        }
        if self.base_rate_bps < 0 || self.slope1_bps < 0 || self.slope2_bps < 0 {
            return Err(LendingError::InvalidInterestRateModel);
        }
        Ok(())
    }
}

impl Default for InterestRateModel {
    fn default() -> Self {
        Self {
            benchmark: RateBenchmark::Isfr,
            optimal_utilization_bps: 8_000,
            base_rate_bps: 0,
            slope1_bps: 400,
            slope2_bps: 6_000,
            reserve_factor_bps: 1_000,
        }
    }
}

impl Write for InterestRateModel {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.benchmark.write(buf);
        self.optimal_utilization_bps.write(buf);
        self.base_rate_bps.write(buf);
        self.slope1_bps.write(buf);
        self.slope2_bps.write(buf);
        self.reserve_factor_bps.write(buf);
    }
}

impl Read for InterestRateModel {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            benchmark: RateBenchmark::read(buf)?,
            optimal_utilization_bps: u16::read(buf)?,
            base_rate_bps: i64::read(buf)?,
            slope1_bps: i64::read(buf)?,
            slope2_bps: i64::read(buf)?,
            reserve_factor_bps: u16::read(buf)?,
        })
    }
}

impl EncodeSize for InterestRateModel {
    fn encode_size(&self) -> usize {
        self.benchmark.encode_size()
            + self.optimal_utilization_bps.encode_size()
            + self.base_rate_bps.encode_size()
            + self.slope1_bps.encode_size()
            + self.slope2_bps.encode_size()
            + self.reserve_factor_bps.encode_size()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterestRateQuote {
    pub benchmark: RateBenchmark,
    pub benchmark_epoch: u64,
    pub benchmark_timestamp: Option<u64>,
    pub benchmark_rate_bps: i64,
    pub available_liquidity: u128,
    pub total_borrowed: u128,
    pub utilization_bps: u16,
    pub protocol_rate_bps: i64,
    pub borrow_rate_bps: i64,
    pub supply_rate_bps: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct IsfrSnapshot {
    pub epoch: u64,
    pub timestamp: Option<u64>,
    pub lending_bps: Option<i64>,
    pub composite_bps: Option<i64>,
    pub confidence_bps: Option<u16>,
    pub source: Option<String>,
}

impl IsfrSnapshot {
    pub fn lending_rate_bps(&self) -> Result<i64, LendingError> {
        self.lending_bps.ok_or(LendingError::MissingIsfrRate)
    }
}

#[async_trait]
pub trait IsfrRateProvider {
    async fn current_snapshot(&self) -> Result<IsfrSnapshot, LendingError>;
}

#[derive(Clone, Debug)]
pub struct HttpIsfrClient {
    base_url: String,
    client: reqwest::Client,
}

impl HttpIsfrClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub fn local() -> Self {
        Self::new("http://127.0.0.1:8001")
    }
}

#[async_trait]
impl IsfrRateProvider for HttpIsfrClient {
    async fn current_snapshot(&self) -> Result<IsfrSnapshot, LendingError> {
        let url = format!("{}/isfr/current", self.base_url);
        self.client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|err| LendingError::IsfrApi(err.to_string()))?
            .error_for_status()
            .map_err(|err| LendingError::IsfrApi(err.to_string()))?
            .json::<IsfrSnapshot>()
            .await
            .map_err(|err| LendingError::IsfrApi(err.to_string()))
    }
}

/// Persistent lending market state.
///
/// Collateral and debt are valued 1:1 in token base units in this MVP. A
/// production market should replace that with an oracle-backed risk engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarketState {
    pub id: MarketId,
    pub collateral_coin: CoinId,
    pub borrow_coin: CoinId,
    pub reserve_account: Address,
    pub collateral_factor_bps: u16,
    pub interest_rate_model: InterestRateModel,
    pub total_collateral: u128,
    pub total_borrowed: u128,
}

impl MarketState {
    pub fn new(
        collateral_coin: CoinId,
        borrow_coin: CoinId,
        collateral_factor_bps: u16,
        interest_rate_model: InterestRateModel,
    ) -> Result<Self, LendingError> {
        if collateral_coin == borrow_coin {
            return Err(LendingError::IdenticalCoins);
        }
        if collateral_factor_bps == 0 || collateral_factor_bps > MAX_COLLATERAL_FACTOR_BPS {
            return Err(LendingError::InvalidCollateralFactor);
        }
        interest_rate_model.validate()?;
        let id = market_id(collateral_coin, borrow_coin);
        Ok(Self {
            id,
            collateral_coin,
            borrow_coin,
            reserve_account: reserve_account(id),
            collateral_factor_bps,
            interest_rate_model,
            total_collateral: 0,
            total_borrowed: 0,
        })
    }

    pub fn interest_rate_quote_from_isfr(
        &self,
        snapshot: &IsfrSnapshot,
        available_liquidity: u128,
    ) -> Result<InterestRateQuote, LendingError> {
        let benchmark_rate_bps = snapshot.lending_rate_bps()?;
        let utilization_bps = utilization_bps(self.total_borrowed, available_liquidity)?;
        let protocol_rate_bps = self
            .interest_rate_model
            .utilization_rate_bps(utilization_bps)?;
        let borrow_rate_bps = self
            .interest_rate_model
            .borrow_rate_bps(benchmark_rate_bps, utilization_bps)?;
        let supply_rate_bps = self
            .interest_rate_model
            .supply_rate_bps(borrow_rate_bps, utilization_bps)?;

        Ok(InterestRateQuote {
            benchmark: self.interest_rate_model.benchmark,
            benchmark_epoch: snapshot.epoch,
            benchmark_timestamp: snapshot.timestamp,
            benchmark_rate_bps,
            available_liquidity,
            total_borrowed: self.total_borrowed,
            utilization_bps,
            protocol_rate_bps,
            borrow_rate_bps,
            supply_rate_bps,
        })
    }
}

impl Write for MarketState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.collateral_coin.write(buf);
        self.borrow_coin.write(buf);
        self.reserve_account.write(buf);
        self.collateral_factor_bps.write(buf);
        self.interest_rate_model.write(buf);
        self.total_collateral.write(buf);
        self.total_borrowed.write(buf);
    }
}

impl Read for MarketState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            id: MarketId::read(buf)?,
            collateral_coin: CoinId::read(buf)?,
            borrow_coin: CoinId::read(buf)?,
            reserve_account: Address::read(buf)?,
            collateral_factor_bps: u16::read(buf)?,
            interest_rate_model: InterestRateModel::read(buf)?,
            total_collateral: u128::read(buf)?,
            total_borrowed: u128::read(buf)?,
        })
    }
}

impl EncodeSize for MarketState {
    fn encode_size(&self) -> usize {
        self.id.encode_size()
            + self.collateral_coin.encode_size()
            + self.borrow_coin.encode_size()
            + self.reserve_account.encode_size()
            + self.collateral_factor_bps.encode_size()
            + self.interest_rate_model.encode_size()
            + self.total_collateral.encode_size()
            + self.total_borrowed.encode_size()
    }
}

/// Account-level lending position in a market.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Position {
    pub collateral: u128,
    pub debt: u128,
}

impl Position {
    fn is_empty(&self) -> bool {
        self.collateral == 0 && self.debt == 0
    }
}

impl Write for Position {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.collateral.write(buf);
        self.debt.write(buf);
    }
}

impl Read for Position {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            collateral: u128::read(buf)?,
            debt: u128::read(buf)?,
        })
    }
}

impl EncodeSize for Position {
    fn encode_size(&self) -> usize {
        self.collateral.encode_size() + self.debt.encode_size()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PositionUpdate {
    pub market_id: MarketId,
    pub account: Address,
    pub collateral: u128,
    pub debt: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LendingExecution {
    MarketCreated(MarketState),
    CollateralSupplied(PositionUpdate),
    CollateralWithdrawn(PositionUpdate),
    Borrowed(PositionUpdate),
    Repaid(PositionUpdate),
}

/// Derive the canonical lending market id for a collateral/debt pair.
pub fn market_id(collateral_coin: CoinId, borrow_coin: CoinId) -> MarketId {
    let mut hasher = Sha256::new();
    hasher.update(MARKET_DERIVATION_DOMAIN);
    hasher.update(collateral_coin.encode().as_ref());
    hasher.update(borrow_coin.encode().as_ref());
    MarketId(hasher.finalize())
}

/// Derive the account that holds market collateral and borrow liquidity.
pub fn reserve_account(market_id: MarketId) -> Address {
    let mut hasher = Sha256::new();
    hasher.update(RESERVE_DERIVATION_DOMAIN);
    hasher.update(market_id.encode().as_ref());
    let digest = hasher.finalize();
    let encoded = digest.encode();
    Address::read(&mut encoded.as_ref()).expect("digest encodes as address")
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, LendingError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| LendingError::Storage(err.to_string()))
}

fn market_key(market_id: MarketId) -> Digest {
    NS.key(Table::Market, market_id.encode().as_ref())
}

fn position_key(market_id: MarketId, account: &Address) -> Digest {
    let mut logical = encoded(&market_id);
    logical.extend_from_slice(account.encode().as_ref());
    NS.key(Table::Position, &logical)
}

#[async_trait]
pub trait LendingDB {
    async fn market(&self, market_id: MarketId) -> Result<Option<MarketState>, LendingError>;
    fn set_market(&mut self, market: &MarketState);
    async fn position(
        &self,
        market_id: MarketId,
        account: &Address,
    ) -> Result<Position, LendingError>;
    fn set_position(&mut self, market_id: MarketId, account: &Address, position: &Position);
}

#[async_trait]
impl<S: StateStore + Send + Sync> LendingDB for S {
    async fn market(&self, market_id: MarketId) -> Result<Option<MarketState>, LendingError> {
        match StateStore::get(self, &market_key(market_id))
            .await
            .map_err(|err| LendingError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded::<MarketState>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_market(&mut self, market: &MarketState) {
        StateStore::set(self, market_key(market.id), encoded(market));
    }

    async fn position(
        &self,
        market_id: MarketId,
        account: &Address,
    ) -> Result<Position, LendingError> {
        match StateStore::get(self, &position_key(market_id, account))
            .await
            .map_err(|err| LendingError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<Position>(&bytes),
            None => Ok(Position::default()),
        }
    }

    fn set_position(&mut self, market_id: MarketId, account: &Address, position: &Position) {
        let key = position_key(market_id, account);
        if position.is_empty() {
            StateStore::remove(self, key);
        } else {
            StateStore::set(self, key, encoded(position));
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LendingOperationId {
    CreateMarket = 0,
    SupplyCollateral = 1,
    WithdrawCollateral = 2,
    Borrow = 3,
    Repay = 4,
}

impl Write for LendingOperationId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        (*self as u8).write(buf);
    }
}

impl Read for LendingOperationId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::CreateMarket),
            1 => Ok(Self::SupplyCollateral),
            2 => Ok(Self::WithdrawCollateral),
            3 => Ok(Self::Borrow),
            4 => Ok(Self::Repay),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// A signed lending operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LendingOperation {
    CreateMarket {
        collateral_coin: CoinId,
        borrow_coin: CoinId,
        collateral_factor_bps: u16,
        interest_rate_model: InterestRateModel,
    },
    SupplyCollateral {
        market_id: MarketId,
        amount: u128,
    },
    WithdrawCollateral {
        market_id: MarketId,
        amount: u128,
    },
    Borrow {
        market_id: MarketId,
        amount: u128,
    },
    Repay {
        market_id: MarketId,
        amount: u128,
    },
}

impl Write for LendingOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::CreateMarket {
                collateral_coin,
                borrow_coin,
                collateral_factor_bps,
                interest_rate_model,
            } => {
                LendingOperationId::CreateMarket.write(buf);
                collateral_coin.write(buf);
                borrow_coin.write(buf);
                collateral_factor_bps.write(buf);
                interest_rate_model.write(buf);
            }
            Self::SupplyCollateral { market_id, amount } => {
                LendingOperationId::SupplyCollateral.write(buf);
                market_id.write(buf);
                amount.write(buf);
            }
            Self::WithdrawCollateral { market_id, amount } => {
                LendingOperationId::WithdrawCollateral.write(buf);
                market_id.write(buf);
                amount.write(buf);
            }
            Self::Borrow { market_id, amount } => {
                LendingOperationId::Borrow.write(buf);
                market_id.write(buf);
                amount.write(buf);
            }
            Self::Repay { market_id, amount } => {
                LendingOperationId::Repay.write(buf);
                market_id.write(buf);
                amount.write(buf);
            }
        }
    }
}

impl Read for LendingOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match LendingOperationId::read(buf)? {
            LendingOperationId::CreateMarket => Ok(Self::CreateMarket {
                collateral_coin: CoinId::read(buf)?,
                borrow_coin: CoinId::read(buf)?,
                collateral_factor_bps: u16::read(buf)?,
                interest_rate_model: InterestRateModel::read(buf)?,
            }),
            LendingOperationId::SupplyCollateral => Ok(Self::SupplyCollateral {
                market_id: MarketId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            LendingOperationId::WithdrawCollateral => Ok(Self::WithdrawCollateral {
                market_id: MarketId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            LendingOperationId::Borrow => Ok(Self::Borrow {
                market_id: MarketId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            LendingOperationId::Repay => Ok(Self::Repay {
                market_id: MarketId::read(buf)?,
                amount: u128::read(buf)?,
            }),
        }
    }
}

impl EncodeSize for LendingOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::CreateMarket {
                collateral_coin,
                borrow_coin,
                collateral_factor_bps,
                interest_rate_model,
            } => {
                collateral_coin.encode_size()
                    + borrow_coin.encode_size()
                    + collateral_factor_bps.encode_size()
                    + interest_rate_model.encode_size()
            }
            Self::SupplyCollateral { market_id, amount }
            | Self::WithdrawCollateral { market_id, amount }
            | Self::Borrow { market_id, amount }
            | Self::Repay { market_id, amount } => market_id.encode_size() + amount.encode_size(),
        }
    }
}

impl Operation for LendingOperation {
    const NAMESPACE: &'static [u8] = LENDING_NAMESPACE;
}

pub type Transaction = nunchi_common::Transaction<LendingOperation>;
pub type TransactionPayload = nunchi_common::TransactionPayload<LendingOperation>;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum LendingError {
    #[error("bad transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("interest rate overflow")]
    RateOverflow,
    #[error("invalid interest rate model")]
    InvalidInterestRateModel,
    #[error("ISFR API error: {0}")]
    IsfrApi(String),
    #[error("ISFR snapshot did not include lending_bps")]
    MissingIsfrRate,
    #[error("invalid zero amount")]
    InvalidAmount,
    #[error("collateral and borrow coins must differ")]
    IdenticalCoins,
    #[error("invalid collateral factor")]
    InvalidCollateralFactor,
    #[error("unknown coin {0:?}")]
    UnknownCoin(CoinId),
    #[error("market already exists {0:?}")]
    DuplicateMarket(MarketId),
    #[error("unknown market {0:?}")]
    UnknownMarket(MarketId),
    #[error("insufficient balance for {account:?} in {coin:?}: available {available}, required {required}")]
    InsufficientBalance {
        account: Box<Address>,
        coin: Box<CoinId>,
        available: u128,
        required: u128,
    },
    #[error("insufficient collateral: available {available}, required {required}")]
    InsufficientCollateral { available: u128, required: u128 },
    #[error("insufficient debt: outstanding {outstanding}, attempted {attempted}")]
    InsufficientDebt { outstanding: u128, attempted: u128 },
    #[error("insufficient market liquidity: available {available}, required {required}")]
    InsufficientLiquidity { available: u128, required: u128 },
    #[error(
        "position would be undercollateralized: max debt {max_debt}, attempted {attempted_debt}"
    )]
    Undercollateralized {
        max_debt: u128,
        attempted_debt: u128,
    },
    #[error("amount overflow")]
    AmountOverflow,
    #[error("state storage error: {0}")]
    Storage(String),
    #[error("coin ledger error: {0}")]
    Coins(#[from] LedgerError),
}

/// Lending state transition helper over a coin database.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LendingLedger<D> {
    db: D,
}

impl<D: CoinDB + LendingDB> LendingLedger<D> {
    pub fn new(db: D) -> Self {
        Self { db }
    }

    pub fn db(&self) -> &D {
        &self.db
    }

    pub fn into_inner(self) -> D {
        self.db
    }

    pub async fn apply_transaction(
        &mut self,
        tx: &Transaction,
    ) -> Result<LendingExecution, LendingError> {
        tx.verify()?;

        let expected = self.db.nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(LendingError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        let outcome = match &tx.payload.operation {
            LendingOperation::CreateMarket {
                collateral_coin,
                borrow_coin,
                collateral_factor_bps,
                interest_rate_model,
            } => LendingExecution::MarketCreated(
                self.create_market(
                    *collateral_coin,
                    *borrow_coin,
                    *collateral_factor_bps,
                    interest_rate_model.clone(),
                )
                .await?,
            ),
            LendingOperation::SupplyCollateral { market_id, amount } => {
                LendingExecution::CollateralSupplied(
                    self.supply_collateral(*market_id, &tx.account_id, *amount)
                        .await?,
                )
            }
            LendingOperation::WithdrawCollateral { market_id, amount } => {
                LendingExecution::CollateralWithdrawn(
                    self.withdraw_collateral(*market_id, &tx.account_id, *amount)
                        .await?,
                )
            }
            LendingOperation::Borrow { market_id, amount } => {
                LendingExecution::Borrowed(self.borrow(*market_id, &tx.account_id, *amount).await?)
            }
            LendingOperation::Repay { market_id, amount } => {
                LendingExecution::Repaid(self.repay(*market_id, &tx.account_id, *amount).await?)
            }
        };

        let next_nonce = expected.checked_add(1).ok_or(LendingError::NonceOverflow)?;
        self.db.set_nonce(&tx.account_id, next_nonce);
        Ok(outcome)
    }

    pub async fn market(&self, market_id: MarketId) -> Result<Option<MarketState>, LendingError> {
        self.db.market(market_id).await
    }

    pub async fn position(
        &self,
        market_id: MarketId,
        account: &Address,
    ) -> Result<Position, LendingError> {
        self.db.position(market_id, account).await
    }

    pub async fn interest_rate_quote_from_isfr(
        &self,
        market_id: MarketId,
        snapshot: &IsfrSnapshot,
    ) -> Result<InterestRateQuote, LendingError> {
        let market = self.load_market(market_id).await?;
        let available_liquidity = self
            .db
            .balance(&market.reserve_account, &market.borrow_coin)
            .await?;
        market.interest_rate_quote_from_isfr(snapshot, available_liquidity)
    }

    pub async fn interest_rate_quote<P: IsfrRateProvider + Sync>(
        &self,
        market_id: MarketId,
        provider: &P,
    ) -> Result<InterestRateQuote, LendingError> {
        let snapshot = provider.current_snapshot().await?;
        self.interest_rate_quote_from_isfr(market_id, &snapshot)
            .await
    }

    pub async fn create_market(
        &mut self,
        collateral_coin: CoinId,
        borrow_coin: CoinId,
        collateral_factor_bps: u16,
        interest_rate_model: InterestRateModel,
    ) -> Result<MarketState, LendingError> {
        let market = MarketState::new(
            collateral_coin,
            borrow_coin,
            collateral_factor_bps,
            interest_rate_model,
        )?;
        self.ensure_coin(market.collateral_coin).await?;
        self.ensure_coin(market.borrow_coin).await?;
        if self.db.market(market.id).await?.is_some() {
            return Err(LendingError::DuplicateMarket(market.id));
        }
        self.db.set_market(&market);
        Ok(market)
    }

    pub async fn supply_collateral(
        &mut self,
        market_id: MarketId,
        account: &Address,
        amount: u128,
    ) -> Result<PositionUpdate, LendingError> {
        ensure_positive(amount)?;
        let mut market = self.load_market(market_id).await?;
        let mut position = self.db.position(market.id, account).await?;

        self.transfer_balance(
            account,
            &market.reserve_account,
            market.collateral_coin,
            amount,
        )
        .await?;

        position.collateral = checked_add(position.collateral, amount)?;
        market.total_collateral = checked_add(market.total_collateral, amount)?;
        self.db.set_position(market.id, account, &position);
        self.db.set_market(&market);
        Ok(position_update(market.id, account, &position))
    }

    pub async fn withdraw_collateral(
        &mut self,
        market_id: MarketId,
        account: &Address,
        amount: u128,
    ) -> Result<PositionUpdate, LendingError> {
        ensure_positive(amount)?;
        let mut market = self.load_market(market_id).await?;
        let mut position = self.db.position(market.id, account).await?;
        if position.collateral < amount {
            return Err(LendingError::InsufficientCollateral {
                available: position.collateral,
                required: amount,
            });
        }

        let updated_collateral = position.collateral - amount;
        ensure_healthy(
            updated_collateral,
            position.debt,
            market.collateral_factor_bps,
        )?;

        self.transfer_balance(
            &market.reserve_account,
            account,
            market.collateral_coin,
            amount,
        )
        .await?;

        position.collateral = updated_collateral;
        market.total_collateral -= amount;
        self.db.set_position(market.id, account, &position);
        self.db.set_market(&market);
        Ok(position_update(market.id, account, &position))
    }

    pub async fn borrow(
        &mut self,
        market_id: MarketId,
        account: &Address,
        amount: u128,
    ) -> Result<PositionUpdate, LendingError> {
        ensure_positive(amount)?;
        let mut market = self.load_market(market_id).await?;
        let mut position = self.db.position(market.id, account).await?;
        let updated_debt = checked_add(position.debt, amount)?;
        ensure_healthy(
            position.collateral,
            updated_debt,
            market.collateral_factor_bps,
        )?;

        let liquidity = self
            .db
            .balance(&market.reserve_account, &market.borrow_coin)
            .await?;
        if liquidity < amount {
            return Err(LendingError::InsufficientLiquidity {
                available: liquidity,
                required: amount,
            });
        }

        self.transfer_balance(&market.reserve_account, account, market.borrow_coin, amount)
            .await?;

        position.debt = updated_debt;
        market.total_borrowed = checked_add(market.total_borrowed, amount)?;
        self.db.set_position(market.id, account, &position);
        self.db.set_market(&market);
        Ok(position_update(market.id, account, &position))
    }

    pub async fn repay(
        &mut self,
        market_id: MarketId,
        account: &Address,
        amount: u128,
    ) -> Result<PositionUpdate, LendingError> {
        ensure_positive(amount)?;
        let mut market = self.load_market(market_id).await?;
        let mut position = self.db.position(market.id, account).await?;
        if position.debt < amount {
            return Err(LendingError::InsufficientDebt {
                outstanding: position.debt,
                attempted: amount,
            });
        }

        self.transfer_balance(account, &market.reserve_account, market.borrow_coin, amount)
            .await?;

        position.debt -= amount;
        market.total_borrowed -= amount;
        self.db.set_position(market.id, account, &position);
        self.db.set_market(&market);
        Ok(position_update(market.id, account, &position))
    }

    async fn load_market(&self, market_id: MarketId) -> Result<MarketState, LendingError> {
        self.db
            .market(market_id)
            .await?
            .ok_or(LendingError::UnknownMarket(market_id))
    }

    async fn ensure_coin(&self, coin: CoinId) -> Result<(), LendingError> {
        if self.db.token(&coin).await?.is_none() {
            return Err(LendingError::UnknownCoin(coin));
        }
        Ok(())
    }

    async fn transfer_balance(
        &mut self,
        from: &Address,
        to: &Address,
        coin: CoinId,
        amount: u128,
    ) -> Result<(), LendingError> {
        ensure_positive(amount)?;
        self.ensure_coin(coin).await?;
        let from_balance = self.db.balance(from, &coin).await?;
        ensure_balance(from, coin, from_balance, amount)?;
        let to_balance = self.db.balance(to, &coin).await?;
        self.db.set_balance(from, &coin, from_balance - amount);
        self.db
            .set_balance(to, &coin, checked_add(to_balance, amount)?);
        Ok(())
    }
}

fn position_update(market_id: MarketId, account: &Address, position: &Position) -> PositionUpdate {
    PositionUpdate {
        market_id,
        account: account.clone(),
        collateral: position.collateral,
        debt: position.debt,
    }
}

fn ensure_healthy(
    collateral: u128,
    debt: u128,
    collateral_factor_bps: u16,
) -> Result<(), LendingError> {
    let max_debt = checked_mul(collateral, u128::from(collateral_factor_bps))? / BPS_DENOMINATOR;
    if debt > max_debt {
        return Err(LendingError::Undercollateralized {
            max_debt,
            attempted_debt: debt,
        });
    }
    Ok(())
}

fn ensure_positive(amount: u128) -> Result<(), LendingError> {
    if amount == 0 {
        Err(LendingError::InvalidAmount)
    } else {
        Ok(())
    }
}

fn checked_add(left: u128, right: u128) -> Result<u128, LendingError> {
    left.checked_add(right).ok_or(LendingError::AmountOverflow)
}

fn checked_mul(left: u128, right: u128) -> Result<u128, LendingError> {
    left.checked_mul(right).ok_or(LendingError::AmountOverflow)
}

fn utilization_bps(total_borrowed: u128, available_liquidity: u128) -> Result<u16, LendingError> {
    if total_borrowed == 0 {
        return Ok(0);
    }
    let total_liquidity = checked_add(total_borrowed, available_liquidity)?;
    let scaled = checked_mul(total_borrowed, BPS_DENOMINATOR)? / total_liquidity;
    u16::try_from(scaled).map_err(|_| LendingError::AmountOverflow)
}

fn checked_rate_add(left: i64, right: i64) -> Result<i64, LendingError> {
    left.checked_add(right).ok_or(LendingError::RateOverflow)
}

fn checked_rate_mul_div(
    rate_bps: i64,
    numerator: u128,
    denominator: u128,
) -> Result<i64, LendingError> {
    if denominator == 0 {
        return Err(LendingError::RateOverflow);
    }
    let scaled = i128::from(rate_bps)
        .checked_mul(i128::try_from(numerator).map_err(|_| LendingError::RateOverflow)?)
        .ok_or(LendingError::RateOverflow)?
        / i128::try_from(denominator).map_err(|_| LendingError::RateOverflow)?;
    i64::try_from(scaled).map_err(|_| LendingError::RateOverflow)
}

fn ensure_balance(
    account: &Address,
    coin: CoinId,
    available: u128,
    required: u128,
) -> Result<(), LendingError> {
    if available < required {
        return Err(LendingError::InsufficientBalance {
            account: Box::new(account.clone()),
            coin: Box::new(coin),
            available,
            required,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner as _};
    use nunchi_coins::{
        external_account_id, CoinOperation, CoinSpec, Ledger, PrivateKey, TokenName, TokenSymbol,
        Transaction as CoinTransaction,
    };
    use nunchi_common::QmdbState;

    fn address(key: &PrivateKey) -> Address {
        external_account_id(&key.public_key())
    }

    fn spec(symbol: &str, name: &str, supply: u128) -> CoinSpec {
        CoinSpec::new(
            TokenSymbol::new(symbol).expect("valid symbol"),
            TokenName::new(name).expect("valid name"),
            6,
            supply,
            None,
        )
    }

    fn isfr_rate_model() -> InterestRateModel {
        InterestRateModel::isfr_aave_style(8_000, 0, 400, 6_000, 1_000).expect("valid rate model")
    }

    fn isfr_snapshot(lending_bps: i64) -> IsfrSnapshot {
        IsfrSnapshot {
            epoch: 42,
            timestamp: Some(1_719_000_000),
            lending_bps: Some(lending_bps),
            composite_bps: Some(lending_bps),
            confidence_bps: Some(9_500),
            source: Some("ISFROracle.currentRate".to_string()),
        }
    }

    async fn seeded_state(
        context: deterministic::Context,
    ) -> (
        QmdbState<deterministic::Context>,
        PrivateKey,
        PrivateKey,
        Address,
        Address,
        CoinId,
        CoinId,
        MarketId,
    ) {
        let mut state = QmdbState::init(context, "lending-test")
            .await
            .expect("init state");
        let lender_key = PrivateKey::ed25519_from_seed(1);
        let borrower_key = PrivateKey::ed25519_from_seed(2);
        let lender = address(&lender_key);
        let borrower = address(&borrower_key);

        let (collateral_coin, borrow_coin) = {
            let mut ledger = Ledger::new(&mut state);
            let collateral_coin = ledger
                .create_token(borrower.clone(), spec("COL", "Collateral", 1_000))
                .await
                .expect("create collateral");
            let borrow_coin = ledger
                .create_token(lender.clone(), spec("DEBT", "Debt Asset", 1_000))
                .await
                .expect("create debt asset");
            (collateral_coin, borrow_coin)
        };

        let market_id = market_id(collateral_coin, borrow_coin);
        let reserve = reserve_account(market_id);
        {
            let mut ledger = Ledger::new(&mut state);
            let fund_market = CoinTransaction::sign(
                &lender_key,
                0,
                CoinOperation::Transfer {
                    coin: borrow_coin,
                    from: lender.clone(),
                    to: reserve,
                    amount: 500,
                },
            );
            ledger
                .apply_transaction(&fund_market)
                .await
                .expect("fund market liquidity");
        }

        (
            state,
            lender_key,
            borrower_key,
            lender,
            borrower,
            collateral_coin,
            borrow_coin,
            market_id,
        )
    }

    #[test]
    fn signed_lending_lifecycle_tracks_balances_and_position() {
        deterministic::Runner::default().start(|context| async move {
            let (
                mut state,
                lender_key,
                borrower_key,
                lender,
                borrower,
                collateral_coin,
                borrow_coin,
                market_id,
            ) = seeded_state(context).await;

            for tx in [
                Transaction::sign(
                    &lender_key,
                    1,
                    LendingOperation::CreateMarket {
                        collateral_coin,
                        borrow_coin,
                        collateral_factor_bps: 5_000,
                        interest_rate_model: isfr_rate_model(),
                    },
                ),
                Transaction::sign(
                    &borrower_key,
                    0,
                    LendingOperation::SupplyCollateral {
                        market_id,
                        amount: 200,
                    },
                ),
                Transaction::sign(
                    &borrower_key,
                    1,
                    LendingOperation::Borrow {
                        market_id,
                        amount: 75,
                    },
                ),
                Transaction::sign(
                    &borrower_key,
                    2,
                    LendingOperation::Repay {
                        market_id,
                        amount: 25,
                    },
                ),
                Transaction::sign(
                    &borrower_key,
                    3,
                    LendingOperation::WithdrawCollateral {
                        market_id,
                        amount: 100,
                    },
                ),
            ] {
                let mut lending = LendingLedger::new(&mut state);
                lending
                    .apply_transaction(&tx)
                    .await
                    .expect("apply lending tx");
            }

            let lending = LendingLedger::new(&mut state);
            let market = lending.market(market_id).await.unwrap().expect("market");
            let position = lending.position(market_id, &borrower).await.unwrap();
            assert_eq!(
                lending
                    .interest_rate_quote_from_isfr(market_id, &isfr_snapshot(450))
                    .await
                    .unwrap(),
                InterestRateQuote {
                    benchmark: RateBenchmark::Isfr,
                    benchmark_epoch: 42,
                    benchmark_timestamp: Some(1_719_000_000),
                    benchmark_rate_bps: 450,
                    available_liquidity: 450,
                    total_borrowed: 50,
                    utilization_bps: 1_000,
                    protocol_rate_bps: 50,
                    borrow_rate_bps: 500,
                    supply_rate_bps: 45,
                }
            );
            assert_eq!(market.total_collateral, 100);
            assert_eq!(market.total_borrowed, 50);
            assert_eq!(
                position,
                Position {
                    collateral: 100,
                    debt: 50,
                }
            );
            drop(lending);

            let ledger = Ledger::new(&mut state);
            assert_eq!(
                ledger.balance(&borrower, &collateral_coin).await.unwrap(),
                900
            );
            assert_eq!(ledger.balance(&borrower, &borrow_coin).await.unwrap(), 50);
            assert_eq!(
                ledger
                    .balance(&market.reserve_account, &collateral_coin)
                    .await
                    .unwrap(),
                100
            );
            assert_eq!(
                ledger
                    .balance(&market.reserve_account, &borrow_coin)
                    .await
                    .unwrap(),
                450
            );
            assert_eq!(ledger.nonce(&lender).await.unwrap(), 2);
            assert_eq!(ledger.nonce(&borrower).await.unwrap(), 4);
        });
    }

    #[test]
    fn rejects_borrow_above_collateral_factor() {
        deterministic::Runner::default().start(|context| async move {
            let (
                mut state,
                _lender_key,
                _borrower_key,
                _lender,
                borrower,
                collateral_coin,
                borrow_coin,
                market_id,
            ) = seeded_state(context).await;
            {
                let mut lending = LendingLedger::new(&mut state);
                lending
                    .create_market(collateral_coin, borrow_coin, 5_000, isfr_rate_model())
                    .await
                    .expect("create market");
                lending
                    .supply_collateral(market_id, &borrower, 100)
                    .await
                    .expect("supply collateral");
            }

            let err = {
                let mut lending = LendingLedger::new(&mut state);
                lending.borrow(market_id, &borrower, 51).await.unwrap_err()
            };
            assert_eq!(
                err,
                LendingError::Undercollateralized {
                    max_debt: 50,
                    attempted_debt: 51,
                }
            );

            let lending = LendingLedger::new(&mut state);
            assert_eq!(
                lending.position(market_id, &borrower).await.unwrap(),
                Position {
                    collateral: 100,
                    debt: 0,
                }
            );
        });
    }

    #[test]
    fn rejects_withdrawal_that_would_make_position_unhealthy() {
        deterministic::Runner::default().start(|context| async move {
            let (
                mut state,
                _lender_key,
                _borrower_key,
                _lender,
                borrower,
                collateral_coin,
                borrow_coin,
                market_id,
            ) = seeded_state(context).await;
            {
                let mut lending = LendingLedger::new(&mut state);
                lending
                    .create_market(collateral_coin, borrow_coin, 5_000, isfr_rate_model())
                    .await
                    .expect("create market");
                lending
                    .supply_collateral(market_id, &borrower, 200)
                    .await
                    .expect("supply collateral");
                lending
                    .borrow(market_id, &borrower, 75)
                    .await
                    .expect("borrow");
            }

            let err = {
                let mut lending = LendingLedger::new(&mut state);
                lending
                    .withdraw_collateral(market_id, &borrower, 100)
                    .await
                    .unwrap_err()
            };
            assert_eq!(
                err,
                LendingError::Undercollateralized {
                    max_debt: 50,
                    attempted_debt: 75,
                }
            );

            let lending = LendingLedger::new(&mut state);
            assert_eq!(
                lending.position(market_id, &borrower).await.unwrap(),
                Position {
                    collateral: 200,
                    debt: 75,
                }
            );
        });
    }

    #[test]
    fn rejects_repaying_more_than_outstanding_debt() {
        deterministic::Runner::default().start(|context| async move {
            let (
                mut state,
                _lender_key,
                _borrower_key,
                _lender,
                borrower,
                collateral_coin,
                borrow_coin,
                market_id,
            ) = seeded_state(context).await;
            {
                let mut lending = LendingLedger::new(&mut state);
                lending
                    .create_market(collateral_coin, borrow_coin, 5_000, isfr_rate_model())
                    .await
                    .expect("create market");
                lending
                    .supply_collateral(market_id, &borrower, 200)
                    .await
                    .expect("supply collateral");
                lending
                    .borrow(market_id, &borrower, 75)
                    .await
                    .expect("borrow");
            }

            let err = {
                let mut lending = LendingLedger::new(&mut state);
                lending.repay(market_id, &borrower, 76).await.unwrap_err()
            };
            assert_eq!(
                err,
                LendingError::InsufficientDebt {
                    outstanding: 75,
                    attempted: 76,
                }
            );
        });
    }
}
