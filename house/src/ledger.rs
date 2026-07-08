use crate::{
    HouseDB, HouseOperation, Mode, NetInventory, Transaction, Vault, VaultId, VaultPolicy,
    BPS_DENOMINATOR, MAX_ALLOWED_MARKETS, MAX_SUBMITTERS_PER_VAULT, MAX_VAULTS,
    MAX_VAULT_MARKETS,
};
use nunchi_clob::{MarketId, Side};
use nunchi_common::{Address, RuntimeContext};
use nunchi_crypto::SignatureError;
use thiserror::Error;

/// Deterministic house state-machine errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HouseError {
    #[error("bad house transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("vault already exists")]
    VaultAlreadyExists,
    #[error("vault not found")]
    VaultNotFound,
    #[error("vault index is full")]
    VaultIndexFull,
    #[error("vault submitter set is full")]
    SubmitterIndexFull,
    #[error("vault inventory index is full")]
    InventoryIndexFull,
    #[error("signer does not own the vault")]
    NotVaultOwner,
    #[error("invalid policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("invalid amount: {0}")]
    InvalidAmount(&'static str),
    #[error("insufficient vault balance")]
    InsufficientBalance,
    #[error("vault balance overflow")]
    BalanceOverflow,
    #[error("net inventory overflow")]
    InventoryOverflow,
    #[error("clearing reservation underflow")]
    ReservationUnderflow,
    #[error("clearing reservation overflow")]
    ReservationOverflow,
    #[error("vault is halted")]
    VaultHalted,
    #[error("vault is not live")]
    VaultNotLive,
    #[error("vault mode forbids exposure increase")]
    ModeForbidsIncrease,
    #[error("market not allowed by vault policy")]
    MarketNotAllowed,
    #[error("net inventory cap exceeded")]
    NetInventoryExceeded,
    #[error("market allocation cap exceeded")]
    AllocationExceeded,
    #[error("house leverage ceiling exceeded")]
    LeverageExceeded,
    #[error("exposure valuation overflow")]
    ExposureOverflow,
    #[error("vault has open inventory")]
    VaultNotFlat,
    #[error("state storage error: {0}")]
    Storage(String),
}

/// Deterministic state machine for house vault capital and policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HouseLedger<D> {
    pub(crate) db: D,
}

impl<D: HouseDB> HouseLedger<D> {
    /// Wrap a database backend as a house ledger.
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

    pub async fn nonce(&self, account: &Address) -> Result<u64, HouseError> {
        self.db.nonce(account).await
    }

    pub async fn vault(&self, id: &VaultId) -> Result<Option<Vault>, HouseError> {
        self.db.vault(id).await
    }

    pub async fn vaults(&self) -> Result<Vec<Vault>, HouseError> {
        let ids = self.db.vault_index().await?;
        let mut vaults = Vec::with_capacity(ids.len());
        for id in ids {
            vaults.push(self.db.vault(&id).await?.ok_or(HouseError::VaultNotFound)?);
        }
        Ok(vaults)
    }

    pub async fn submitters(&self, vault: &VaultId) -> Result<Vec<Address>, HouseError> {
        self.db.submitters(vault).await
    }

    pub async fn inventory(
        &self,
        vault: &VaultId,
        market: &MarketId,
    ) -> Result<NetInventory, HouseError> {
        self.db.inventory(vault, market).await
    }

    pub async fn inventory_index(&self, vault: &VaultId) -> Result<Vec<MarketId>, HouseError> {
        self.db.inventory_index(vault).await
    }

    pub async fn reserved(&self, vault: &VaultId, market: &MarketId) -> Result<u128, HouseError> {
        self.db.reserved(vault, market).await
    }

    /// Validate and apply a signed house transaction.
    pub async fn apply_transaction(
        &mut self,
        tx: &Transaction,
        context: RuntimeContext,
    ) -> Result<(), HouseError> {
        tx.verify()?;

        let expected = self.db.nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(HouseError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        self.apply_operation(tx, context).await?;
        let next_nonce = expected.checked_add(1).ok_or(HouseError::NonceOverflow)?;
        self.db.set_nonce(&tx.account_id, next_nonce);
        Ok(())
    }

    async fn apply_operation(
        &mut self,
        tx: &Transaction,
        context: RuntimeContext,
    ) -> Result<(), HouseError> {
        match &tx.payload.operation {
            HouseOperation::CreateVault { policy } => {
                self.create_vault(&tx.account_id, VaultId(tx.digest()), policy.clone(), context)
                    .await
            }
            HouseOperation::Deposit { vault, amount } => {
                self.deposit(&tx.account_id, vault, *amount).await
            }
            HouseOperation::Withdraw { vault, amount } => {
                self.withdraw(&tx.account_id, vault, *amount).await
            }
            HouseOperation::SetVaultPolicy { vault, policy } => {
                self.set_policy(&tx.account_id, vault, policy.clone()).await
            }
            HouseOperation::SetAuthorizedSubmitter {
                vault,
                submitter,
                enabled,
            } => {
                self.set_submitter(&tx.account_id, vault, submitter, *enabled)
                    .await
            }
            HouseOperation::SetVaultMode { vault, mode } => {
                self.set_mode(&tx.account_id, vault, *mode).await
            }
        }
    }

    async fn create_vault(
        &mut self,
        owner: &Address,
        id: VaultId,
        policy: VaultPolicy,
        context: RuntimeContext,
    ) -> Result<(), HouseError> {
        validate_policy(&policy)?;
        if self.db.vault(&id).await?.is_some() {
            return Err(HouseError::VaultAlreadyExists);
        }

        let mut vaults = self.db.vault_index().await?;
        if vaults.len() == MAX_VAULTS {
            return Err(HouseError::VaultIndexFull);
        }

        let vault = Vault {
            id,
            owner: owner.clone(),
            quote_balance: 0,
            policy,
            mode: Mode::Live,
            created_at_height: context.height,
            created_at_ms: context.timestamp_ms,
        };
        self.db.set_vault(&vault);
        vaults.push(id);
        self.db.set_vault_index(&vaults);
        Ok(())
    }

    async fn owned_vault(&self, signer: &Address, id: &VaultId) -> Result<Vault, HouseError> {
        let vault = self.db.vault(id).await?.ok_or(HouseError::VaultNotFound)?;
        if vault.owner != *signer {
            return Err(HouseError::NotVaultOwner);
        }
        Ok(vault)
    }

    async fn deposit(
        &mut self,
        signer: &Address,
        id: &VaultId,
        amount: u128,
    ) -> Result<(), HouseError> {
        if amount == 0 {
            return Err(HouseError::InvalidAmount("deposit must be non-zero"));
        }
        let mut vault = self.owned_vault(signer, id).await?;
        vault.quote_balance = vault
            .quote_balance
            .checked_add(amount)
            .ok_or(HouseError::BalanceOverflow)?;
        self.db.set_vault(&vault);
        Ok(())
    }

    /// Withdrawals require a live vault with a flat book across all markets.
    ///
    /// Partial withdrawal against margin coverage needs an oracle valuation and
    /// arrives with chain-level oracle wiring.
    async fn withdraw(
        &mut self,
        signer: &Address,
        id: &VaultId,
        amount: u128,
    ) -> Result<(), HouseError> {
        if amount == 0 {
            return Err(HouseError::InvalidAmount("withdrawal must be non-zero"));
        }
        let mut vault = self.owned_vault(signer, id).await?;
        if vault.mode != Mode::Live {
            return Err(HouseError::VaultNotLive);
        }
        if !self.db.inventory_index(id).await?.is_empty() {
            return Err(HouseError::VaultNotFlat);
        }
        if vault.quote_balance < amount {
            return Err(HouseError::InsufficientBalance);
        }
        vault.quote_balance -= amount;
        self.db.set_vault(&vault);
        Ok(())
    }

    async fn set_policy(
        &mut self,
        signer: &Address,
        id: &VaultId,
        policy: VaultPolicy,
    ) -> Result<(), HouseError> {
        validate_policy(&policy)?;
        let mut vault = self.owned_vault(signer, id).await?;
        vault.policy = policy;
        self.db.set_vault(&vault);
        Ok(())
    }

    async fn set_submitter(
        &mut self,
        signer: &Address,
        id: &VaultId,
        submitter: &Address,
        enabled: bool,
    ) -> Result<(), HouseError> {
        self.owned_vault(signer, id).await?;
        let mut submitters = self.db.submitters(id).await?;
        let present = submitters.contains(submitter);
        if enabled && !present {
            if submitters.len() == MAX_SUBMITTERS_PER_VAULT {
                return Err(HouseError::SubmitterIndexFull);
            }
            submitters.push(submitter.clone());
            self.db.set_submitters(id, &submitters);
        } else if !enabled && present {
            submitters.retain(|address| address != submitter);
            self.db.set_submitters(id, &submitters);
        }
        Ok(())
    }

    async fn set_mode(
        &mut self,
        signer: &Address,
        id: &VaultId,
        mode: Mode,
    ) -> Result<(), HouseError> {
        let mut vault = self.owned_vault(signer, id).await?;
        vault.mode = mode;
        self.db.set_vault(&vault);
        Ok(())
    }
}

pub(crate) fn validate_policy(policy: &VaultPolicy) -> Result<(), HouseError> {
    if policy.allowed_markets.len() > MAX_ALLOWED_MARKETS {
        return Err(HouseError::InvalidPolicy("too many allowed markets"));
    }
    for (idx, market) in policy.allowed_markets.iter().enumerate() {
        if policy.allowed_markets[..idx].contains(market) {
            return Err(HouseError::InvalidPolicy("duplicate allowed market"));
        }
    }
    Ok(())
}

/// Whether `submitter` may manage the vault's clearing liquidity.
///
/// The vault owner is always authorized.
pub async fn authorized_submitter<D: HouseDB>(
    db: &D,
    vault: &VaultId,
    submitter: &Address,
) -> Result<bool, HouseError> {
    let vault_state = db.vault(vault).await?.ok_or(HouseError::VaultNotFound)?;
    if vault_state.owner == *submitter {
        return Ok(true);
    }
    Ok(db.submitters(vault).await?.contains(submitter))
}

/// Move free quote balance into a per-market clearing reservation.
///
/// Reservations back the worst-case cost of pending buy intents so a vault can
/// never distort a batch price with intents it cannot settle.
pub async fn reserve_clearing_quote<D: HouseDB>(
    db: &mut D,
    vault: &VaultId,
    market: &MarketId,
    amount: u128,
) -> Result<(), HouseError> {
    if amount == 0 {
        return Err(HouseError::InvalidAmount("reservation must be non-zero"));
    }
    let mut vault_state = db.vault(vault).await?.ok_or(HouseError::VaultNotFound)?;
    if !vault_state.mode.allows_activity() {
        return Err(HouseError::VaultHalted);
    }
    if !vault_state.policy.allows_market(market) {
        return Err(HouseError::MarketNotAllowed);
    }
    let reserved = db.reserved(vault, market).await?;
    let next_reserved = reserved
        .checked_add(amount)
        .ok_or(HouseError::ReservationOverflow)?;
    if next_reserved > vault_state.policy.max_market_allocation {
        return Err(HouseError::AllocationExceeded);
    }
    if vault_state.quote_balance < amount {
        return Err(HouseError::InsufficientBalance);
    }
    vault_state.quote_balance -= amount;
    db.set_vault(&vault_state);
    db.set_reserved(vault, market, next_reserved);
    Ok(())
}

/// Return reserved quote to the vault's free balance.
pub async fn release_clearing_quote<D: HouseDB>(
    db: &mut D,
    vault: &VaultId,
    market: &MarketId,
    amount: u128,
) -> Result<(), HouseError> {
    if amount == 0 {
        return Ok(());
    }
    let mut vault_state = db.vault(vault).await?.ok_or(HouseError::VaultNotFound)?;
    let reserved = db.reserved(vault, market).await?;
    if reserved < amount {
        return Err(HouseError::ReservationUnderflow);
    }
    vault_state.quote_balance = vault_state
        .quote_balance
        .checked_add(amount)
        .ok_or(HouseError::BalanceOverflow)?;
    db.set_vault(&vault_state);
    db.set_reserved(vault, market, reserved - amount);
    Ok(())
}

/// Validate one clearing fill against vault policy without touching state.
///
/// Returns the post-fill net inventory and free quote balance. Exposure caps
/// (allowed market, net inventory, leverage ceiling) bind only when the fill
/// increases absolute exposure, so a vault can always trade back toward flat.
/// For a `Bid` fill, `reservation_release` is the reserved quote consumed by
/// the fill and must cover the fill cost.
#[allow(clippy::too_many_arguments)]
pub fn validate_clearing_fill(
    vault: &Vault,
    market: &MarketId,
    current: NetInventory,
    side: Side,
    base: u128,
    quote: u128,
    reservation_release: u128,
    oracle_price: u128,
) -> Result<(NetInventory, u128), HouseError> {
    if base == 0 {
        return Err(HouseError::InvalidAmount("fill base must be non-zero"));
    }
    if !vault.mode.allows_activity() {
        return Err(HouseError::VaultHalted);
    }

    let next = current
        .apply(side, base)
        .ok_or(HouseError::InventoryOverflow)?;
    let balance_after = match side {
        Side::Bid => {
            if reservation_release < quote {
                return Err(HouseError::InvalidAmount(
                    "reservation release below fill cost",
                ));
            }
            vault
                .quote_balance
                .checked_add(reservation_release - quote)
                .ok_or(HouseError::BalanceOverflow)?
        }
        Side::Ask => vault
            .quote_balance
            .checked_add(quote)
            .ok_or(HouseError::BalanceOverflow)?,
    };

    let increases = next.magnitude() > current.magnitude();
    if increases {
        if !vault.mode.allows_increase() {
            return Err(HouseError::ModeForbidsIncrease);
        }
        if !vault.policy.allows_market(market) {
            return Err(HouseError::MarketNotAllowed);
        }
        if next.magnitude() > vault.policy.max_net_inventory {
            return Err(HouseError::NetInventoryExceeded);
        }
        let exposure = next
            .magnitude()
            .checked_mul(oracle_price)
            .ok_or(HouseError::ExposureOverflow)?;
        let scaled_exposure = exposure
            .checked_mul(BPS_DENOMINATOR)
            .ok_or(HouseError::ExposureOverflow)?;
        let leverage_room = balance_after
            .checked_mul(vault.policy.max_leverage_bps as u128)
            .ok_or(HouseError::ExposureOverflow)?;
        if scaled_exposure > leverage_room {
            return Err(HouseError::LeverageExceeded);
        }
    }

    Ok((next, balance_after))
}

/// Apply one validated clearing fill to vault state.
///
/// This is the settlement entry point for the cooperative batch clearing
/// module. All checks from [`validate_clearing_fill`] are re-run against
/// persisted state before any mutation.
#[allow(clippy::too_many_arguments)]
pub async fn settle_clearing_fill<D: HouseDB>(
    db: &mut D,
    vault: &VaultId,
    market: &MarketId,
    side: Side,
    base: u128,
    quote: u128,
    reservation_release: u128,
    oracle_price: u128,
) -> Result<NetInventory, HouseError> {
    let mut vault_state = db.vault(vault).await?.ok_or(HouseError::VaultNotFound)?;
    let current = db.inventory(vault, market).await?;
    let reserved = db.reserved(vault, market).await?;
    if side == Side::Bid && reserved < reservation_release {
        return Err(HouseError::ReservationUnderflow);
    }

    let (next, balance_after) = validate_clearing_fill(
        &vault_state,
        market,
        current,
        side,
        base,
        quote,
        reservation_release,
        oracle_price,
    )?;

    let mut index = db.inventory_index(vault).await?;
    let present = index.contains(market);
    let inserts = !next.is_flat() && !present;
    if inserts && index.len() == MAX_VAULT_MARKETS {
        return Err(HouseError::InventoryIndexFull);
    }

    if side == Side::Bid {
        db.set_reserved(vault, market, reserved - reservation_release);
    }
    vault_state.quote_balance = balance_after;
    db.set_vault(&vault_state);
    db.set_inventory(vault, market, next);
    if next.is_flat() && present {
        index.retain(|entry| entry != market);
        db.set_inventory_index(vault, &index);
    } else if inserts {
        index.push(*market);
        db.set_inventory_index(vault, &index);
    }
    Ok(next)
}
