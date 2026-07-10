use super::{
    multisig_account_id, Account, AccountPolicy, AccountType, Address, Authorization, CoinId,
    CoinOperation, FeeConfig, TokenDefinition, TokenFactory, Transaction,
};
use crate::db::CoinDB;
use crate::events::{
    account_policy_registered_event, burned_event, fee_charged_event, minted_event,
    token_created_event, transferred_event, AccountPolicyRegistered, Burned, FeeCharged, Minted,
    TokenCreated, Transferred,
};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{CommitState, Event, EventSink};
use nunchi_crypto::SignatureError;
use thiserror::Error;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum LedgerError {
    #[error("bad transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("unknown account policy {0:?}")]
    UnknownAccountPolicy(Box<Address>),
    #[error("account policy mismatch for {0:?}")]
    AccountPolicyMismatch(Box<Address>),
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("invalid token spec: {0}")]
    InvalidTokenSpec(&'static str),
    #[error("invalid zero amount")]
    InvalidAmount,
    #[error("unknown token {0:?}")]
    UnknownToken(CoinId),
    #[error("token already exists {0:?}")]
    DuplicateToken(CoinId),
    #[error("unauthorized coin operation")]
    Unauthorized,
    #[error("invalid account policy: {0}")]
    InvalidAccountPolicy(#[from] super::AccountPolicyError),
    #[error("insufficient balance for {account:?} in {coin:?}: available {available}, required {required}")]
    InsufficientBalance {
        account: Box<Address>,
        coin: Box<CoinId>,
        available: u128,
        required: u128,
    },
    #[error("balance overflow")]
    BalanceOverflow,
    #[error("fee overflow")]
    FeeOverflow,
    #[error("supply overflow")]
    SupplyOverflow,
    #[error("allocation sum mismatch: expected {expected}, got {actual}")]
    AllocationSumMismatch { expected: u128, actual: u128 },
    #[error("max supply exceeded: max {max}, attempted {attempted}")]
    MaxSupplyExceeded { max: u128, attempted: u128 },
    #[error("invalid coins genesis: {0}")]
    InvalidGenesis(String),
    #[error("state storage error: {0}")]
    Storage(String),
}

/// Deterministic state machine for accounts and tokens over a [`CoinDB`] backend.
///
/// State lives in the shared, authenticated database; [`Ledger::root`] commits to it succinctly.
/// Operations stage writes that become durable on [`Ledger::commit`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ledger<D> {
    db: D,
}

impl<D: CoinDB> Ledger<D> {
    /// Wrap a database backend as a coin ledger.
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

    pub async fn account(&self, id: &Address) -> Result<Account, LedgerError> {
        let kind = if self.db.account_policy(id).await?.is_some() {
            AccountType::Multisig
        } else {
            AccountType::External
        };
        Ok(Account::new(id.clone(), kind, self.db.nonce(id).await?))
    }

    pub async fn nonce(&self, id: &Address) -> Result<u64, LedgerError> {
        self.db.nonce(id).await
    }

    pub async fn factory_nonce(&self) -> Result<u64, LedgerError> {
        self.db.factory_nonce().await
    }

    pub async fn token(&self, coin: &CoinId) -> Result<Option<TokenDefinition>, LedgerError> {
        self.db.token(coin).await
    }

    pub async fn balance(&self, account: &Address, coin: &CoinId) -> Result<u128, LedgerError> {
        self.db.balance(account, coin).await
    }

    /// The chain's fee configuration (`None` if the chain charges no fees).
    pub async fn fee_config(&self) -> Result<Option<FeeConfig>, LedgerError> {
        self.db.fee_config().await
    }

    /// Stage the chain's fee configuration.
    pub fn set_fee_config(&mut self, config: &FeeConfig) {
        self.db.set_fee_config(config);
    }

    /// Charge the deterministic fee for a transaction of `encoded_size` canonical bytes to
    /// `payer`, crediting the configured collector. A no-op when no [`FeeConfig`] is stored.
    ///
    /// Callers stage this alongside the rest of the transaction's writes so a failed
    /// transaction reverts its fee.
    pub async fn charge_fee<Events>(
        &mut self,
        payer: &Address,
        encoded_size: usize,
        mut events: Events,
    ) -> Result<(), LedgerError>
    where
        Events: EventSink + Send,
    {
        let Some(config) = self.db.fee_config().await? else {
            return Ok(());
        };
        let amount = config.quote(encoded_size)?;
        if amount == 0 {
            return Ok(());
        }
        self.debit(payer, config.coin, amount).await?;
        self.credit(&config.collector, config.coin, amount).await?;
        events.emit(fee_charged_event(FeeCharged {
            coin: config.coin,
            payer: payer.clone(),
            collector: config.collector,
            amount,
        }));
        Ok(())
    }

    /// Move `amount` of `coin` from `from` to `to`, preserving total supply.
    ///
    /// This is an unauthenticated ledger primitive: it performs no signature or policy check, so
    /// the caller is responsible for authorization. It exists for chain-level integrations (such as
    /// moving a locked asset into bridge escrow) that authorize the movement through another
    /// module's signed transaction and stage it in the same overlay.
    pub async fn transfer(
        &mut self,
        from: &Address,
        to: &Address,
        coin: CoinId,
        amount: u128,
    ) -> Result<(), LedgerError> {
        self.debit(from, coin, amount).await?;
        self.credit(to, coin, amount).await?;
        Ok(())
    }

    /// Apply a transaction that has already passed stateless verification.
    ///
    /// This performs stateful account-policy and nonce checks, but deliberately
    /// does not repeat [`Transaction::verify`]. Chain callers verify transactions
    /// at mempool admission and again when verifying untrusted blocks.
    pub async fn apply_transaction<Events>(
        &mut self,
        tx: &Transaction,
        mut events: Events,
    ) -> Result<(), LedgerError>
    where
        Events: EventSink + Send,
    {
        self.ensure_authorized(tx).await?;

        let expected = self.db.nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(LedgerError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        let next_nonce = expected.checked_add(1).ok_or(LedgerError::NonceOverflow)?;
        let event = self
            .apply_operation(&tx.account_id, &tx.payload.operation)
            .await?;
        self.db.set_nonce(&tx.account_id, next_nonce);
        events.emit(event);
        Ok(())
    }

    /// Validate stateful account-policy authorization for a preverified transaction.
    pub async fn validate_authorization(&self, tx: &Transaction) -> Result<(), LedgerError> {
        self.ensure_authorized(tx).await
    }

    pub async fn register_account_policy(
        &mut self,
        account_id: Address,
        policy: AccountPolicy,
    ) -> Result<Address, LedgerError> {
        let expected = match &policy {
            AccountPolicy::Multisig(policy) => multisig_account_id(policy),
        };
        if account_id != expected {
            return Err(LedgerError::AccountPolicyMismatch(Box::new(account_id)));
        }
        if let Some(existing) = self.db.account_policy(&account_id).await? {
            if existing != policy {
                return Err(LedgerError::AccountPolicyMismatch(Box::new(account_id)));
            }
        }
        self.db.set_account_policy(&account_id, &policy);
        Ok(account_id)
    }

    pub async fn create_token(
        &mut self,
        issuer: Address,
        spec: super::CoinSpec,
    ) -> Result<CoinId, LedgerError> {
        let token = self.create_token_definition(issuer, spec).await?;
        Ok(token.id)
    }

    async fn create_token_definition(
        &mut self,
        issuer: Address,
        spec: super::CoinSpec,
    ) -> Result<TokenDefinition, LedgerError> {
        let mut factory = TokenFactory::with_nonce(self.db.factory_nonce().await?);
        let token = factory.create(issuer.clone(), spec)?;

        let id = token.id;
        if self.db.token(&id).await?.is_some() {
            return Err(LedgerError::DuplicateToken(id));
        }
        self.db.set_factory_nonce(factory.next_nonce());
        self.db.set_token(&token);
        if token.total_supply > 0 {
            self.credit(&issuer, id, token.total_supply).await?;
        }
        Ok(token)
    }

    /// Stateful authorization checks (account policy consistency).
    async fn ensure_authorized(&self, tx: &Transaction) -> Result<(), LedgerError> {
        match (&tx.authorization, &tx.payload.operation) {
            (
                Authorization::Multisig { policy, .. },
                CoinOperation::RegisterAccountPolicy {
                    account_id,
                    policy: registered,
                },
            ) => {
                if &tx.account_id != account_id
                    || policy != registered
                    || tx.account_id != multisig_account_id(registered)
                {
                    return Err(LedgerError::AccountPolicyMismatch(Box::new(
                        tx.account_id.clone(),
                    )));
                }
                match self.db.account_policy(&tx.account_id).await? {
                    Some(AccountPolicy::Multisig(existing)) if &existing == policy => {}
                    Some(_) => {
                        return Err(LedgerError::AccountPolicyMismatch(Box::new(
                            tx.account_id.clone(),
                        )));
                    }
                    None => {}
                }
            }
            (Authorization::Single { .. }, CoinOperation::RegisterAccountPolicy { .. }) => {
                return Err(LedgerError::Unauthorized);
            }
            (Authorization::Single { .. }, _) => {
                if self.db.account_policy(&tx.account_id).await?.is_some() {
                    return Err(LedgerError::AccountPolicyMismatch(Box::new(
                        tx.account_id.clone(),
                    )));
                }
            }
            (Authorization::Multisig { policy, .. }, _) => {
                match self.db.account_policy(&tx.account_id).await? {
                    Some(AccountPolicy::Multisig(registered)) if &registered == policy => {}
                    Some(_) => {
                        return Err(LedgerError::AccountPolicyMismatch(Box::new(
                            tx.account_id.clone(),
                        )));
                    }
                    None => {
                        return Err(LedgerError::UnknownAccountPolicy(Box::new(
                            tx.account_id.clone(),
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    async fn apply_operation(
        &mut self,
        signer: &Address,
        operation: &CoinOperation,
    ) -> Result<Event, LedgerError> {
        match operation {
            CoinOperation::RegisterAccountPolicy { account_id, policy } => {
                if signer != account_id {
                    return Err(LedgerError::Unauthorized);
                }
                self.register_account_policy(
                    account_id.clone(),
                    AccountPolicy::Multisig(policy.clone()),
                )
                .await?;
                Ok(account_policy_registered_event(AccountPolicyRegistered {
                    account_id: account_id.clone(),
                    policy: policy.clone(),
                }))
            }
            CoinOperation::CreateToken { spec } => {
                let token = self
                    .create_token_definition(signer.clone(), spec.clone())
                    .await?;
                Ok(token_created_event(TokenCreated { token }))
            }
            CoinOperation::Mint { coin, to, amount } => {
                ensure_positive(*amount)?;
                self.ensure_issuer(signer, coin).await?;
                let total_supply = self.increase_supply(*coin, *amount).await?;
                self.credit(to, *coin, *amount).await?;
                Ok(minted_event(Minted {
                    coin: *coin,
                    to: to.clone(),
                    amount: *amount,
                    total_supply,
                }))
            }
            CoinOperation::Burn { coin, from, amount } => {
                ensure_positive(*amount)?;
                if signer != from {
                    return Err(LedgerError::Unauthorized);
                }
                self.debit(from, *coin, *amount).await?;
                let total_supply = self.decrease_supply(*coin, *amount).await?;
                Ok(burned_event(Burned {
                    coin: *coin,
                    from: from.clone(),
                    amount: *amount,
                    total_supply,
                }))
            }
            CoinOperation::Transfer {
                coin,
                from,
                to,
                amount,
            } => {
                ensure_positive(*amount)?;
                if signer != from {
                    return Err(LedgerError::Unauthorized);
                }
                self.debit(from, *coin, *amount).await?;
                self.credit(to, *coin, *amount).await?;
                Ok(transferred_event(Transferred {
                    coin: *coin,
                    from: from.clone(),
                    to: to.clone(),
                    amount: *amount,
                }))
            }
        }
    }

    async fn ensure_issuer(&self, signer: &Address, coin: &CoinId) -> Result<(), LedgerError> {
        let token = self
            .db
            .token(coin)
            .await?
            .ok_or(LedgerError::UnknownToken(*coin))?;
        if &token.issuer == signer {
            Ok(())
        } else {
            Err(LedgerError::Unauthorized)
        }
    }

    async fn increase_supply(&mut self, coin: CoinId, amount: u128) -> Result<u128, LedgerError> {
        let mut token = self
            .db
            .token(&coin)
            .await?
            .ok_or(LedgerError::UnknownToken(coin))?;
        let attempted = token
            .total_supply
            .checked_add(amount)
            .ok_or(LedgerError::SupplyOverflow)?;
        if let Some(max) = token.max_supply {
            if attempted > max {
                return Err(LedgerError::MaxSupplyExceeded { max, attempted });
            }
        }
        token.total_supply = attempted;
        self.db.set_token(&token);
        Ok(attempted)
    }

    async fn decrease_supply(&mut self, coin: CoinId, amount: u128) -> Result<u128, LedgerError> {
        let mut token = self
            .db
            .token(&coin)
            .await?
            .ok_or(LedgerError::UnknownToken(coin))?;
        let total_supply = token
            .total_supply
            .checked_sub(amount)
            .ok_or(LedgerError::SupplyOverflow)?;
        token.total_supply = total_supply;
        self.db.set_token(&token);
        Ok(total_supply)
    }

    pub(crate) async fn credit(
        &mut self,
        account: &Address,
        coin: CoinId,
        amount: u128,
    ) -> Result<(), LedgerError> {
        if self.db.token(&coin).await?.is_none() {
            return Err(LedgerError::UnknownToken(coin));
        }
        let current = self.db.balance(account, &coin).await?;
        let updated = current
            .checked_add(amount)
            .ok_or(LedgerError::BalanceOverflow)?;
        self.db.set_balance(account, &coin, updated);
        Ok(())
    }

    pub(crate) async fn debit(
        &mut self,
        account: &Address,
        coin: CoinId,
        amount: u128,
    ) -> Result<(), LedgerError> {
        if self.db.token(&coin).await?.is_none() {
            return Err(LedgerError::UnknownToken(coin));
        }
        let available = self.db.balance(account, &coin).await?;
        if available < amount {
            return Err(LedgerError::InsufficientBalance {
                account: Box::new(account.clone()),
                coin: Box::new(coin),
                available,
                required: amount,
            });
        }
        self.db.set_balance(account, &coin, available - amount);
        Ok(())
    }
}

impl<D: CoinDB + CommitState> Ledger<D> {
    /// Flush staged writes, returning the new authenticated state root.
    pub async fn commit(&mut self) -> Result<Digest, LedgerError> {
        self.db
            .commit()
            .await
            .map_err(|err| LedgerError::Storage(err.to_string()))
    }

    /// The most recently committed authenticated state root.
    pub fn root(&self) -> Digest {
        self.db.root()
    }
}

fn ensure_positive(amount: u128) -> Result<(), LedgerError> {
    if amount == 0 {
        Err(LedgerError::InvalidAmount)
    } else {
        Ok(())
    }
}
