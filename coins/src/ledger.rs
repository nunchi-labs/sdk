use super::{
    Account, AccountId, CoinId, CoinOperation, TokenDefinition, TokenFactory, Transaction,
};
use commonware_codec::Encode;
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum LedgerError {
    #[error("bad transaction signature")]
    BadSignature,
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<AccountId>,
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
    #[error("insufficient balance for {account:?} in {coin:?}: available {available}, required {required}")]
    InsufficientBalance {
        account: Box<AccountId>,
        coin: Box<CoinId>,
        available: u128,
        required: u128,
    },
    #[error("balance overflow")]
    BalanceOverflow,
    #[error("supply overflow")]
    SupplyOverflow,
    #[error("max supply exceeded: max {max}, attempted {attempted}")]
    MaxSupplyExceeded { max: u128, attempted: u128 },
}

/// Deterministic in-memory state for accounts and tokens.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ledger {
    factory: TokenFactory,
    accounts: BTreeMap<AccountId, u64>,
    tokens: BTreeMap<CoinId, TokenDefinition>,
    balances: BTreeMap<(AccountId, CoinId), u128>,
}

impl Ledger {
    pub fn factory(&self) -> &TokenFactory {
        &self.factory
    }

    pub fn account(&self, id: &AccountId) -> Account {
        Account::new(id.clone(), self.nonce(id))
    }

    pub fn nonce(&self, id: &AccountId) -> u64 {
        self.accounts.get(id).copied().unwrap_or(0)
    }

    pub fn token(&self, coin: &CoinId) -> Option<&TokenDefinition> {
        self.tokens.get(coin)
    }

    pub fn tokens(&self) -> impl Iterator<Item = (&CoinId, &TokenDefinition)> {
        self.tokens.iter()
    }

    pub fn balance(&self, account: &AccountId, coin: &CoinId) -> u128 {
        self.balances
            .get(&(account.clone(), *coin))
            .copied()
            .unwrap_or(0)
    }

    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), LedgerError> {
        if !tx.verify() {
            return Err(LedgerError::BadSignature);
        }

        let expected = self.nonce(&tx.signer);
        if tx.payload.nonce != expected {
            return Err(LedgerError::NonceMismatch {
                account: Box::new(tx.signer.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        self.apply_operation(&tx.signer, &tx.payload.operation)?;
        let next_nonce = expected.checked_add(1).ok_or(LedgerError::NonceOverflow)?;
        self.accounts.insert(tx.signer.clone(), next_nonce);
        Ok(())
    }

    pub fn create_token(
        &mut self,
        issuer: AccountId,
        spec: super::CoinSpec,
    ) -> Result<CoinId, LedgerError> {
        let token = self.factory.create(issuer.clone(), spec)?;
        let id = token.id;
        if self.tokens.insert(id, token.clone()).is_some() {
            return Err(LedgerError::DuplicateToken(id));
        }
        if token.total_supply > 0 {
            self.credit(&issuer, id, token.total_supply)?;
        }
        Ok(id)
    }

    pub fn state_root(&self) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"NUNCHI_LEDGER_V1");
        hasher.update(&self.factory.encode());

        for (account, nonce) in &self.accounts {
            hasher.update(b"account");
            hasher.update(&account.encode());
            hasher.update(&nonce.encode());
        }

        for (coin, token) in &self.tokens {
            hasher.update(b"token");
            hasher.update(&coin.encode());
            hasher.update(&token.encode());
        }

        for ((account, coin), balance) in &self.balances {
            hasher.update(b"balance");
            hasher.update(&account.encode());
            hasher.update(&coin.encode());
            hasher.update(&balance.encode());
        }

        hasher.finalize()
    }

    fn apply_operation(
        &mut self,
        signer: &AccountId,
        operation: &CoinOperation,
    ) -> Result<(), LedgerError> {
        match operation {
            CoinOperation::CreateToken { spec } => {
                self.create_token(signer.clone(), spec.clone())?;
            }
            CoinOperation::Mint { coin, to, amount } => {
                self.ensure_positive(*amount)?;
                self.ensure_issuer(signer, coin)?;
                self.increase_supply(*coin, *amount)?;
                self.credit(to, *coin, *amount)?;
            }
            CoinOperation::Burn { coin, from, amount } => {
                self.ensure_positive(*amount)?;
                if signer != from {
                    return Err(LedgerError::Unauthorized);
                }
                self.debit(from, *coin, *amount)?;
                self.decrease_supply(*coin, *amount)?;
            }
            CoinOperation::Transfer {
                coin,
                from,
                to,
                amount,
            } => {
                self.ensure_positive(*amount)?;
                if signer != from {
                    return Err(LedgerError::Unauthorized);
                }
                self.debit(from, *coin, *amount)?;
                self.credit(to, *coin, *amount)?;
            }
        }
        Ok(())
    }

    fn ensure_positive(&self, amount: u128) -> Result<(), LedgerError> {
        if amount == 0 {
            Err(LedgerError::InvalidAmount)
        } else {
            Ok(())
        }
    }

    fn ensure_issuer(&self, signer: &AccountId, coin: &CoinId) -> Result<(), LedgerError> {
        let token = self
            .tokens
            .get(coin)
            .ok_or(LedgerError::UnknownToken(*coin))?;
        if &token.issuer == signer {
            Ok(())
        } else {
            Err(LedgerError::Unauthorized)
        }
    }

    fn increase_supply(&mut self, coin: CoinId, amount: u128) -> Result<(), LedgerError> {
        let token = self
            .tokens
            .get_mut(&coin)
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
        Ok(())
    }

    fn decrease_supply(&mut self, coin: CoinId, amount: u128) -> Result<(), LedgerError> {
        let token = self
            .tokens
            .get_mut(&coin)
            .ok_or(LedgerError::UnknownToken(coin))?;
        token.total_supply = token
            .total_supply
            .checked_sub(amount)
            .ok_or(LedgerError::SupplyOverflow)?;
        Ok(())
    }

    fn credit(
        &mut self,
        account: &AccountId,
        coin: CoinId,
        amount: u128,
    ) -> Result<(), LedgerError> {
        if !self.tokens.contains_key(&coin) {
            return Err(LedgerError::UnknownToken(coin));
        }
        let key = (account.clone(), coin);
        let current = self.balances.get(&key).copied().unwrap_or(0);
        let updated = current
            .checked_add(amount)
            .ok_or(LedgerError::BalanceOverflow)?;
        self.balances.insert(key, updated);
        Ok(())
    }

    fn debit(
        &mut self,
        account: &AccountId,
        coin: CoinId,
        amount: u128,
    ) -> Result<(), LedgerError> {
        if !self.tokens.contains_key(&coin) {
            return Err(LedgerError::UnknownToken(coin));
        }
        let key = (account.clone(), coin);
        let available = self.balances.get(&key).copied().unwrap_or(0);
        if available < amount {
            return Err(LedgerError::InsufficientBalance {
                account: Box::new(account.clone()),
                coin: Box::new(coin),
                available,
                required: amount,
            });
        }
        let updated = available - amount;
        if updated == 0 {
            self.balances.remove(&key);
        } else {
            self.balances.insert(key, updated);
        }
        Ok(())
    }
}
