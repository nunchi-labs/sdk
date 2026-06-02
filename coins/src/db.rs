//! Persistence layer for the coin module.
//!
//! [`CoinDB`] is the coin module's typed *extension* of the shared [`StateDb`]: it adds the account,
//! token, and balance maps the ledger needs while reusing the shared, authenticated backend. The
//! blanket impl below means any [`StateDb`] is automatically a [`CoinDB`], so the coin module
//! composes onto the same store as every other module without bespoke wiring.

use super::{AccountId, CoinId, TokenDefinition, COINS_NAMESPACE};
use crate::LedgerError;
use commonware_codec::{Encode, Read, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_common::state_db::{Namespace, StateDb};

/// Namespace owned by the coin module within the shared [`StateDb`].
const NS: Namespace = Namespace::new(COINS_NAMESPACE);

/// Logical maps the coin module keeps inside its namespace. The discriminant separates same-shaped
/// keys (e.g. a 32-byte account id vs. a 32-byte coin id) into disjoint regions of the shared store.
#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    Account = 0,
    Factory = 1,
    Token = 2,
    Balance = 3,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, LedgerError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| LedgerError::Storage(err.to_string()))
}

fn balance_key(account: &AccountId, coin: &CoinId) -> Digest {
    let mut logical = encoded(account);
    logical.extend_from_slice(coin.encode().as_ref());
    NS.key(Table::Balance, &logical)
}

#[allow(async_fn_in_trait)]
pub trait CoinDB {
    /// Current nonce for `id` (0 if the account has never transacted).
    async fn nonce(&self, id: &AccountId) -> Result<u64, LedgerError>;

    /// Stage the next nonce for `id`.
    fn set_nonce(&mut self, id: &AccountId, nonce: u64);

    /// Next token-derivation nonce for the [`crate::TokenFactory`] (0 if no token exists yet).
    async fn factory_nonce(&self) -> Result<u64, LedgerError>;

    /// Stage the factory's next derivation nonce.
    fn set_factory_nonce(&mut self, nonce: u64);

    /// Look up a token definition.
    async fn token(&self, coin: &CoinId) -> Result<Option<TokenDefinition>, LedgerError>;

    /// Stage a token definition (insert or update).
    fn set_token(&mut self, token: &TokenDefinition);

    /// Balance of `coin` held by `account` (0 if none).
    async fn balance(&self, account: &AccountId, coin: &CoinId) -> Result<u128, LedgerError>;

    /// Stage a balance. An amount of 0 removes the entry so empty balances leave no state.
    fn set_balance(&mut self, account: &AccountId, coin: &CoinId, amount: u128);

    /// Flush staged writes, returning the new authenticated state root.
    async fn commit(&mut self) -> Result<Digest, LedgerError>;

    /// The most recently committed authenticated state root.
    fn root(&self) -> Digest;
}

impl<S: StateDb> CoinDB for S {
    async fn nonce(&self, id: &AccountId) -> Result<u64, LedgerError> {
        let key = NS.key(Table::Account, &encoded(id));
        match StateDb::get(self, &key)
            .await
            .map_err(|err| LedgerError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<u64>(&bytes),
            None => Ok(0),
        }
    }

    fn set_nonce(&mut self, id: &AccountId, nonce: u64) {
        let key = NS.key(Table::Account, &encoded(id));
        StateDb::set(self, key, encoded(&nonce));
    }

    async fn factory_nonce(&self) -> Result<u64, LedgerError> {
        let key = NS.key(Table::Factory, &[]);
        match StateDb::get(self, &key)
            .await
            .map_err(|err| LedgerError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<u64>(&bytes),
            None => Ok(0),
        }
    }

    fn set_factory_nonce(&mut self, nonce: u64) {
        let key = NS.key(Table::Factory, &[]);
        StateDb::set(self, key, encoded(&nonce));
    }

    async fn token(&self, coin: &CoinId) -> Result<Option<TokenDefinition>, LedgerError> {
        let key = NS.key(Table::Token, &encoded(coin));
        match StateDb::get(self, &key)
            .await
            .map_err(|err| LedgerError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded::<TokenDefinition>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_token(&mut self, token: &TokenDefinition) {
        let key = NS.key(Table::Token, &encoded(&token.id));
        StateDb::set(self, key, encoded(token));
    }

    async fn balance(&self, account: &AccountId, coin: &CoinId) -> Result<u128, LedgerError> {
        let key = balance_key(account, coin);
        match StateDb::get(self, &key)
            .await
            .map_err(|err| LedgerError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<u128>(&bytes),
            None => Ok(0),
        }
    }

    fn set_balance(&mut self, account: &AccountId, coin: &CoinId, amount: u128) {
        let key = balance_key(account, coin);
        if amount == 0 {
            StateDb::remove(self, key);
        } else {
            StateDb::set(self, key, encoded(&amount));
        }
    }

    async fn commit(&mut self) -> Result<Digest, LedgerError> {
        StateDb::commit(self)
            .await
            .map_err(|err| LedgerError::Storage(err.to_string()))
    }

    fn root(&self) -> Digest {
        StateDb::root(self)
    }
}
