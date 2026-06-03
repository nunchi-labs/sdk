use super::{
    Account, AccountId, CoinId, CoinOperation, TokenDefinition, TokenFactory, Transaction,
};
use crate::db::CoinDB;
use commonware_cryptography::sha256::Digest;
use nunchi_crypto::SignatureError;
use thiserror::Error;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum LedgerError {
    #[error("bad transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
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

    pub async fn account(&self, id: &AccountId) -> Result<Account, LedgerError> {
        Ok(Account::new(id.clone(), self.db.nonce(id).await?))
    }

    pub async fn nonce(&self, id: &AccountId) -> Result<u64, LedgerError> {
        self.db.nonce(id).await
    }

    pub async fn token(&self, coin: &CoinId) -> Result<Option<TokenDefinition>, LedgerError> {
        self.db.token(coin).await
    }

    pub async fn balance(&self, account: &AccountId, coin: &CoinId) -> Result<u128, LedgerError> {
        self.db.balance(account, coin).await
    }

    pub async fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), LedgerError> {
        tx.verify()?;

        let expected = self.db.nonce(&tx.signer).await?;
        if tx.payload.nonce != expected {
            return Err(LedgerError::NonceMismatch {
                account: Box::new(tx.signer.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        self.apply_operation(&tx.signer, &tx.payload.operation)
            .await?;
        let next_nonce = expected.checked_add(1).ok_or(LedgerError::NonceOverflow)?;
        self.db.set_nonce(&tx.signer, next_nonce);
        Ok(())
    }

    pub async fn create_token(
        &mut self,
        issuer: AccountId,
        spec: super::CoinSpec,
    ) -> Result<CoinId, LedgerError> {
        let mut factory = TokenFactory::with_nonce(self.db.factory_nonce().await?);
        let token = factory.create(issuer.clone(), spec)?;
        self.db.set_factory_nonce(factory.next_nonce());

        let id = token.id;
        if self.db.token(&id).await?.is_some() {
            return Err(LedgerError::DuplicateToken(id));
        }
        self.db.set_token(&token);
        if token.total_supply > 0 {
            self.credit(&issuer, id, token.total_supply).await?;
        }
        Ok(id)
    }

    /// Flush staged writes, returning the new authenticated state root.
    pub async fn commit(&mut self) -> Result<Digest, LedgerError> {
        self.db.commit().await
    }

    /// The most recently committed authenticated state root.
    pub fn root(&self) -> Digest {
        self.db.root()
    }

    async fn apply_operation(
        &mut self,
        signer: &AccountId,
        operation: &CoinOperation,
    ) -> Result<(), LedgerError> {
        match operation {
            CoinOperation::CreateToken { spec } => {
                self.create_token(signer.clone(), spec.clone()).await?;
            }
            CoinOperation::Mint { coin, to, amount } => {
                ensure_positive(*amount)?;
                self.ensure_issuer(signer, coin).await?;
                self.increase_supply(*coin, *amount).await?;
                self.credit(to, *coin, *amount).await?;
            }
            CoinOperation::Burn { coin, from, amount } => {
                ensure_positive(*amount)?;
                if signer != from {
                    return Err(LedgerError::Unauthorized);
                }
                self.debit(from, *coin, *amount).await?;
                self.decrease_supply(*coin, *amount).await?;
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
            }
        }
        Ok(())
    }

    async fn ensure_issuer(&self, signer: &AccountId, coin: &CoinId) -> Result<(), LedgerError> {
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

    async fn increase_supply(&mut self, coin: CoinId, amount: u128) -> Result<(), LedgerError> {
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
        Ok(())
    }

    async fn decrease_supply(&mut self, coin: CoinId, amount: u128) -> Result<(), LedgerError> {
        let mut token = self
            .db
            .token(&coin)
            .await?
            .ok_or(LedgerError::UnknownToken(coin))?;
        token.total_supply = token
            .total_supply
            .checked_sub(amount)
            .ok_or(LedgerError::SupplyOverflow)?;
        self.db.set_token(&token);
        Ok(())
    }

    async fn credit(
        &mut self,
        account: &AccountId,
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

    async fn debit(
        &mut self,
        account: &AccountId,
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

fn ensure_positive(amount: u128) -> Result<(), LedgerError> {
    if amount == 0 {
        Err(LedgerError::InvalidAmount)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoinSpec, PrivateKey};
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
    use nunchi_common::QmdbState;

    async fn ledger(context: deterministic::Context) -> Ledger<QmdbState<deterministic::Context>> {
        let db = QmdbState::init(context, "coins-test")
            .await
            .expect("init state db");
        Ledger::new(db)
    }

    fn spec(supply: u128, max: Option<u128>) -> CoinSpec {
        CoinSpec::new("NCH", "Nunchi", 9, supply, max)
    }

    #[test]
    fn create_token_credits_issuer_and_commits_root() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut ledger = ledger(context).await;
            let alice = PrivateKey::ed25519_from_seed(1).public_key();

            let empty_root = ledger.root();
            let coin = ledger
                .create_token(alice.clone(), spec(1_000, None))
                .await
                .expect("create token");

            assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 1_000);
            assert_eq!(
                ledger.token(&coin).await.unwrap().unwrap().total_supply,
                1_000
            );

            let root = ledger.commit().await.expect("commit");
            assert_ne!(root, empty_root, "committing state must change the root");
        });
    }

    #[test]
    fn transfer_via_signed_transaction_moves_balance_and_bumps_nonce() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut ledger = ledger(context).await;
            let alice_key = PrivateKey::ed25519_from_seed(1);
            let alice = alice_key.public_key();
            let bob = PrivateKey::ed25519_from_seed(2).public_key();

            let coin = ledger
                .create_token(alice.clone(), spec(1_000, None))
                .await
                .expect("create token");

            let tx = Transaction::sign(
                &alice_key,
                0,
                CoinOperation::Transfer {
                    coin,
                    from: alice.clone(),
                    to: bob.clone(),
                    amount: 250,
                },
            );
            ledger.apply_transaction(&tx).await.expect("apply transfer");

            assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 750);
            assert_eq!(ledger.balance(&bob, &coin).await.unwrap(), 250);
            assert_eq!(ledger.nonce(&alice).await.unwrap(), 1);
        });
    }

    #[test]
    fn rejects_transaction_with_wrong_nonce() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut ledger = ledger(context).await;
            let alice_key = PrivateKey::ed25519_from_seed(1);
            let alice = alice_key.public_key();
            let bob = PrivateKey::ed25519_from_seed(2).public_key();

            let coin = ledger
                .create_token(alice.clone(), spec(1_000, None))
                .await
                .expect("create token");

            // Signer's account nonce is still 0; signing with nonce 5 must be rejected.
            let tx = Transaction::sign(
                &alice_key,
                5,
                CoinOperation::Transfer {
                    coin,
                    from: alice.clone(),
                    to: bob,
                    amount: 1,
                },
            );
            let err = ledger.apply_transaction(&tx).await.unwrap_err();
            assert!(matches!(
                err,
                LedgerError::NonceMismatch {
                    expected: 0,
                    actual: 5,
                    ..
                }
            ));
        });
    }

    #[test]
    fn rejects_transaction_with_bad_signature() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut ledger = ledger(context).await;
            let alice_key = PrivateKey::ed25519_from_seed(1);
            let alice = alice_key.public_key();
            let bob = PrivateKey::ed25519_from_seed(2).public_key();

            let coin = ledger
                .create_token(alice.clone(), spec(1_000, None))
                .await
                .expect("create token");

            let mut tx = Transaction::sign(
                &alice_key,
                0,
                CoinOperation::Transfer {
                    coin,
                    from: alice.clone(),
                    to: bob,
                    amount: 1,
                },
            );
            tx.payload.operation = CoinOperation::Transfer {
                coin,
                from: alice,
                to: PrivateKey::ed25519_from_seed(3).public_key(),
                amount: 1,
            };

            let err = ledger.apply_transaction(&tx).await.unwrap_err();
            assert_eq!(
                err,
                LedgerError::BadSignature(SignatureError::InvalidSignature)
            );
        });
    }

    #[test]
    fn committed_state_survives_reopen() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let alice = PrivateKey::ed25519_from_seed(1).public_key();

            let coin = {
                let mut ledger = ledger(context.child("open")).await;
                let coin = ledger
                    .create_token(alice.clone(), spec(1_000, None))
                    .await
                    .expect("create token");
                ledger.commit().await.expect("commit");
                coin
            };

            // Reopen the same partitions: committed balances must be recovered.
            let reopened = ledger(context.child("reopen")).await;
            assert_eq!(reopened.balance(&alice, &coin).await.unwrap(), 1_000);
        });
    }
}
