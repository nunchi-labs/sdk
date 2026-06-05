//! Foundational coin, account, and ledger primitives for the Nunchi SDK.

mod account;
mod asset;
mod codec;
mod db;
mod factory;
mod ledger;
mod transaction;

pub use account::{
    Account, AccountId, AccountPolicy, AccountPolicyError, AccountType, MultisigPolicy, PrivateKey,
    Signature,
};
pub use asset::{CoinId, CoinSpec, TokenDefinition, MAX_NAME_BYTES, MAX_SYMBOL_BYTES};
pub use db::CoinDB;
pub use factory::TokenFactory;
pub use ledger::{Ledger, LedgerError};
pub use nunchi_common::{AccountSignature, Authorization};
pub use transaction::{CoinOperation, Transaction, TransactionPayload};

/// Domain separator used for coin transaction signatures and token identifiers.
pub const COINS_NAMESPACE: &[u8] = b"_NUNCHI_COINS";
