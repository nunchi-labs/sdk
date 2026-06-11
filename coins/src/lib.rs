//! Foundational coin, account, and ledger primitives for the Nunchi SDK.

mod account;
mod asset;
mod codec;
mod db;
mod factory;
mod ledger;
/// JSON-RPC surface for the coin module (enabled by the default `rpc` feature).
#[cfg(feature = "rpc")]
pub mod rpc;
mod transaction;

pub use account::{
    external_account_id, multisig_account_id, Account, AccountPolicy, AccountPolicyError,
    AccountType, Address, MultisigPolicy, PrivateKey, Signature,
};
pub use asset::{CoinId, CoinSpec, TokenDefinition, MAX_NAME_BYTES, MAX_SYMBOL_BYTES};
pub use db::CoinDB;
pub use factory::TokenFactory;
pub use ledger::{Ledger, LedgerError};
pub use nunchi_common::{AccountSignature, Authorization};
pub use transaction::{CoinOperation, Transaction, TransactionPayload};

/// Domain separator used for coin transaction signatures and token identifiers.
pub const COINS_NAMESPACE: &[u8] = b"_NUNCHI_COINS";
