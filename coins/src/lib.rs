//! Foundational coin, account, and ledger primitives for the Nunchi SDK.

commonware_macros::stability_scope!(ALPHA {
mod account;
mod asset;
#[cfg(feature = "state")]
mod db;
#[cfg(feature = "state")]
mod events;
#[cfg(feature = "state")]
mod factory;
#[cfg(feature = "state")]
mod fees;
#[cfg(feature = "state")]
mod genesis;
#[cfg(feature = "state")]
mod ledger;
/// JSON-RPC surface for the coin module (enabled by the default `rpc` feature).
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(test)]
mod tests;
mod transaction;

pub use account::{
    external_account_id, multisig_account_id, Account, AccountPolicy, AccountPolicyError,
    AccountType, Address, MultisigPolicy, PrivateKey, Signature,
};
pub use asset::{
    CoinId, CoinSpec, TokenDefinition, TokenName, TokenSymbol, MAX_NAME_BYTES, MAX_SYMBOL_BYTES,
};
#[cfg(feature = "state")]
pub use db::CoinDB;
#[cfg(feature = "state")]
pub use events::{
    account_policy_registered_event, burned_event, fee_charged_event, minted_event,
    token_created_event, transferred_event, AccountPolicyRegistered, Burned, FeeCharged, Minted,
    TokenCreated, Transferred, ACCOUNT_POLICY_REGISTERED_EVENT, BURNED_EVENT, FEE_CHARGED_EVENT,
    MINTED_EVENT, TOKEN_CREATED_EVENT, TRANSFERRED_EVENT,
};
#[cfg(feature = "state")]
pub use factory::TokenFactory;
#[cfg(feature = "state")]
pub use fees::FeeConfig;
#[cfg(feature = "state")]
pub use genesis::{
    AccountPolicyGenesis, AllocationGenesis, CoinsGenesis, FeeGenesis, MultisigPolicyGenesis,
    TokenGenesis,
};
#[cfg(feature = "state")]
pub use ledger::{Ledger, LedgerError};
pub use nunchi_common::{AccountSignature, Authorization};
pub use transaction::{CoinOperation, Transaction, TransactionPayload};

/// Domain separator used for coin transaction signatures and token identifiers.
pub const COINS_NAMESPACE: &[u8] = b"_NUNCHI_COINS";
});
