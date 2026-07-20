//! Native wallet framework for Nunchi SDK chains.

pub mod client;
pub mod keystore;
pub mod passkey;
pub mod record;

pub use client::{submit_coins_transaction, SubmitTransactionResponse, WalletRpcClient};
pub use keystore::{KeystoreError, WalletKeystore};
pub use passkey::{PasskeyAssertion, PasskeyPublicKey, SECP256R1_SCHEME};
pub use record::{
    address_from_public_key, address_hrp, create_wallet, list_wallets, load_private_key,
    parse_address, show_wallet, sign_message, CreateWalletOptions, CreatedWallet,
    ListWalletsOptions, WalletError, WalletLookupOptions, WalletRecord, WalletSummary,
};
