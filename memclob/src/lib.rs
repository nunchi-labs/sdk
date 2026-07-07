//! Validator-local in-memory order books with P2P gossip.
//!
//! Each validator keeps a deterministic [`MemBookEngine`] in RAM. Signed
//! `nunchi_clob::Transaction` instructions gossip over the overlay before
//! fills settle on-chain through `nunchi_clob::ClobLedger`.

commonware_macros::stability_scope!(ALPHA {
mod actor;
mod book;
mod config;
mod error;
#[cfg(test)]
mod tests;

pub use actor::{MemClob, MemClobHandle};
pub use book::{snapshot_digest, MemBookEngine, MEMCLOB_NAMESPACE};
pub use config::MemClobConfig;
pub use error::MemClobError;
});
