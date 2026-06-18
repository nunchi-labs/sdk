//! Proof-of-authority validator registry primitives for Nunchi chains.

mod db;
mod genesis;
mod ledger;
#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
mod transaction;
mod types;

pub use db::AuthorityDB;
pub use genesis::{AuthorityGenesis, AuthorityPolicyGenesis};
pub use ledger::{proposal_id, AuthorityError, AuthorityLedger, MAX_EPOCH_LOOKAHEAD};
pub use transaction::{AuthorityOperation, Transaction, TransactionPayload};
pub use types::{
    EpochNumber, EpochRegistry, MultisigPolicy, OwnerId, Proposal, ProposalId, RegistryChange,
    ValidatorId, ValidatorSchedule, MAX_VALIDATORS,
};

/// Domain separator used for authority transaction signatures and state keys.
pub const AUTHORITY_NAMESPACE: &[u8] = b"_NUNCHI_AUTHORITY";
