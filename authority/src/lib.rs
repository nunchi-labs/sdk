//! Proof-of-authority validator registry primitives for Nunchi chains.

commonware_macros::stability_scope!(ALPHA {
#[cfg(feature = "state")]
mod db;
#[cfg(feature = "state")]
mod genesis;
#[cfg(feature = "state")]
mod ledger;
#[cfg(test)]
mod tests;
mod transaction;
mod types;

#[cfg(feature = "state")]
pub use db::AuthorityDB;
#[cfg(feature = "state")]
pub use genesis::{AuthorityGenesis, AuthorityPolicyGenesis};
#[cfg(feature = "state")]
pub use ledger::{proposal_id, AuthorityError, AuthorityLedger, MAX_EPOCH_LOOKAHEAD};
pub use transaction::{AuthorityOperation, Transaction, TransactionPayload};
pub use types::{
    EpochNumber, EpochRegistry, MultisigPolicy, OwnerId, Proposal, ProposalId, RegistryChange,
    ValidatorId, ValidatorSchedule, MAX_VALIDATORS,
};

/// Domain separator used for authority transaction signatures and state keys.
pub const AUTHORITY_NAMESPACE: &[u8] = b"_NUNCHI_AUTHORITY";
});
