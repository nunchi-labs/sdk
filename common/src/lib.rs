//! Shared Nunchi primitives used across application crates.

commonware_macros::stability_scope!(ALPHA {
use commonware_codec::varint::UInt;
use commonware_codec::MaxEncodeSize;

/// Larger of two encoded-size bounds.
pub const fn wider(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

/// Upper bound on a length-prefixed sequence of `len` items of `item_size` bytes.
///
/// The length prefix contributes its widest `u32` varint, matching
/// `commonware_codec::util::max_items_size`.
pub const fn items_bound(len: usize, item_size: usize) -> usize {
    len * item_size + UInt::<u32>::MAX_ENCODE_SIZE
}

#[cfg(feature = "state")]
pub mod state_db;

mod account;
mod events;
#[cfg(feature = "state")]
mod runtime;
#[cfg(test)]
mod tests;
mod transaction;

pub use account::{
    AccountPolicyError, Address, Bech32Error, MultisigPolicy, ADDRESS_HRP, MAX_MULTISIG_SIGNERS,
};
pub use events::{Event, EventSink, NoopEventSink, VecEventSink};
#[cfg(feature = "state")]
pub use runtime::{Runtime, RuntimeContext};
#[cfg(feature = "state")]
pub use state_db::{
    max_qmdb_operation_bytes, max_qmdb_operation_encode_size, max_state_proof_encode_size,
    qmdb_operation_codec_config, shared_database, CommitState, Namespace, Overlay, QmdbBackend,
    QmdbBatch, QmdbConfig, QmdbDatabaseSet, QmdbMerkleized, QmdbOperation, QmdbOperationCfg,
    QmdbReader, QmdbState, QmdbUnmerkleized, QmdbUpdate, StateDb, StateError, StateStore,
    MAX_STATE_VALUE_SIZE,
};
pub use transaction::{
    AccountSignature, Authorization, Operation, Transaction, TransactionPayload,
};
});
