//! A demo blockchain that runs the Nunchi coins module under consensus.

use commonware_consensus::types::Epoch;
use std::num::NonZeroU64;

mod block;
mod consensus;

pub mod application;
pub mod engine;
pub mod execution;
pub mod txpool;

pub use block::{Block, Finalized, Notarized, MAX_TRANSACTIONS};
pub use consensus::{
    Activity, Context, EdScheme, EpochProvider, Finalization, Identity, Notarization, Provider,
    PublicKey, Scheme, Seed, Seedable, Signature, ThresholdScheme,
};

/// Namespace prefix used in all consensus signing operations to prevent signature replay attacks.
pub const NAMESPACE: &[u8] = b"_NUNCHI_COINS_CHAIN";

/// The consensus epoch. The demo chain never reconfigures, so the epoch is hardcoded to 0.
pub const EPOCH: Epoch = Epoch::zero();

/// The number of blocks in an epoch.
///
/// Production systems should use a much larger value, as DKG/reshare safety depends on
/// synchrony during the epoch window.
pub const BLOCKS_PER_EPOCH: NonZeroU64 = commonware_utils::NZU64!(200);
