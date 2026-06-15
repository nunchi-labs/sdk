//! Coins-chain block aliases over the reusable `nunchi-chain` block.

use crate::RuntimeTransaction;

pub type Block<Tx = RuntimeTransaction> = nunchi_chain::Block<Tx>;
pub type Notarized<Tx = RuntimeTransaction> = nunchi_chain::Notarized<Tx>;
pub type Finalized<Tx = RuntimeTransaction> = nunchi_chain::Finalized<Tx>;

pub use nunchi_chain::{StateCommitment, MAX_TRANSACTIONS};
