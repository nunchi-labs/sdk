//! Coins-chain transaction pool aliases.
//!
//! The implementation lives in `nunchi-common` so generated runtimes and downstream chains can
//! reuse the same local ingress pool with their own transaction type.

pub type Submitter = nunchi_common::txpool::Submitter<crate::RuntimeTransaction>;
pub type TxPool = nunchi_common::txpool::TxPool<crate::RuntimeTransaction>;
