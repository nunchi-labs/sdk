//! Coins-chain transaction pool aliases.
//!
//! The implementation lives in `nunchi-common` so generated runtimes and downstream chains can
//! reuse the same local ingress pool with their own transaction type.

pub type RuntimeSubmitter<R> =
    nunchi_common::txpool::Submitter<<R as nunchi_common::Runtime>::Transaction>;
pub type RuntimeTxPool<R> =
    nunchi_common::txpool::TxPool<<R as nunchi_common::Runtime>::Transaction>;

pub type Submitter = RuntimeSubmitter<crate::CoinsRuntime>;
pub type TxPool = RuntimeTxPool<crate::CoinsRuntime>;
