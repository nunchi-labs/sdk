//! Runtime-generic transaction pool aliases.

pub type RuntimeSubmitter<R> =
    nunchi_common::txpool::Submitter<<R as nunchi_common::Runtime>::Transaction>;
pub type RuntimeTxPool<R> =
    nunchi_common::txpool::TxPool<<R as nunchi_common::Runtime>::Transaction>;
