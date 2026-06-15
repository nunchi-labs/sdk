//! Coins-chain transaction pool aliases over the reusable `nunchi-chain` pool.

pub type RuntimeSubmitter<R> = nunchi_chain::RuntimeSubmitter<R>;
pub type RuntimeTxPool<R> = nunchi_chain::RuntimeTxPool<R>;

pub type Submitter = RuntimeSubmitter<crate::CoinsRuntime>;
pub type TxPool = RuntimeTxPool<crate::CoinsRuntime>;
