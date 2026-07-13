/// Resource bounds and tuning knobs for a [`crate::Mempool`].
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Maximum pending transactions across all accounts.
    pub max_total_txs: usize,
    /// Maximum pending transactions in any single account's queue.
    pub max_per_account_txs: usize,
    /// Maximum encoded byte size of a single transaction. This is a pool
    /// resource bound, not a consensus validity rule.
    pub max_tx_bytes: usize,
    /// Pending transactions are dropped once this many blocks finalize after
    /// their admission without including them. Reclaims gapped or otherwise
    /// unexecutable transactions.
    pub ttl_blocks: u64,
    /// Number of per-digest status entries retained (FIFO eviction beyond).
    pub status_cache_capacity: usize,
    /// Bound on the actor's message mailbox.
    pub mailbox_size: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_total_txs: 10_000,
            max_per_account_txs: 64,
            max_tx_bytes: 64 * 1024,
            ttl_blocks: 1_000,
            status_cache_capacity: 100_000,
            mailbox_size: 1_024,
        }
    }
}
