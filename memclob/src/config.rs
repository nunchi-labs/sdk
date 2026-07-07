use std::num::NonZeroUsize;

/// Memclob actor configuration.
#[derive(Clone, Debug)]
pub struct MemClobConfig {
    /// Capacity of the actor ingress mailbox.
    pub mailbox_size: NonZeroUsize,
    /// Maximum gossiped instructions retained for deduplication.
    pub dedup_capacity: usize,
}

impl Default for MemClobConfig {
    fn default() -> Self {
        Self {
            mailbox_size: NonZeroUsize::new(1024).expect("non-zero mailbox"),
            dedup_capacity: 65_536,
        }
    }
}
