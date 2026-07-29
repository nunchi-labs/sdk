use commonware_runtime::{deterministic, Runner as _};
use nunchi_common::RuntimeContext;

use crate::{EventConsumer, InMemoryEventConsumer};

#[test]
fn in_memory_consumer_ignores_begin_block_without_digest() {
    deterministic::Runner::default().start(|_| async move {
        let consumer = InMemoryEventConsumer::new();
        consumer
            .begin_block(RuntimeContext {
                epoch: 1,
                height: 2,
                timestamp_ms: 3,
                block_digest: None,
            })
            .await;

        assert!(consumer.is_empty());
    });
}
