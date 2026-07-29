use std::panic::{AssertUnwindSafe, catch_unwind};

use commonware_cryptography::sha256::Digest;
use futures::executor::block_on;
use nunchi_common::RuntimeContext;

use crate::{EventConsumer, InMemoryEventConsumer};

fn context(block_digest: Digest) -> RuntimeContext {
    RuntimeContext {
        epoch: 0,
        height: 1,
        timestamp_ms: 0,
        block_digest: Some(block_digest),
    }
}

#[test]
fn in_memory_event_consumer_recovers_poisoned_pending_buffer() {
    let consumer = InMemoryEventConsumer::new();
    assert!(catch_unwind(AssertUnwindSafe(|| consumer.poison_pending())).is_err());

    let block_digest = Digest::from([1; 32]);
    block_on(consumer.begin_block(context(block_digest)));
    block_on(consumer.finalized(context(block_digest)));

    assert_eq!(consumer.len(), 1);
}

#[test]
fn in_memory_event_consumer_recovers_poisoned_reports() {
    let consumer = InMemoryEventConsumer::new();
    assert!(catch_unwind(AssertUnwindSafe(|| consumer.poison_reports())).is_err());

    assert!(consumer.is_empty());
    assert!(consumer.reports().is_empty());
}
