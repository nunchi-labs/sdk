use bytes::Bytes;
use commonware_consensus::types::Height;
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner as _, Supervisor as _};
use commonware_storage::archive::immutable;
use commonware_utils::{NZUsize, NZU16, NZU64};
use nunchi_common::{receipts_root, Event, EventAttribute, TransactionEvents};

use crate::{
    EventArchiveError, EventKey, FinalizedEventArchive, FinalizedEvents,
    PersistentFinalizedEventArchive,
};

fn event(kind: &'static [u8], key: &'static [u8], value: &'static [u8]) -> Event {
    Event::new(
        Bytes::from_static(b"coins"),
        Bytes::from_static(kind),
        1,
        vec![EventAttribute::new(
            Bytes::from_static(key),
            Bytes::from_static(value),
        )],
    )
}

fn batch(height: u64, tx_label: &'static [u8], event: Event) -> FinalizedEvents {
    let tx_digest = Sha256::hash(tx_label);
    let transaction = TransactionEvents::new(0, tx_digest, vec![event]).expect("transaction");
    FinalizedEvents {
        height: Height::new(height),
        block_digest: Sha256::hash(&height.to_be_bytes()),
        block_timestamp: 1_000 + height,
        receipts_root: receipts_root(&[transaction.receipt]),
        transactions: vec![transaction],
    }
}

#[test]
fn finalized_event_archive_indexes_batches_transactions_and_event_keys() {
    let archive = FinalizedEventArchive::new();
    let first = batch(1, b"tx-1", event(b"minted", b"account", b"alice"));
    let second = batch(2, b"tx-2", event(b"minted", b"account", b"bob"));
    let key = EventKey::new(
        Bytes::from_static(b"coins"),
        Bytes::from_static(b"minted"),
        1,
        Bytes::from_static(b"account"),
    );

    archive.insert(first.clone()).expect("insert first");
    archive.insert(second.clone()).expect("insert second");

    assert_eq!(
        archive
            .batch_by_height(Height::new(1))
            .expect("height query"),
        Some(first.clone())
    );
    assert_eq!(
        archive
            .batch_by_block_digest(second.block_digest)
            .expect("block query"),
        Some(second.clone())
    );
    let tx_events = archive
        .transactions_by_digest(first.transactions[0].receipt.tx_digest)
        .expect("transaction query");
    assert_eq!(tx_events.len(), 1);
    assert_eq!(tx_events[0].height, Height::new(1));
    assert_eq!(tx_events[0].events, first.transactions[0].events);

    let indexed_events = archive
        .events_by_key(&key, Some(Height::new(2)), 10)
        .expect("event key query");
    assert_eq!(indexed_events.len(), 1);
    assert_eq!(indexed_events[0].height, Height::new(2));
    assert_eq!(indexed_events[0].event, second.transactions[0].events[0]);

    let streamed = archive
        .stream_from(Height::new(1), 10)
        .expect("stream query");
    assert_eq!(streamed, vec![first, second]);
}

#[test]
fn finalized_event_archive_allows_idempotent_insert_and_rejects_conflicts() {
    let archive = FinalizedEventArchive::new();
    let first = batch(1, b"tx-1", event(b"minted", b"account", b"alice"));
    let conflicting_height = batch(1, b"tx-2", event(b"minted", b"account", b"bob"));
    let mut conflicting_block = batch(2, b"tx-3", event(b"minted", b"account", b"carol"));
    conflicting_block.block_digest = first.block_digest;

    archive.insert(first.clone()).expect("insert first");
    archive.insert(first).expect("idempotent insert");

    assert_eq!(
        archive
            .insert(conflicting_height)
            .expect_err("height conflict"),
        EventArchiveError::HeightConflict { height: 1 }
    );
    assert_eq!(
        archive
            .insert(conflicting_block)
            .expect_err("block conflict"),
        EventArchiveError::BlockDigestConflict {
            block_digest: archive
                .batch_by_height(Height::new(1))
                .unwrap()
                .unwrap()
                .block_digest,
            height: 1,
        }
    );
}

#[test]
fn persistent_finalized_event_archive_rebuilds_indexes_after_restart() {
    let (batch, checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let archive = PersistentFinalizedEventArchive::init(
                context.child("first"),
                persistent_config(&context, "events-persistent"),
            )
            .await
            .expect("init persistent archive");
            let batch = batch(7, b"tx-persistent", event(b"minted", b"account", b"alice"));

            archive.insert(batch.clone()).await.expect("insert batch");
            batch
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        let archive = PersistentFinalizedEventArchive::init(
            context.child("second"),
            persistent_config(&context, "events-persistent"),
        )
        .await
        .expect("reopen persistent archive");
        let query = archive.query_archive();
        let key = EventKey::new(
            Bytes::from_static(b"coins"),
            Bytes::from_static(b"minted"),
            1,
            Bytes::from_static(b"account"),
        );

        assert_eq!(
            query
                .batch_by_block_digest(batch.block_digest)
                .expect("block query"),
            Some(batch.clone())
        );
        assert_eq!(
            query
                .transactions_by_digest(batch.transactions[0].receipt.tx_digest)
                .expect("transaction query")
                .len(),
            1
        );
        assert_eq!(
            query
                .events_by_key(&key, Some(Height::new(7)), 10)
                .expect("event key query")
                .len(),
            1
        );
    });
}

fn persistent_config(
    context: &deterministic::Context,
    prefix: &str,
) -> immutable::Config<nunchi_common::EventLimits> {
    immutable::Config {
        metadata_partition: format!("{prefix}-metadata"),
        freezer_table_partition: format!("{prefix}-table"),
        freezer_table_initial_size: 64,
        freezer_table_resize_frequency: 4,
        freezer_table_resize_chunk_size: 64,
        freezer_key_partition: format!("{prefix}-key"),
        freezer_key_page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
        freezer_key_write_buffer: NZUsize!(1024),
        freezer_value_partition: format!("{prefix}-value"),
        freezer_value_write_buffer: NZUsize!(1024),
        freezer_value_target_size: 1024 * 1024,
        freezer_value_compression: None,
        ordinal_partition: format!("{prefix}-ordinal"),
        ordinal_write_buffer: NZUsize!(1024),
        items_per_section: NZU64!(64),
        codec_config: nunchi_common::EventLimits::default(),
        replay_buffer: NZUsize!(1024),
    }
}
