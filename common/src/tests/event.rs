use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};

use crate::{
    empty_events_root, empty_receipts_root, events_root, receipts_root, BlockExecutionOutput,
    Event, EventAttribute, EventBuffer, EventError, EventLimits, EventSink, TransactionEvents,
};

fn attr(key: &'static [u8], value: &'static [u8]) -> EventAttribute {
    EventAttribute::new(Bytes::from_static(key), Bytes::from_static(value))
}

fn event(kind: &'static [u8], value: &'static [u8]) -> Event {
    Event::new(
        Bytes::from_static(b"coins"),
        Bytes::from_static(kind),
        1,
        vec![attr(b"amount", value)],
    )
}

#[test]
fn event_codec_roundtrips() {
    let limits = EventLimits::default();
    let original = Event::new(
        Bytes::from_static(b"authority"),
        Bytes::from_static(b"validator_added"),
        1,
        vec![
            attr(b"validator", b"alice"),
            EventAttribute::new(
                Bytes::from_static(b"epoch"),
                Bytes::copy_from_slice(&7u64.to_be_bytes()),
            ),
        ],
    );

    let decoded = Event::decode_cfg(original.encode(), &limits).expect("decode event");

    assert_eq!(decoded, original);
}

#[test]
fn event_buffer_preserves_emission_order() {
    let tx_digest = Sha256::hash(b"tx-0");
    let mut buffer = EventBuffer::default();
    buffer.emit(event(b"minted", b"10")).expect("emit minted");
    buffer
        .emit(event(b"transferred", b"4"))
        .expect("emit transferred");

    let output = buffer.finish(0, tx_digest).expect("finish buffer");

    assert_eq!(output.events[0].kind, Bytes::from_static(b"minted"));
    assert_eq!(output.events[1].kind, Bytes::from_static(b"transferred"));
    assert_eq!(output.receipt.event_count, 2);
    assert_eq!(
        output.receipt.events_root,
        events_root(0, tx_digest, &output.events).expect("events root")
    );
}

#[test]
fn empty_roots_are_fixed_and_domain_separated() {
    assert_eq!(
        empty_events_root(),
        Digest([
            0x5d, 0x9d, 0x70, 0x59, 0xe7, 0x98, 0x5d, 0x70, 0x61, 0x9d, 0xd9, 0x64, 0xf6, 0x27,
            0x0e, 0xee, 0xe0, 0x50, 0x3e, 0xd9, 0xbf, 0xe4, 0xb6, 0x58, 0xdd, 0x97, 0xc7, 0x44,
            0xac, 0xef, 0x80, 0xfd,
        ])
    );
    assert_eq!(
        empty_receipts_root(),
        Digest([
            0x94, 0x37, 0x34, 0x24, 0xa2, 0xc7, 0xab, 0xb8, 0x35, 0xc2, 0xc5, 0xed, 0xb4, 0x77,
            0x70, 0x84, 0x52, 0x6a, 0x56, 0x0d, 0x63, 0x47, 0xde, 0xee, 0x0c, 0x10, 0x8d, 0x4a,
            0x9a, 0xba, 0x77, 0x39,
        ])
    );
    assert_ne!(empty_events_root(), empty_receipts_root());
}

#[test]
fn event_roots_are_ordered_and_stable() {
    let tx_digest = Sha256::hash(b"tx-1");
    let minted = event(b"minted", b"10");
    let burned = event(b"burned", b"2");
    let ordered = vec![minted.clone(), burned.clone()];
    let reversed = vec![burned, minted];

    let single = events_root(3, tx_digest, &ordered[..1]).expect("single root");
    let ordered_root = events_root(3, tx_digest, &ordered).expect("ordered root");
    let reversed_root = events_root(3, tx_digest, &reversed).expect("reversed root");

    assert_eq!(
        single,
        Digest([
            0x3d, 0xc2, 0xb1, 0x33, 0xb5, 0xb0, 0xd1, 0x8a, 0x73, 0x16, 0xef, 0x40, 0xe3, 0x63,
            0xf4, 0xc2, 0xa2, 0xac, 0x58, 0x75, 0x1e, 0xb0, 0x12, 0x24, 0x22, 0x30, 0x38, 0x49,
            0x0c, 0xe1, 0xb3, 0xb4,
        ])
    );
    assert_eq!(
        ordered_root,
        Digest([
            0xe1, 0x85, 0x5b, 0x1f, 0x14, 0x0d, 0x31, 0xb9, 0x22, 0x65, 0xfe, 0x53, 0xbc, 0x6f,
            0x0c, 0xb7, 0xc8, 0xe4, 0x89, 0x8e, 0xc0, 0xfd, 0x58, 0x24, 0xe7, 0xaf, 0x53, 0x38,
            0x33, 0x41, 0x5b, 0xf6,
        ])
    );
    assert_ne!(ordered_root, reversed_root);
}

#[test]
fn receipt_roots_are_ordered_and_stable() {
    let tx0 = Sha256::hash(b"tx-0");
    let tx1 = Sha256::hash(b"tx-1");
    let first = TransactionEvents::new(0, tx0, vec![event(b"minted", b"10")]).unwrap();
    let second = TransactionEvents::new(1, tx1, vec![event(b"burned", b"2")]).unwrap();

    let ordered = receipts_root(&[first.receipt, second.receipt]);
    let reversed = receipts_root(&[second.receipt, first.receipt]);

    assert_eq!(
        ordered,
        Digest([
            0x40, 0xa5, 0x49, 0xea, 0xd9, 0xc5, 0xc7, 0x6b, 0x9f, 0x40, 0xd3, 0xe7, 0x9c, 0x08,
            0x9e, 0xc8, 0xf7, 0xa0, 0x87, 0x28, 0x11, 0x90, 0x08, 0x97, 0xbb, 0xd5, 0x95, 0xa4,
            0x25, 0x3c, 0x55, 0x5f,
        ])
    );
    assert_ne!(ordered, reversed);
}

#[test]
fn block_execution_output_computes_and_roundtrips() {
    let limits = EventLimits::default();
    let tx0 =
        TransactionEvents::new(0, Sha256::hash(b"tx-0"), vec![event(b"minted", b"10")]).unwrap();
    let tx1 = TransactionEvents::new(1, Sha256::hash(b"tx-1"), vec![event(b"transferred", b"4")])
        .unwrap();

    let output = BlockExecutionOutput::with_limits(vec![tx0.clone(), tx1.clone()], limits).unwrap();
    let decoded =
        BlockExecutionOutput::decode_cfg(output.encode(), &limits).expect("decode output");

    assert_eq!(
        output.receipts_root,
        receipts_root(&[tx0.receipt, tx1.receipt])
    );
    assert_eq!(decoded, output);
}

#[test]
fn event_buffer_enforces_event_count_limit() {
    let limits = EventLimits {
        max_events_per_transaction: 1,
        ..EventLimits::default()
    };
    let mut buffer = EventBuffer::new(limits);

    buffer.emit(event(b"minted", b"10")).expect("first emit");
    let err = buffer
        .emit(event(b"burned", b"2"))
        .expect_err("second emit should fail");

    assert_eq!(err, EventError::TooManyEvents { max: 1, actual: 2 });
}

#[test]
fn event_buffer_enforces_attribute_count_limit() {
    let limits = EventLimits {
        max_attributes_per_event: 0,
        ..EventLimits::default()
    };
    let mut buffer = EventBuffer::new(limits);

    let err = buffer
        .emit(event(b"minted", b"10"))
        .expect_err("attribute limit should fail");

    assert_eq!(err, EventError::TooManyAttributes { max: 0, actual: 1 });
}

#[test]
fn event_buffer_enforces_event_size_limit() {
    let limits = EventLimits {
        max_event_bytes: 8,
        ..EventLimits::default()
    };
    let mut buffer = EventBuffer::new(limits);

    let err = buffer
        .emit(event(b"minted", b"10"))
        .expect_err("event size should fail");

    assert!(matches!(err, EventError::EventTooLarge { max: 8, .. }));
}

#[test]
fn event_buffer_enforces_transaction_size_limit() {
    let limits = EventLimits {
        max_transaction_event_bytes: 8,
        ..EventLimits::default()
    };
    let mut buffer = EventBuffer::new(limits);

    let err = buffer
        .emit(event(b"minted", b"10"))
        .expect_err("transaction event size should fail");

    assert!(matches!(
        err,
        EventError::TransactionEventsTooLarge { max: 8, .. }
    ));
}

#[test]
fn block_execution_output_enforces_block_size_limit() {
    let limits = EventLimits {
        max_block_event_bytes: 8,
        ..EventLimits::default()
    };
    let tx = TransactionEvents::new(0, Sha256::hash(b"tx-0"), vec![event(b"minted", b"10")])
        .expect("transaction events");

    let err = BlockExecutionOutput::with_limits(vec![tx], limits)
        .expect_err("block event size should fail");

    assert!(matches!(
        err,
        EventError::BlockEventsTooLarge { max: 8, .. }
    ));
}
