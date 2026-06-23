use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::sha256::Digest;

use crate::{
    empty_events_root, empty_receipts_root, events_root, receipts_root, transaction_receipt,
    BlockExecutionOutput, Event, EventAttribute, EventBuffer, EventEnvelope, EventError,
    EventLimits, EventSink, TransactionEvents, TransactionReceipt,
};

const TX_0_DIGEST: Digest = Digest([
    0x91, 0xf0, 0xe7, 0x15, 0x9d, 0xa2, 0x06, 0x7f, 0x58, 0x40, 0x9c, 0xc8, 0x12, 0x94, 0x57, 0xd8,
    0x10, 0xbf, 0x12, 0x4d, 0xfa, 0xa3, 0x64, 0x6a, 0x45, 0x51, 0xc1, 0xca, 0x60, 0x48, 0x36, 0x2a,
]);

const TX_1_DIGEST: Digest = Digest([
    0x04, 0x5e, 0xf5, 0x94, 0xd8, 0x1d, 0x2f, 0x21, 0x34, 0xd6, 0x11, 0x51, 0xed, 0x71, 0x26, 0x0d,
    0x8f, 0x79, 0xe6, 0x57, 0xc7, 0xcb, 0x6e, 0xd1, 0xd8, 0x93, 0x68, 0x85, 0x32, 0x01, 0x74, 0x09,
]);

const SINGLE_EVENT_ROOT: Digest = Digest([
    0x3d, 0xc2, 0xb1, 0x33, 0xb5, 0xb0, 0xd1, 0x8a, 0x73, 0x16, 0xef, 0x40, 0xe3, 0x63, 0xf4, 0xc2,
    0xa2, 0xac, 0x58, 0x75, 0x1e, 0xb0, 0x12, 0x24, 0x22, 0x30, 0x38, 0x49, 0x0c, 0xe1, 0xb3, 0xb4,
]);

const MULTIPLE_EVENTS_ROOT: Digest = Digest([
    0xe1, 0x85, 0x5b, 0x1f, 0x14, 0x0d, 0x31, 0xb9, 0x22, 0x65, 0xfe, 0x53, 0xbc, 0x6f, 0x0c, 0xb7,
    0xc8, 0xe4, 0x89, 0x8e, 0xc0, 0xfd, 0x58, 0x24, 0xe7, 0xaf, 0x53, 0x38, 0x33, 0x41, 0x5b, 0xf6,
]);

const MULTIPLE_RECEIPTS_ROOT: Digest = Digest([
    0x40, 0xa5, 0x49, 0xea, 0xd9, 0xc5, 0xc7, 0x6b, 0x9f, 0x40, 0xd3, 0xe7, 0x9c, 0x08, 0x9e, 0xc8,
    0xf7, 0xa0, 0x87, 0x28, 0x11, 0x90, 0x08, 0x97, 0xbb, 0xd5, 0x95, 0xa4, 0x25, 0x3c, 0x55, 0x5f,
]);

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

fn minted_event_codec_vector() -> &'static [u8] {
    &[
        0x05, b'c', b'o', b'i', b'n', b's', 0x06, b'm', b'i', b'n', b't', b'e', b'd', 0x00, 0x01,
        0x01, 0x06, b'a', b'm', b'o', b'u', b'n', b't', 0x02, b'1', b'0',
    ]
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
fn event_codec_uses_fixed_vector() {
    let limits = EventLimits::default();
    let original = event(b"minted", b"10");

    assert_eq!(original.encode().as_ref(), minted_event_codec_vector());
    assert_eq!(
        Event::decode_cfg(minted_event_codec_vector(), &limits).expect("decode event"),
        original
    );
}

#[test]
fn event_envelope_codec_uses_fixed_vector() {
    let limits = EventLimits::default();
    let envelope = EventEnvelope {
        tx_index: 3,
        tx_digest: TX_1_DIGEST,
        event_index: 0,
        event: event(b"minted", b"10"),
    };
    let mut expected = Vec::new();
    expected.extend_from_slice(&3u32.to_be_bytes());
    expected.extend_from_slice(&TX_1_DIGEST.0);
    expected.extend_from_slice(&0u32.to_be_bytes());
    expected.extend_from_slice(minted_event_codec_vector());

    assert_eq!(envelope.encode().as_ref(), expected.as_slice());
    assert_eq!(
        EventEnvelope::decode_cfg(expected.as_slice(), &limits).expect("decode envelope"),
        envelope
    );
}

#[test]
fn transaction_receipt_codec_uses_fixed_vector() {
    let receipt = TransactionReceipt {
        tx_index: 3,
        tx_digest: TX_1_DIGEST,
        events_root: SINGLE_EVENT_ROOT,
        event_count: 1,
    };
    let mut expected = Vec::new();
    expected.extend_from_slice(&3u32.to_be_bytes());
    expected.extend_from_slice(&TX_1_DIGEST.0);
    expected.extend_from_slice(&SINGLE_EVENT_ROOT.0);
    expected.extend_from_slice(&1u32.to_be_bytes());

    assert_eq!(receipt.encode().as_ref(), expected.as_slice());
    assert_eq!(
        TransactionReceipt::decode_cfg(expected.as_slice(), &()).expect("decode receipt"),
        receipt
    );
}

#[test]
fn event_buffer_preserves_emission_order() {
    let tx_digest = TX_0_DIGEST;
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
fn empty_transaction_events_use_empty_events_root() {
    let receipt = transaction_receipt(0, TX_0_DIGEST, &[]).expect("receipt");

    assert_eq!(receipt.event_count, 0);
    assert_eq!(receipt.events_root, empty_events_root());
}

#[test]
fn empty_block_execution_output_uses_empty_receipts_root() {
    let output = BlockExecutionOutput::new(Vec::new());

    assert_eq!(output.receipts_root, empty_receipts_root());
}

#[test]
fn event_roots_are_ordered_and_stable() {
    let tx_digest = TX_1_DIGEST;
    let minted = event(b"minted", b"10");
    let burned = event(b"burned", b"2");
    let ordered = vec![minted.clone(), burned.clone()];
    let reversed = vec![burned, minted];

    let single = events_root(3, tx_digest, &ordered[..1]).expect("single root");
    let ordered_root = events_root(3, tx_digest, &ordered).expect("ordered root");
    let reversed_root = events_root(3, tx_digest, &reversed).expect("reversed root");

    assert_eq!(single, SINGLE_EVENT_ROOT);
    assert_eq!(ordered_root, MULTIPLE_EVENTS_ROOT);
    assert_ne!(ordered_root, reversed_root);
}

#[test]
fn receipt_roots_are_ordered_and_stable() {
    let first = TransactionEvents::new(0, TX_0_DIGEST, vec![event(b"minted", b"10")]).unwrap();
    let second = TransactionEvents::new(1, TX_1_DIGEST, vec![event(b"burned", b"2")]).unwrap();

    let ordered = receipts_root(&[first.receipt, second.receipt]);
    let reversed = receipts_root(&[second.receipt, first.receipt]);

    assert_eq!(ordered, MULTIPLE_RECEIPTS_ROOT);
    assert_ne!(ordered, reversed);
}

#[test]
fn block_execution_output_computes_and_roundtrips() {
    let limits = EventLimits::default();
    let tx0 = TransactionEvents::new(0, TX_0_DIGEST, vec![event(b"minted", b"10")]).unwrap();
    let tx1 = TransactionEvents::new(1, TX_1_DIGEST, vec![event(b"transferred", b"4")]).unwrap();

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
fn transaction_events_decode_rejects_receipt_mismatch() {
    let limits = EventLimits::default();
    let output = TransactionEvents::new(0, TX_0_DIGEST, vec![event(b"minted", b"10")])
        .expect("transaction events");
    let mut encoded = output.encode().to_vec();
    encoded[3] ^= 1;

    assert!(TransactionEvents::decode_cfg(encoded.as_slice(), &limits).is_err());
}

#[test]
fn block_execution_output_decode_rejects_receipts_root_mismatch() {
    let limits = EventLimits::default();
    let tx = TransactionEvents::new(0, TX_0_DIGEST, vec![event(b"minted", b"10")])
        .expect("transaction events");
    let output = BlockExecutionOutput::new(vec![tx]);
    let mut encoded = output.encode().to_vec();
    encoded[0] ^= 1;

    assert!(BlockExecutionOutput::decode_cfg(encoded.as_slice(), &limits).is_err());
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
fn event_buffer_enforces_field_length_limits() {
    let cases = [
        (
            EventLimits {
                max_module_bytes: 4,
                ..EventLimits::default()
            },
            event(b"minted", b"10"),
            EventError::ModuleTooLarge { max: 4, actual: 5 },
        ),
        (
            EventLimits {
                max_kind_bytes: 5,
                ..EventLimits::default()
            },
            event(b"minted", b"10"),
            EventError::KindTooLarge { max: 5, actual: 6 },
        ),
        (
            EventLimits {
                max_key_bytes: 5,
                ..EventLimits::default()
            },
            event(b"minted", b"10"),
            EventError::KeyTooLarge { max: 5, actual: 6 },
        ),
        (
            EventLimits {
                max_value_bytes: 1,
                ..EventLimits::default()
            },
            event(b"minted", b"10"),
            EventError::ValueTooLarge { max: 1, actual: 2 },
        ),
    ];

    for (limits, event, expected) in cases {
        let mut buffer = EventBuffer::new(limits);
        assert_eq!(
            buffer.emit(event).expect_err("field limit should fail"),
            expected
        );
    }
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
    let tx = TransactionEvents::new(0, TX_0_DIGEST, vec![event(b"minted", b"10")])
        .expect("transaction events");

    let err = BlockExecutionOutput::with_limits(vec![tx], limits)
        .expect_err("block event size should fail");

    assert!(matches!(
        err,
        EventError::BlockEventsTooLarge { max: 8, .. }
    ));
}

#[test]
fn block_execution_output_enforces_transaction_count_limit() {
    let limits = EventLimits {
        max_transactions_per_block: 0,
        ..EventLimits::default()
    };
    let tx = TransactionEvents::new(0, TX_0_DIGEST, vec![event(b"minted", b"10")])
        .expect("transaction events");

    let err = BlockExecutionOutput::with_limits(vec![tx], limits)
        .expect_err("transaction count should fail");

    assert_eq!(err, EventError::TooManyTransactions { max: 0, actual: 1 });
}
