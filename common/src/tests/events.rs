use bytes::Bytes;

use crate::{Event, EventSink, NoopEventSink, VecEventSink};

#[test]
fn vec_event_sink_records_events_in_order() {
    let first = Event::new(
        Bytes::from_static(b"coins.minted.v1"),
        Bytes::from_static(b"mint"),
    );
    let second = Event::new(
        Bytes::from_static(b"coins.transferred.v1"),
        Bytes::from_static(b"transfer"),
    );
    let mut sink = VecEventSink::new();

    sink.emit(first.clone());
    sink.emit(second.clone());

    assert_eq!(sink.len(), 2);
    assert_eq!(sink.events(), &[first.clone(), second.clone()]);
    assert_eq!(sink.into_events(), vec![first, second]);
}

#[test]
fn vec_event_sink_starts_empty() {
    let sink = VecEventSink::default();

    assert!(sink.is_empty());
    assert!(sink.events().is_empty());
}

#[test]
fn noop_event_sink_accepts_events() {
    let mut sink = NoopEventSink;

    sink.emit(Event::new(
        Bytes::from_static(b"coins.burned.v1"),
        Bytes::from_static(b"burn"),
    ));
}
