//! Runtime event primitives.
//!
//! # Status
//!
//! Events are local execution output for finalized processing. They are not consensus state and
//! are not committed to a block digest.
//!
//! # Examples
//!
//! ```
//! use bytes::Bytes;
//! use nunchi_common::{Event, EventSink, VecEventSink};
//!
//! let mut sink = VecEventSink::new();
//! sink.emit(Event::new(
//!     Bytes::from_static(b"coins.transferred.v1"),
//!     Bytes::from_static(b"payload"),
//! ));
//!
//! assert_eq!(sink.events().len(), 1);
//! ```

use bytes::Bytes;

/// Opaque event data emitted by runtime execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    /// Stable namespaced event identifier, for example `coins.transferred.v1`.
    pub name: Bytes,
    /// Event payload encoded according to the schema identified by `name`.
    pub value: Bytes,
}

impl Event {
    /// Create an event from name and value bytes.
    pub fn new(name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Infallible event collector used during transaction execution.
pub trait EventSink {
    /// Emit an event.
    fn emit(&mut self, event: Event);
}

impl<T: EventSink + ?Sized> EventSink for &mut T {
    fn emit(&mut self, event: Event) {
        (**self).emit(event);
    }
}

/// Event sink that discards all events.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn emit(&mut self, _: Event) {}
}

/// Event sink that stores emitted events in order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VecEventSink {
    events: Vec<Event>,
}

impl VecEventSink {
    /// Create an empty vector-backed event sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the events emitted so far.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Consume the sink and return the emitted events.
    pub fn into_events(self) -> Vec<Event> {
        self.events
    }

    /// Return the number of events emitted so far.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Return true when no events have been emitted.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl EventSink for VecEventSink {
    fn emit(&mut self, event: Event) {
        self.events.push(event);
    }
}
