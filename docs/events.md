# Runtime Events Implementation Plan

## Goal

Add a runtime/module event API so modules can emit standardized events during
transaction execution. The first slice publishes finalized event batches to an
indexer boundary. It does not add consensus commitments, a durable archive,
historical queries, or event RPC.

`coins/src/rpc.rs` remains current-state RPC for `coins.nonce`, `coins.token`,
`coins.balance`, and `coins.state_root`.

## Non-Goals

* Do not add `receipts_root` or event commitments to `Block`.
* Do not change block digest or block codec formats.
* Do not reject blocks based on emitted events.
* Do not make events consensus-provable.
* Do not implement a durable indexer, archive, historical query API, or event
  RPC.

## Principles

* Events are local finalized execution output, not consensus state.
* State transition validity continues to depend only on deterministic execution
  and the block state commitment.
* `validate` stays event-free because proposal validation is speculative.
* Failed transaction execution discards any events emitted before the error.
* Module crates can define and emit events without depending on `nunchi-chain`.
* Event metadata must be stable enough for external indexers to consume
  idempotently.

## Event Model

Put shared event primitives near the runtime abstraction, likely in
`common/src/events.rs`, and re-export them from `common/src/lib.rs`.

```rust
pub struct Event {
    pub name: Bytes,
    pub value: Bytes,
}

pub trait EventSink {
    fn emit(&mut self, event: Event);
}

pub struct NoopEventSink;
pub struct VecEventSink;
```

`value` is opaque bytes. Consumers decode it according to the schema identified
by `name`. Event names should be stable namespaced bytes such as
`coins.transferred.v1`.

First-party event payloads should use existing deterministic binary encodings.
Other encodings, including JSON, are out of scope for the first slice and should
only be introduced later under explicitly versioned event names.

Keep `emit` infallible so event collection cannot turn a valid transaction into
an invalid one. The first slice does not add event-specific collection limits;
revisit limits if events become durable, remotely queryable, or user-controlled
in size.

## Runtime API

Update `nunchi_common::Runtime` in `common/src/runtime.rs` so only apply-side 
execution receives an event sink.

```rust
fn apply<S, Events>(
    state: &mut S,
    context: RuntimeContext,
    transaction: &Self::Transaction,
    events: &mut Events,
) -> impl Future<Output = Result<(), Self::Error>> + Send
where
    S: StateStore + Send + Sync,
    Events: EventSink + Send;
```

Use `NoopEventSink` in paths that do not need event output.

## Chain Application

Update `chain/src/application.rs` in three paths.

1. Proposal construction:
   * Keep `build_valid_transactions` on `R::validate`.
   * Continue discarding the overlay when a candidate fails.

2. Verification:
   * Execute with `NoopEventSink`.
   * Keep verification limited to deterministic execution, `state_root`, and
     `state_range`.

3. Finalized apply:
   * Add an execution helper that collects events per transaction.
   * During certified block apply, collect the block and transaction metadata
     needed by `FinalizedEvents`.
   * Publish events only after the commonware stateful actor finalizes the
     database batch and calls `Application::finalized`.

Because the commonware `Application::apply` hook returns only a merkleized
database batch, use an internal handoff:

* store collected event batches in an in-memory map keyed by block digest
* in `Application::finalized`, remove the batch for that digest and report it
* if finalization replays a block after restart and no batch exists, report no
  events for that block

This first release is live-only. Indexers that need complete history must stay
online for finalized reports or wait for a later archive/backfill
implementation.

## Finalized Event Batch

Add chain-level event metadata types, likely in `chain/src/events.rs`.

```rust
pub struct FinalizedEvents {
    pub height: Height,
    pub block_digest: Digest,
    pub block_timestamp: u64,
    pub transactions: Vec<TransactionEvents>,
}

pub struct TransactionEvents {
    pub tx_index: u32,
    pub tx_digest: Digest,
    pub events: Vec<IndexedEvent>,
}

pub struct IndexedEvent {
    pub event_index: u32,
    pub event: Event,
}
```

External indexers can use this idempotency key:

```text
(height, block_digest, tx_index, event_index)
```

Do not use transaction digest alone as the event key because one transaction can
emit multiple events.

## Indexer Boundary

Add a minimal reporter trait in `nunchi-chain`:

```rust
pub trait EventReporter: Clone + Send + Sync + 'static {
    fn finalized_events(
        &self,
        events: FinalizedEvents,
    ) -> impl Future<Output = ()> + Send;
}
```

Provide `NoopEventReporter` and an in-memory reporter for tests. Thread the
reporter into `Application` construction with a default noop constructor so
existing chains do not need custom event handling.

```text
finalized block apply -> FinalizedEvents -> EventReporter -> indexer/archive/RPC
```

## Module Events

Implementing module-specific events is out of scope for this plan. Module crates
can adopt the runtime event sink in a later slice by defining event constructors
near ledger logic, not in RPC.

Example coins event names:

* `coins.account_policy_registered.v1`
* `coins.token_created.v1`
* `coins.minted.v1`
* `coins.burned.v1`
* `coins.transferred.v1`

An implementation that adds one of these events should document the payload type
and encoding in the module, then pass the sink from the runtime into the ledger:

```text
Transaction::Coin -> Ledger::apply_transaction(..., events)
```

This document does not require implementing those event constructors or changing
module transaction execution.

## Tests

Unit tests:

* `VecEventSink` records events in order.
* `NoopEventSink` accepts events without observable side effects.
* failed transaction execution discards collected events.

Runtime/application tests:

* proposal validation includes the same valid transactions as before.
* verification ignores event output and still rejects state root mismatches.
* finalized apply reports events only after the database is finalized.
* transaction and event indexes are stable and ordered.
* replay/finalization after a missing in-memory batch reports no events.

Compatibility tests:

* existing coins RPC tests still pass.
* existing mempool status behavior is unchanged.
* block encode/decode and digest tests are unchanged.

## Implementation Order

1. Add shared event primitives and sinks in `nunchi-common`.
2. Update the `Runtime` trait and all runtime implementations to accept a sink
   in `apply`.
3. Thread `NoopEventSink` through verification and non-reporting apply paths.
4. Add finalized event collection, event batch metadata, and `EventReporter` in
   `nunchi-chain`.
5. Add focused tests for event ordering, discard-on-failure, and finalized
   reporting.
6. Revisit module events, durable archive/RPC/indexer scope, and historical
   backfill as separate tasks.
