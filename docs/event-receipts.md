# Consensus-Committed Runtime Events

Status: design proposal

This document describes a design for adding a runtime event API to Nunchi SDK
chains. The goal is to let custom modules emit standardized events that
indexers, explorers, and downstream services can consume, while also committing
the event output in consensus through a block-level receipts root.

The proposal is intentionally split into two parts:

- A developer-facing event API for runtimes and modules.
- A consensus-facing receipt commitment that makes emitted events provable.

## Goals

- Let runtime modules emit structured events during deterministic transaction
  execution.
- Commit successful transaction events into each block using a `receipts_root`.
- Let validators reject a block if replayed events do not match the proposed
  `receipts_root`.
- Keep full events out of the consensus block body to avoid increasing block
  propagation size.
- Provide a stable finalized event stream for indexers.
- Keep protocol crates runtime-agnostic and compatible with commonware's
  deterministic testing model.

## Non-Goals

- Do not add a JSON event format to consensus commitments.
- Do not commit tracing logs, metrics, or node-local diagnostics.
- Do not add failed transaction receipts in the first version. Current Nunchi
  blocks only include transactions that execute successfully.
- Do not make indexer configuration part of consensus. Indexers can decide which
  event keys to index locally.

## Prior Art

Ethereum provides the closest commitment model. Solidity events are EVM logs in
transaction receipts, and each block header commits to those receipts through a
receipts root. The full logs are not part of the transaction list, but a light
client can verify logs against the committed block header.

Aptos also commits transaction outputs. Each transaction info includes an
`event_root_hash`, which makes the event list for that transaction provable
against ledger state.

Cosmos SDK has the best module ergonomics. Modules emit events through a
context-carried event manager, with typed event helpers on top of key-value
events. Cosmos is not the best commitment model to copy directly because
CometBFT result events have historically been for indexing and subscription
rather than a clean application-level receipt root. The API shape is still a
good reference.

Sui is useful as an indexing model. It exposes finalized checkpoints,
transaction effects, and events as a stable stream for off-chain consumers. The
lesson for Nunchi is that finalized delivery and backfill matter as much as the
root in the block.

Alto is useful as a commonware example for archival and indexer-style reporting,
but it indexes consensus artifacts rather than runtime module events.

References:

- Ethereum blocks and receipts root: https://ethereum.org/developers/docs/blocks/
- Ethereum receipt trie background: https://ethereum.org/developers/docs/data-structures-and-encoding/patricia-merkle-trie/
- Aptos transaction output/event root types: https://github.com/aptos-labs/aptos-core/blob/main/api/types/src/transaction.rs
- Sui transaction lifecycle and checkpoints: https://docs.sui.io/develop/transactions/transaction-lifecycle
- Cosmos SDK event service: https://github.com/cosmos/cosmos-sdk/blob/main/core/event/service.go
- Cosmos SDK event manager: https://github.com/cosmos/cosmos-sdk/blob/main/types/events.go
- Cosmos SDK BaseApp event handling: https://github.com/cosmos/cosmos-sdk/blob/main/baseapp/baseapp.go
- CometBFT data structures: https://github.com/cometbft/cometbft/blob/main/spec/core/data_structures.md
- Alto indexer README: https://github.com/commonwarexyz/alto/blob/main/indexer/README.md

## Current Nunchi Surface

The runtime abstraction currently lives in `common/src/runtime.rs`, not in the
`chain` crate. It exposes `Runtime::validate` and `Runtime::apply`, both of
which return `Result<(), Runtime::Error>`.

The chain application in `chain/src/application.rs` has three execution paths:

- `build_valid_transactions` executes mempool candidates against an overlay
  during proposal construction.
- `execute_block` executes all block transactions during verification and local
  apply.
- `finalized` updates applied height and informs the mempool after a block is
  finalized.

The block type in `chain/src/block.rs` currently commits to:

- consensus context
- parent digest
- height
- timestamp
- runtime transactions
- optional reshare log
- consensus extension payload
- `state_root`
- `state_range`

There is no execution output object and no receipt or event commitment.

## Core Decision

Add a block-level `receipts_root` and make it part of the block digest.

Validators must deterministically re-execute the block, reconstruct transaction
receipts, compute `receipts_root`, and reject the block if it differs from the
root in the block.

Full event payloads should not be placed in the block. Nodes that execute a
block can store and publish the finalized event output separately. Indexers can
verify that output against the committed `receipts_root`.

## Data Model

Event types should live in `nunchi-common` or a small shared crate re-exported
by `nunchi-common`. Module crates such as `coins` and `authority` should not
depend on `nunchi-chain`.

Suggested core types:

```rust
pub struct Event {
    pub module: Bytes,
    pub kind: Bytes,
    pub version: u16,
    pub attributes: Vec<EventAttribute>,
}

pub struct EventAttribute {
    pub key: Bytes,
    pub value: Bytes,
}

pub struct EventEnvelope {
    pub tx_index: u32,
    pub tx_digest: Digest,
    pub event_index: u32,
    pub event: Event,
}

pub struct TransactionReceipt {
    pub tx_index: u32,
    pub tx_digest: Digest,
    pub events_root: Digest,
    pub event_count: u32,
}

pub struct BlockExecutionOutput {
    pub receipts_root: Digest,
    pub transactions: Vec<TransactionEvents>,
}

pub struct TransactionEvents {
    pub receipt: TransactionReceipt,
    pub events: Vec<Event>,
}
```

The exact field types can be adjusted to match `commonware_codec` support, but
the consensus encoding must be binary and stable. Do not commit JSON, `Debug`
strings, or display-formatted numbers.

Recommended naming rules:

- `module` is a short ASCII namespace such as `coins` or `authority`.
- `kind` is a short ASCII event name such as `transfer` or `proposal_approved`.
- `version` starts at `1` and changes only when the event schema changes.
- attribute keys are short ASCII names.
- attribute values are canonical bytes for the underlying type.

Indexers should identify fields by `(module, kind, version, key)`.

## Event API

Use an event sink passed through deterministic execution.

```rust
pub trait EventSink {
    fn emit(&mut self, event: Event) -> Result<(), EventError>;
}

pub struct EventBuffer {
    limits: EventLimits,
    events: Vec<Event>,
}

pub struct NoopEventSink;
```

The runtime trait should change shape roughly like this:

```rust
pub trait Runtime {
    type Transaction: Clone + EncodeSize + Read<Cfg = ()> + Write + Send + Sync + 'static;
    type Error: std::error::Error + Send + Sync + 'static;

    fn validate<S, Events>(
        state: &mut S,
        events: &mut Events,
        context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        S: StateStore + Send + Sync,
        Events: EventSink + Send;

    fn apply<S, Events>(
        state: &mut S,
        events: &mut Events,
        context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        S: StateStore + Send + Sync,
        Events: EventSink + Send;

    fn is_storage_error(error: &Self::Error) -> bool;
}
```

`validate` and `apply` must emit identical events for the same
`state + context + transaction` input. This is already close to how the example
coins chain works: both methods dispatch to the same `apply_transaction`
function.

`EventSink::emit` should return an `EventError` when event limits are exceeded.
Module error enums should wrap this error and classify it as deterministic
transaction invalidity, not storage failure.

## Receipt Root Construction

Root construction must be order-preserving and domain-separated.

Suggested rules:

1. For each successful transaction, collect events in emission order.
2. Wrap each event in an `EventEnvelope` containing `tx_index`, `tx_digest`, and
   `event_index`.
3. Compute `events_root` as an ordered Merkle root over encoded
   `EventEnvelope` values.
4. Build a `TransactionReceipt` containing the transaction index, transaction
   digest, events root, and event count.
5. Compute `receipts_root` as an ordered Merkle root over encoded
   `TransactionReceipt` values.
6. Store `receipts_root` in the block and include it in the block digest.

Use separate hash domains for each level, for example:

- `nunchi:event-leaf:v1`
- `nunchi:event-node:v1`
- `nunchi:event-root:v1`
- `nunchi:receipt-leaf:v1`
- `nunchi:receipt-node:v1`
- `nunchi:receipt-root:v1`

The root function should include the item count in the final root hash. This
avoids ambiguity between different ordered lists that reduce to the same tree
shape.

Empty roots must be specified with fixed test vectors:

- empty transaction events produce the empty `events_root`
- empty block transactions produce the empty `receipts_root`
- the genesis block uses the empty `receipts_root`

## Block Changes

Add `receipts_root: Digest` to `chain::Block`.

It must be included in:

- `Block` fields
- `Clone`
- `PartialEq`
- `compute_digest`
- `Block::new`
- `Write`
- `Read`
- `EncodeSize`
- genesis block construction
- block tests and codec tests

This is a consensus and wire-format change. If there are already live networks,
it needs an activation height or a network reset. If there are no live networks,
the simpler path is to change the block codec directly and update all tests.

## Execution Flow

Proposal construction:

1. Create a per-transaction `EventBuffer`.
2. Execute each mempool candidate with `Runtime::validate` against the overlay.
3. If execution succeeds, commit the overlay, retain the transaction, and retain
   the event buffer.
4. If execution fails with deterministic invalidity, discard both state changes
   and emitted events.
5. If execution fails with storage failure, abort proposal construction.
6. After selected transactions are known, merkleize state and compute
   `receipts_root`.
7. Create the block with both `state_root` and `receipts_root`.
8. Cache the full execution output by block digest for later finalized
   publishing.

Verification:

1. Check timestamp, transaction count, and transaction signatures as today.
2. Execute the block transactions with `Runtime::apply`, collecting events.
3. Merkleize state and compute `state_range`.
4. Compute `receipts_root`.
5. Reject the block if `state_root`, `state_range`, or `receipts_root` differs
   from the block.
6. Cache the full execution output by block digest.

Apply:

1. Execute the certified block with `Runtime::apply`, collecting events.
2. Assert `state_root`, `state_range`, and `receipts_root`.
3. Cache the full execution output by block digest.

Finalized:

1. Remove the cached output for the finalized block digest.
2. Publish or persist the finalized event batch.
3. Update applied height and finalize mempool transactions as today.

The cache is needed because commonware's stateful application hooks return only
the merkleized state from proposal, verification, and apply. They do not pass an
application-specific execution output to `finalized`.

If a block reaches `finalized` without cached output, that is an internal logic
bug. The implementation should make this visible with a hard failure in tests
and an operator-visible error path in production.

## Finalized Event Output

Indexers need a standardized finalized batch, not just a root.

Suggested finalized output:

```rust
pub struct FinalizedEvents {
    pub height: Height,
    pub block_digest: Digest,
    pub block_timestamp: u64,
    pub receipts_root: Digest,
    pub transactions: Vec<TransactionEvents>,
}
```

This batch can be consumed by:

- an in-process reporter
- an append-only local archive
- an RPC method
- a WebSocket or stream endpoint
- an external indexer process

The first implementation can use a no-op reporter to keep consensus changes
small, but a complete product should persist finalized event batches. Without a
durable event archive, an indexer cannot reliably backfill events after a node
restart unless the node can replay historical blocks from the required
pre-state.

Event proofs can be added on top of the same data:

1. prove an event against its transaction `events_root`
2. prove the transaction receipt against the block `receipts_root`
3. prove the block digest through the normal finalization proof

## Event Limits

Events are consensus output, so limits must be deterministic and enforced during
execution.

Recommended initial limits:

- maximum events per transaction
- maximum attributes per event
- maximum bytes per event
- maximum bytes per transaction event output
- maximum bytes per block event output
- maximum module, kind, and key lengths

The exact constants should be chosen during implementation and covered by
tests. Exceeding a limit should make the transaction invalid. It should not
truncate events.

## Determinism Rules

Event emission is consensus-critical once `receipts_root` is part of the block.
Adding, removing, reordering, or changing event fields changes block validity.

Modules must follow these rules:

- emit events only from deterministic execution paths
- emit events in a stable order
- never depend on map iteration order unless keys are sorted first
- never include local wall clock time, local node identity, random values, logs,
  metrics, or storage backend details
- never use `Display`, `Debug`, JSON, or locale-sensitive formatting for
  committed values
- use canonical binary encodings for amounts, account IDs, coin IDs, validator
  IDs, proposal IDs, and epochs
- treat event schema changes as state-machine changes

## Module Event Schemas

Each module should define typed event constructors near its ledger code. The
constructors should be the only place that maps domain values into generic
`Event` values.

Example coins events:

- `coins.account_policy_registered.v1`
- `coins.token_created.v1`
- `coins.minted.v1`
- `coins.burned.v1`
- `coins.transferred.v1`

Example authority events:

- `authority.configured.v1`
- `authority.proposal_created.v1`
- `authority.proposal_approved.v1`
- `authority.proposal_executed.v1`
- `authority.validator_added.v1`
- `authority.validator_removed.v1`

The schema for each event should document:

- event kind and version
- attribute keys
- value encodings
- when the event is emitted
- whether the event replaces or complements another event

## Suggested Implementation Plan

1. Add event primitives to `nunchi-common`.
   - Add `Event`, `EventAttribute`, `EventSink`, `EventBuffer`, `EventLimits`,
     `EventError`, `TransactionReceipt`, and execution output types.
   - Implement stable `commonware_codec` encoding.
   - Add root utilities for `events_root` and `receipts_root`.

2. Add commitment tests before wiring the chain.
   - Empty events root.
   - Empty receipts root.
   - Single event root.
   - Multiple events preserve order.
   - Multiple receipts preserve order.
   - Fixed vectors for codec and root values.
   - Limit enforcement tests.

3. Change the `Runtime` trait.
   - Add an `EventSink` parameter to `validate` and `apply`.
   - Update example runtimes to pass the sink through dispatch.
   - Add `NoopEventSink` for paths that intentionally do not collect events.

4. Wire `nunchi-chain` execution.
   - Update proposal construction to collect per-transaction events.
   - Update verification and apply to compute receipts.
   - Add `receipts_root` mismatch rejection.
   - Add execution-output cache keyed by block digest.

5. Add `receipts_root` to `Block`.
   - Include it in digest and codec.
   - Update genesis block construction.
   - Update block tests.

6. Add module events.
   - Start with `coins` and `authority` because the example chain uses both.
   - Keep event schemas minimal and stable.
   - Add ledger tests that assert emitted event content.

7. Add finalized event reporting.
   - Add a no-op default reporter.
   - Add a trait or handle that receives `FinalizedEvents`.
   - Publish only after finalization.
   - Keep reporter failures separate from deterministic execution failures.

8. Add integration tests.
   - A valid proposed block includes the expected `receipts_root`.
   - Verification rejects a block with a modified `receipts_root`.
   - Failed mempool candidates discard emitted events.
   - Re-executing the same block produces the same receipts root.
   - Finalized blocks publish exactly one finalized event batch.
   - Crash/recovery paths do not lose finalized event output in supported
     configurations.

9. Add archive and RPC support.
   - Store finalized event batches by height, block digest, transaction digest,
     and event key.
   - Add query and stream endpoints for indexers.
   - Add inclusion proof support when needed.

## Difficulty

This is a medium-high difficulty task.

The event data types are straightforward. The harder parts are:

- changing the `Runtime` trait without making module APIs awkward
- making events consensus-critical without introducing nondeterminism
- updating block digest and codec safely
- ensuring all execution paths compute identical receipts
- preserving event output until finalization
- testing replay, invalid blocks, discarded mempool candidates, and recovery

The safest implementation shape is several small PRs: primitives and root tests
first, runtime trait second, chain/block commitment third, module events fourth,
and finalized reporting/archive last.

## Open Questions

- Is there any live network or persisted testnet data that requires a protocol
  upgrade path?
- Should the first implementation include durable event archive storage, or only
  the consensus commitment plus no-op reporter?
- Should consensus extension payloads and DKG resharing emit system events, or
  should version 1 include only runtime transaction events?
- Which exact event limits are acceptable for the expected finance workloads?
- Do indexers need inclusion proofs in the first release, or is root commitment
  plus finalized batch delivery enough initially?
