# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Repository Overview

The Nunchi SDK is an easy-to-use modular blockchain framework offering financial primitives for commonware-based chains. The heart of the framework can be found in the [`nunchi-coins`](coins/) crate. The repo is organized as a Cargo workspace with many primitives that build on each other.

A chain built with the Nunchi SDK adopts our coin model, account model, dkg resharing, and bridging setup. The SDK is handcrafted for the requirements of specialized low-latency finance.

## Essential Commands

### Quick Reference

```bash
# Build entire workspace
cargo build --workspace --all-targets

# Run tests 
just test

# Run linter + unused deps
just check
```

## Architecture

### Core Primitives

* [`coins`](coins/) - defines what a coin and account are. Also contains other basic financial functions
* [`crypto`](crypto/) - defines key primitives and wrappers around commonware cryptographic primitives
* [`rpc`](rpc/) - core abstractions for modular RPC
* `bridge` - moves coins between chains
* `oracle` - takes in price feeds and provides them to other modules
* `chat` - allows humans or agents to publish to permanent on-chain public conversations
* `factory` - wrapper of coins for mass issuance 

### Network Infrastructure 

* [`authority`](authority/) - provides a proof of authority setup for a chain
* [`dkg`](dkg/) - contains dkg resharing ceremony logic and a consensus engine orchestator
* [`mempool`](mempool/) contains a node-local mempool for chains
* `pos` - provides a proof of stake security setup for a chain

### Financial Primitives

* `margin` - user has BTC + nunchi and doesn't want to sell, and deposits BTC+nunchi and gets a stablecoin.  Could be backed by other coins, not just btc and nunchi. 
* `securities` - Non-synthetic perps contracts (delivery of tokenized stock)
* `vaults` - a module for running vaults composed of many types of capital, traded by an authorised offchain party
* `clob` - used on the global chain, provides liquidity between local chain tokens
* `derivatives` - ingests a price feed and creates derivatives products
* `stablecoin` - a wrapper of coins special for the needs of stablecoins

_All workspace crates can be found in the [Cargo.toml](Cargo.toml) file (anything with a `nunchi-` prefix)._


### Key Design Principles

1. **The Simpler The Better**: Code should look obviously correct and contain the minimum features necessary to achieve a goal.
2. **Test Everything**: All code should be designed for deterministic and comprehensive testing. We employ an abstract runtime from commonware commonly in the repository to drive tests.
3. **Performance Sensitive**: All primitives are optimized for high throughput/low latency.
4. **Adversarial Safety**: All primitives are designed to operate robustly in adversarial environments.
5. **Abstract Runtime**: Protocol primitives should stay runtime-agnostic. Do not introduce direct `tokio` usage unless the crate already owns a runtime integration or command-line runtime path. When requiring some `runtime`, use the provided traits from commonware.
6. **Always Commit Complete Code**: When implementing code and writing tests, always implement complete functionality. If there is a large task, implement the simplest possible solution that works and then incrementally improve it.
7. **Own Core Mechanisms**: If a primitive relies heavily on some core mechanism/algorithm, we should implement it rather than relying on external crates.

## Reviewing PRs

When reviewing PRs, focus the majority of your effort on correctness and style. Pay special attention to bugs that can be caused by malicious participants when a function accepts untrusted input. This repository is designed to be used in adversarial environments, and as such, we should be extra careful to ensure that the code is robust.

## Deterministic Async Testing

Exclusively use commonware's deterministic runtime for reproducible async tests:
```rust
#[test]
fn test_async_behavior() {
    let executor = deterministic::Runner::seeded(42); // Use seed for reproducibility
    executor.start(|context| async move {
        // Spawn actors with child contexts for metrics and debugging
        let handle = context.child("worker").spawn(|context| async move {
            // Actor logic here
            context.sleep(Duration::from_secs(1)).await;
        });

        // Control time explicitly
        context.sleep(Duration::from_millis(100)).await;

        // Use commonware_macros::select! for timeouts
        select! {
            result = handle => { /* handle result */ },
            _ = context.sleep(Duration::from_secs(5)) => panic!("timeout"),
        }
    });
}
```


### Advanced Testing Patterns

#### Test Configuration

```rust
// Use deterministic::Config for precise control
let cfg = deterministic::Config::new()
    .with_seed(seed)
    .with_timeout(Some(Duration::from_secs(30)));
let executor = deterministic::Runner::new(cfg);

// Or use timed runner for simpler tests
let executor = deterministic::Runner::timed(Duration::from_secs(30));
```

#### Stateful Recovery Testing

```rust
// Test unclean shutdowns and recovery
let mut checkpoint = None;
loop {
    let runner = if let Some(checkpoint) = checkpoint.take() {
        deterministic::Runner::from(checkpoint) // Resume from previous state
    } else {
        deterministic::Runner::timed(Duration::from_secs(30))
    };

    let (complete, next_checkpoint) = runner.start_and_recover(f);

    if complete { break; }
    checkpoint = Some(next_checkpoint); // Save state for next iteration
}
```

#### Deterministic RNG

Use `commonware_utils::test_rng()` for random number generation in tests:
```rust
let mut rng = test_rng();
let key = PrivateKey::random(&mut rng);
```

When you need multiple independent RNG streams in the same test (e.g., to generate
non-overlapping keys), use `test_rng_seeded(seed)`:
```rust
let mut rng1 = test_rng();           // Stream 1: seed 0
let mut rng2 = test_rng_seeded(1);   // Stream 2: seed 1
```

Avoid `OsRng`, `StdRng::from_entropy()`, or raw `StdRng::seed_from_u64()`.
Exceptions: fuzz tests deriving seed from input, or loops testing multiple seeds.

### Simulated Network Testing

To simulate network operations, use the commonware simulated network:
```rust
let (network, mut oracle) = Network::new(
    context.child("network"),
    Config {
        max_size: 1024 * 1024,
        disconnect_on_block: true,
        tracked_peer_sets: NZUsize!(1),
    },
);
network.start();

// Register multiple channels per peer for different message types
let (vote_sender, vote_receiver) = oracle.register(pk, 0).await.unwrap();
let (certificate_sender, certificate_receiver) = oracle.register(pk, 1).await.unwrap();
let (resolver_sender, resolver_receiver) = oracle.register(pk, 2).await.unwrap();

// Configure network links with realistic conditions
oracle.add_link(pk1, pk2, Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(3),
    success_rate: 0.95, // 95% success
}).await.unwrap();
```

#### Dynamic Network Conditions

```rust
// Test network partitions
fn separated(n: usize, a: usize, b: usize) -> bool {
    let m = n / 2;
    (a < m && b >= m) || (a >= m && b < m)
}
link_validators(&mut oracle, &validators, Action::Unlink, Some(separated)).await;

// Update links dynamically
let degraded_link = Link {
    latency: Duration::from_secs(3), // Simulate slow network
    jitter: Duration::from_millis(0),
    success_rate: 1.0,
};
oracle.update_link(pk1, pk2, degraded_link).await.unwrap();

// Test with lossy networks
let lossy_link = Link {
    latency: Duration::from_millis(200),
    jitter: Duration::from_millis(150),
    success_rate: 0.5, // 50% packet loss
};
```

### Byzantine Testing Patterns

```rust
// Test Byzantine actors by replacing normal participants
if idx_scheme == 0 {
    // Create Byzantine actor instead of normal engine
    let cfg = mocks::conflicter::Config { /* ... */ };
    let engine = mocks::conflicter::Conflicter::new(context, cfg);
    engine.start(pending);
} else {
    // Normal honest participant
    let engine = Engine::new(context, cfg);
    engine.start(pending, recovered, resolver);
}

// Verify Byzantine behavior is detected
let blocked = oracle.blocked().await.unwrap();
assert!(!blocked.is_empty()); // Byzantine nodes should be blocked
```

### Verification Patterns

```rust
// Use supervisors to monitor and verify distributed behavior
let supervisor = mocks::supervisor::Supervisor::new(config);
let (mut latest, mut monitor) = supervisor.subscribe().await;

// Wait for progress with explicit monitoring
while latest < required_containers {
    latest = monitor.next().await.expect("event missing");
}

// Verify no Byzantine faults occurred
let faults = supervisor.faults.lock().unwrap();
assert!(faults.is_empty());

// Verify determinism across runs
let state1 = slow_and_lossy_links::<MinPk>(seed);
let state2 = slow_and_lossy_links::<MinPk>(seed);
assert_eq!(state1, state2); // Must be deterministic with same seed
```

### Key Testing Patterns

- **Determinism First**: Always verify tests are deterministic with `context.auditor().state()`
- **Label Everything**: Use `context.child("role")` for all actors and spawned tasks; use `with_attribute()` for dynamic dimensions
- **Multi-Channel Testing**: Register multiple channels per peer for different message types
- **Progressive Degradation**: Start with ideal conditions, then introduce failures
- **Byzantine Simulation**: Replace honest nodes with Byzantine actors to test fault tolerance
- **State Recovery**: Test crash recovery by saving and restoring context state
- **Network Partitions**: Simulate split-brain scenarios with selective link removal
- **Metric Verification**: Use supervisors, monitors, or metric output to verify distributed properties. For task shutdown checks, assert the selected task prefix is non-zero before shutdown, then assert the same prefix is zero after shutdown.


## Code Style Guide

### Runtime Isolation Rule

**CRITICAL**: Protocol primitives should remain runtime-agnostic:
- Do not introduce direct `tokio` usage in protocol crates unless the module is explicitly runtime-specific, a benchmark, a chain example, or a test.
- Existing runtime-owning crates and paths such as `examples` may use `tokio` where that is already part of their contract.
- Prefer `futures` for async operations in runtime-agnostic code.
- Use capabilities exported by `runtime` traits for I/O operations.
- This keeps primitives portable across different runtime implementations.

### Error Handling

Use `thiserror` for all error types:
```rust
#[derive(Error, Debug)]
pub enum Error {
    #[error("descriptive message: {0}")]
    VariantWithContext(String),

    #[error("validation failed: Context({0}), Message({1})")]
    ValidationError(&'static str, &'static str),

    #[error("wrapped: {0}")]
    Wrapped(#[from] OtherError),
}
```

### Documentation

- Use `//!` for module-level docs with Status and Examples sections
- Use `///` for public items with clear descriptions
- Include `# Examples` sections for public APIs
- Document `# Safety` for any unsafe code usage
- Place explanatory comments above the logical code block they describe; do not split a single consecutive sequence with inline comments between adjacent lines.
- Only use characters that can be easily typed. For example, don't use em dashes or arrows.
- Do not describe trait implementations on the trait definition (e.g., "For production runtimes, this does X. For deterministic testing, this does Y."). These comments become stale as implementations change. Document what the trait does, not how specific implementations behave.
- Do not write comments that sound unnatural, out of place, or overly verbose outside the context of the changes being made. For example, if you edit a function to call foo() instead of bar(), don't add a comment "// Used to call bar() here".

### Naming Conventions

- **Types**: `PascalCase` (e.g., `PublicKey`, `SignatureSet`)
- **Functions/methods**: `snake_case` (e.g., `verify_signature`, `from_bytes`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `MAX_MESSAGE_SIZE`)
- **Traits**: Action-oriented names (`Signer`, `Verifier`) or `-able` suffix (`Viewable`)

_Generally, we try to minimize the length of functions and variables._

### Trait Patterns

```rust
// Comprehensive trait bounds
pub trait PublicKey: Verifier + Sized + ReadExt + Encode + PartialEq + Array {}

// Extension traits for additional functionality
pub trait PrivateKeyExt: PrivateKey {
    fn from_rng<R: CryptoRngCore>(rng: &mut R) -> Self;
}
```

### Async Code

- Use `async-trait` for async trait methods
- Utilize `commonware_macros::select!` for concurrent operations

### Test Organization

Put tests in a `tests/mod.rs` file under a crate's `src` directory.

### Module Structure

- Keep `mod.rs` minimal with re-exports
- Use `cfg_if!` for platform-specific code
- Always place imports at the top of a module (never inline within functions)

```rust
// BAD - inline import inside function
fn foo() -> usize {
    use crate::Bar;
    Bar::get()
}

// GOOD - import at module top
use crate::Bar;

fn foo() -> usize {
    Bar::get()
}
```

### Performance Patterns

- Prefer `Bytes` over `Vec<u8>` for zero-copy operations
- Use `Arc` for shared ownership without cloning data
- Implement `Clone` as cheaply as possible (often just `Arc` clones)
- Avoid allocations in hot paths
- Prefer static dispatch with generics over trait objects where possible
- Use `context.shared(true).spawn()` for CPU-intensive work in async contexts
- When in doubt, write a benchmark and profile the code (don't trust your intuition)

### Debugging Patterns

- Use `tracing` for structured, leveled logging throughout the codebase
- Implement metrics (via prometheus) for performance-critical operations
- Add comprehensive context to errors for better debugging
- Write a failing test case for a suspected bug before claiming it is a bug

### Tracing Spans

Spans represent discrete, time-limited units of work and are exported to OTLP in
production. Follow these rules when adding instrumentation:

#### Spans are not part of the runtime context

Tracing is deliberately decoupled from the runtime context (`Supervisor::child`,
`Supervisor::with_attribute`). Context identity feeds metrics and supervision; spans
are created independently at the work site. A trace follows a request as it hops
between actors. A span's parent is whoever asked for the work, which is usually a
different task on the other side of a mailbox. The context tree only records who
spawned whom, so it cannot describe that relationship.


#### `#[instrument]` vs manual spans

- Prefer `#[tracing::instrument(name = "...", level = "info", skip_all)]` on the function
  performing the work. Always use `skip_all` and opt fields in explicitly; never capture
  parameters implicitly.
- In `#[instrument(fields(...))]` a bare name declares an empty field: `fields(index)`
  records nothing. Write `fields(index = index)` to capture the variable. This is the
  opposite of the span macros, where a bare `info_span!("...", index)` is shorthand for
  `index = index`.
- As a rule of thumb, a span name should never be declared twice. If the same name appears
  at two or more call sites, that is a good sign the span belongs as `#[instrument]` on a
  re-usable function.
- When the underlying function cannot carry the attribute (e.g. a bare lock acquisition),
  create a small instrumented wrapper function instead of repeating `info_span!` at each
  call site.
- Reserve manual `.instrument(info_span!(...))` for one-off spans whose name or fields
  depend on call-site context (e.g. per-variant names), and
  `info_span!(...).entered()`/`in_scope` for synchronous sections within an async fn.
  Never hold an `entered()` guard across an `.await`.

#### Span design

- A span is a unit of work with a clear start and end, expected to last well under a
  minute. Do not wrap long-lived task loops in a single span; create one span per
  iteration.
- Spans measure boundaries; events record moments within them. Do not emit log events
  solely to mark progress inside a span (e.g. "dequeued"); create a child span instead so
  the gap is visible in the trace without polluting logs.
- For latency-sensitive paths, instrument waits separately from work: lock acquisition,
  channel/stream pulls, and fsyncs should each get their own span so contention is
  attributable.

#### Crossing actor boundaries

- `tracing`'s implicit context is task-local and does not survive a mailbox channel. When
  a request crosses an actor boundary, the message must carry its `Span` as a field
  (created at enqueue with the caller as parent) and the actor must re-enter it with
  `.instrument(span)` when processing.
- At dequeue, open a child span so queue wait and processing time are distinguishable.
- A span carried across a boundary measures enqueue-to-completion; that is intentional.

#### Levels and errors

- Use `level = "info"` for lifecycle and per-block work; `debug`/`trace` for chatty or
  large-data spans.
- Only record errors (`err`) at root spans to avoid logging the same failure at every
  level of the stack.

### Safety Guidelines

- Minimize unsafe blocks with clear `// SAFETY:` comments
- Prefer safe abstractions over raw unsafe code
- Enable overflow checks in all profiles (already configured)
