# Perpetuals Production Follow-Up Roadmap

This document tracks the work intentionally left out of the first minimal perps draft. PR #79 proves the core path: Oracle-backed mark prices, isolated collateral escrow, funding indices, liquidation checks, RPC, and consensus-backed integration coverage. The items below are the next pieces required before treating the module as production-ready.

## 1. Branch Stack And Wire Tag Reconciliation

The perps draft is stacked on top of the Oracle branch. Before merge:

- Land or otherwise finalize the Oracle branch.
- Rebase the perps branch onto the finalized Oracle commit.
- Reconcile transaction wire tags if `nunchi-swap` is restored on the same branch stack.
- Rerun the full workspace checks after the rebase.

Expected output: a perps branch whose transaction tags match the final chain module set.

## 2. Insurance Fund And Liquidation Rewards

The current draft leaves residual liquidated collateral in the perps escrow account. That is enough for a minimal liquidation path, but production semantics should be explicit.

Required decisions:

- Whether each market has its own insurance bucket or all markets share one per collateral asset.
- Whether liquidators receive a fixed reward, a percentage of remaining equity, or only gas/fee compensation.
- What happens when a position is underwater and escrow cannot cover a profitable close or reward.
- Whether insurance balances are queryable and configurable through genesis/RPC.

Expected output: explicit state fields, operations, accounting tests, and documentation for liquidation proceeds.

## 3. Market Administration

Market parameters are immutable after creation in the minimal draft. Production chains will need controlled updates.

Candidate operations:

- `SetMarketStatus` for pausing opens while allowing closes/liquidations.
- `UpdateRiskParams` for leverage, maintenance margin, funding cap, and staleness thresholds.
- `UpdateOracleConfig` for namespace, interval, and payload-decimal changes.

Required safeguards:

- Authorization model for market admins.
- Tests proving parameter changes cannot instantly make existing healthy positions invalid unless explicitly allowed.
- Clear handling for paused or stale markets.

Expected output: admin transaction operations with authorization and invariant tests.

## 4. Oracle Publisher And Operator Tooling

The Oracle module intentionally stores opaque bytes. Operators still need a reliable way to produce the perps payload schema.

Required tooling:

- Small CLI or script that encodes `OraclePricePayload`.
- Example command sequence for configuring an Oracle namespace/writer.
- Example command sequence for appending mock prices and refreshing markets.
- Testnet walkthrough that exercises create collateral, refresh, open, price move, and liquidation through RPC.

Expected output: repeatable operator demo rather than manually constructing payload bytes in tests.

## 5. Risk And Accounting Hardening

The draft has deterministic tests for the basic math path, but production readiness requires broader adversarial coverage.

Additional tests:

- Profitable close when escrow has insufficient balance.
- Funding across many intervals and negative premium.
- Liquidation at exact maintenance margin boundaries.
- Collateral reduction at exact safe/unsafe thresholds.
- Multiple positions across long and short sides sharing one market.
- Multiple markets sharing one collateral asset.
- Repeated refreshes with older, newer, malformed, and wrong-market Oracle records.

Expected output: focused unit tests and at least one expanded integration test.

## 6. Fee Model And Settlement Policy

The current module does not charge trading fees and does not define protocol-level revenue.

Open questions:

- Whether open/close/liquidation fees are charged.
- Whether fees accrue to market insurance, protocol treasury, or both.
- Whether fees are paid in collateral asset only.
- How fees interact with equity, maintenance margin, and liquidation reward calculations.

Expected output: fee accounting model, state fields, tests, and RPC query support.

## Merge Readiness Checklist

- Oracle PR finalized and perps rebased.
- Wire tags reconciled with all enabled modules.
- `cargo test -p nunchi-perpetuals` passes.
- `cargo test -p nunchi-coins-chain` passes.
- Operator/demo flow is documented and repeatable.
- Insurance/liquidation reward semantics are explicit.
- Market admin and pause semantics are reviewed.
