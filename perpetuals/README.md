# nunchi-perpetuals

`nunchi-perpetuals` is a minimal perpetual futures primitive for Nunchi chains. It is intentionally generic: markets, isolated collateral, funding, liquidation, and Oracle-backed mark prices are implemented without assuming a specific venue or product shape.

## Current model

- Markets define base, quote, and collateral assets, plus their Oracle namespace, trusted `oracle_writer`, and risk parameters.
- Oracle records remain opaque to `nunchi-oracle`; this module decodes `OraclePricePayload`, scales/truncates prices, and owns freshness checks. Malformed or untrusted-writer records are skipped rather than aborting refresh.
- `index_price` comes from the trusted oracle writer. `mark_price` is bootstrapped from the first oracle refresh and can diverge via `UpdateMarkPrice` or the optional `actor` mailbox wired to the CLOB module.
- Positions use isolated margin. Collateral is escrowed in a deterministic perps account backed by `nunchi-coins` balances.
- Funding accrues only when both long and short open interest are non-zero, keeping index deltas zero-sum across sides.
- Liquidation pays a configurable reward to the liquidator, returns residual equity to the owner when possible, and routes the remainder to an insurance fund account.
- Underwater positions cannot be closed voluntarily; they must be liquidated.

## CLOB + clearinghouse integration

Production position changes arrive via `nunchi-clearinghouse::SettleFill`, which calls
`apply_fill_settlement` for both maker and taker after the shared CLOB emits a `Fill`.

Direct `OpenPosition` / `ClosePosition` transactions require the `mock-execution` feature.

## CLOB mark-price ingress (PR #117)

Enable the `actor` feature to expose:

- `nunchi_perpetuals::ingress::Mailbox` — send `UpdateMarkPrice` from the CLOB actor after matching.
- `nunchi_perpetuals::actor::Actor` — drain mailbox messages into `PerpetualLedger` state.

Markets may optionally store a linked `clob_market` id at creation time so operators can wire the two modules deterministically.

## Mock Oracle payload

The perps module expects Oracle records to carry an encoded `OraclePricePayload`:

```rust
OraclePricePayload {
    market,
    price,
    price_decimals,
    source_timestamp_ms,
}
```

The Oracle stores this as opaque bytes under a `NamespaceId` and `IntervalKey`. The perps market refresh step queries the configured namespace, decodes only records matching the market id, verifies source and write-time freshness, and updates the market's mark and index price.

## RPC exercise flow

The coins-chain example exposes the perps module over JSON-RPC when built with this crate:

- `perpetuals.nonce`
- `perpetuals.market`
- `perpetuals.position`
- `perpetuals.state_root`
- `perpetuals.submit_transaction`
- `perpetuals.transaction_status`

A minimal mock flow is:

1. Create a collateral token through `coins.submit_transaction`.
2. Transfer collateral to the trader account.
3. Configure an Oracle namespace and writer through Oracle transactions.
4. Append a mock `OraclePricePayload` record for the target market.
5. Submit `PerpetualOperation::CreateMarket`.
6. Submit `PerpetualOperation::RefreshMarketFromOracle`.
7. Submit `PerpetualOperation::OpenPosition`.
8. Append an adverse mock price record.
9. Submit another `RefreshMarketFromOracle`.
10. Submit `PerpetualOperation::Liquidate`.

The consensus-backed integration test `perps_oracle_flow_finalizes_across_validators` in `examples/coins-chain/tests/coins.rs` executes this sequence through the same submitted transaction path used by the example chain.

## Known follow-ups

- Add explicit insurance fund and liquidation reward semantics.
- Decide whether profitable PnL should be paid from pooled collateral, a funded insurance account, or a separate market-liquidity primitive.
- Add market admin controls for parameter updates once the first draft API is reviewed.
- Reconcile wire tags when this branch is rebased onto the final Oracle and swap branch stack.
