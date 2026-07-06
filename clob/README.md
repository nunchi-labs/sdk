# nunchi-clob

`nunchi-clob` is the shared central limit order book for Nunchi spot and derivatives execution.

The module owns:

- market metadata for base/quote pairs
- signed place/cancel operations
- deterministic price-time matching
- open order state
- fill records queryable by market

It intentionally does not own settlement, balances, margin, funding, PnL, liquidations, house liquidity, AMM bins, or cooperative batch clearing. Spot, perpetuals, house, and batch-clearing modules should consume the book as clients rather than embedding matching logic of their own.

## v1 operations

- `CreateMarket`
- `PlaceOrder`
- `CancelOrder`

`PlaceOrder` supports `GoodTilCancelled` and `ImmediateOrCancel` time-in-force. Fills execute at the resting maker price. Asset ids are opaque `Digest`-backed identifiers so the CLOB can be wired to `nunchi-coins`, perps market ids, or other settlement domains later without changing the matching primitive.

## Current integration boundary

This crate compiles and tests as a standalone workspace module. It does not allocate a chain transaction wrapper tag or wire into `examples/coins-chain` yet; that should be coordinated with the final module set so CLOB can land before the perps PR stack without preempting chain-level wire-tag allocation.
