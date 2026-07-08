# nunchi-clob

`nunchi-clob` is the shared CLOB module for Nunchi spot and derivatives execution.

The module owns:

- market metadata for base/quote pairs
- signed place/cancel order intents for the validator-local book
- deterministic price-time matching and validator replay
- proposer match batches carried as a consensus extension
- fill records queryable by market

It intentionally does not own settlement, balances, margin, funding, PnL, liquidations, house liquidity, AMM bins, or cooperative batch clearing. Verified fills are recorded for downstream consumers; balance movement must be provided by a settlement module.

## v1 operations

- `CreateMarket`
- `PlaceOrder` / `CancelOrder` as off-chain signed intents
- `ApplyMatchBatch` as a batch payload verified from signed order inputs

`PlaceOrder` supports `GoodTilCancelled` and `ImmediateOrCancel` time-in-force, but it is not an on-chain matcher entry point. Validators accept fills because they re-run deterministic matching over signed order inputs, not because a validator signed the fill output. Fills execute at the resting maker price. Asset ids are opaque `Digest`-backed identifiers so the CLOB can be wired to `nunchi-coins`, perps market ids, or other settlement domains later without changing the matching primitive.

## Current integration boundary

`examples/coins-chain` wires the CLOB actor into the application as a consensus extension. Clients submit signed order intents to the CLOB mailbox; the proposer embeds a match batch; every validator verifies signatures, replays the matcher, and records the verified fills in QMDB. No validator-local bridge signs fills into the mempool.
