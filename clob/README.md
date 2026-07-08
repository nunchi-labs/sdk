# nunchi-clob

`nunchi-clob` is the shared CLOB module for Nunchi spot and derivatives execution.

The module owns:

- market metadata for base/quote pairs
- signed order intents for the validator-local book
- deterministic price-time matching and validator replay
- proposer match batches carried as a consensus extension
- active order snapshots needed to replay later matches
- fill records queryable by market

It intentionally does not own settlement, balances, margin, funding, PnL, liquidations, house liquidity, AMM bins, or cooperative batch clearing. Verified fills are recorded for downstream consumers; balance movement must be provided by a settlement module.

## v1 operations

- `CreateMarket`
- `PlaceOrder` as an off-chain signed intent
- `CancelOrder` remains an off-chain intent boundary and is not a direct on-chain matcher entry point
- `ApplyMatchBatch` as a batch payload verified from signed order inputs

`PlaceOrder` supports `GoodTilCancelled` and `ImmediateOrCancel` time-in-force, but it is not an on-chain matcher entry point. Validators accept fills because they seed deterministic replay from committed active order snapshots, then re-run matching over fresh signed order inputs. Batches name any committed resting order ids they depend on and carry only the fresh signed intents whose nonces should advance. Fills execute at the resting maker price. Asset ids are opaque `Digest`-backed identifiers so the CLOB can be wired to `nunchi-coins`, perps market ids, or other settlement domains later without changing the matching primitive.

## Current integration boundary

`examples/coins-chain` wires the CLOB actor into the application as a consensus extension. Clients submit signed order intents to the CLOB mailbox; the proposer keeps non-crossing GTC intents locally until there is a matchable batch; every validator verifies signatures, replays the matcher, records active order snapshots for residual GTC liquidity, and records verified fills in QMDB. `market_fills` is a bounded recent-fill window: old fill ids and stale fill records are pruned instead of blocking later matches. No validator-local bridge signs fills into the mempool.
