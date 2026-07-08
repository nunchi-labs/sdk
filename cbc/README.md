# nunchi-cbc

`nunchi-cbc` is the cooperative batch clearing module of the Nunchi hybrid AMM stack. It clears signed liquidity-management intents from house vaults and allowlisted market makers at one deterministic uniform price per market per batch, and settles fills through `nunchi-house`'s checked clearing API.

Uniform pricing is the trust model: every executable fill in a batch receives the same price, so a hostile public submitter cannot selectively trade against another participant's price-time edge, and participants reveal nothing beyond their signed intents. The house-liquidity path therefore needs no TEE; confidential clearing remains a future hardening option.

## v1 operations

- `RegisterMarket` / `SetClearingMode` (admin-gated)
- `SubmitIntent` / `CancelIntent` (authorized vault submitters)
- `CloseAndClearBatch` (keeper-gated)

## Clearing flow

1. Intents rest in a per-market queue in submission order. Buy intents reserve their worst-case quote cost (`limit_price * base_quantity`) in the house module at submission, so a vault can never distort a batch price with intents it cannot settle.
2. On `CloseAndClearBatch`, expired intents and intents whose vault is halted or has no reducing capacity are retired first.
3. The clearing price maximizes executable volume over the surviving intents; ties break toward the keeper-posted oracle price, then toward the lower price. Prices outside the oracle band record an `OutsideBand` result and leave the queue untouched.
4. Matched volume is allocated in submission order. Each matched chunk validates both sides against current house state (mode gates, reducing capacity, caps, leverage ceiling) and settles immediately; an intent whose side fails validation is skipped for the batch and remains pending.
5. The batch result (outcome, prices, aggregate fills, retired intents) is recorded and queryable; results are the module's event surface for ABM reconciliation.

Settlement is conservation-preserving by construction: every chunk credits and debits equal base and quote across its two sides at the uniform price.

## Trust seams and v1 limits

- The keeper posts the oracle price with each clearing call. This is a documented interim seam until chain-level oracle wiring supplies registry-approved prices directly, and it is why `CloseAndClearBatch` is keeper-gated rather than permissionless.
- Sell intents post no collateral; they are bounded by per-vault and per-batch notional caps and by house-side exposure checks at settlement. Economic short margining arrives with perps wiring.
- Reduce-only quantities are capped against pre-batch inventory for price discovery and re-checked exactly during allocation.
- Risk-weighted KKT clearing (explicit `gamma`/`c` parameters) is the planned v1.1 upgrade of the price rule; the intent codec deliberately leaves room for a versioned extension.
