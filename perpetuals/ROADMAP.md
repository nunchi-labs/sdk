# Perpetuals Modular Roadmap

This document supersedes the original PR #80 follow-up list. Perpetuals is now a
**CLOB consumer** settled through `nunchi-clearinghouse`, not a standalone execution engine.

## Module boundaries

| Module | Responsibility |
|--------|----------------|
| `nunchi-clob` | Book state, matching, `Fill` records |
| `nunchi-clearinghouse` | Fill settlement routing, idempotency, counterparty pairing |
| `nunchi-perpetuals` | Margin, funding, PnL, liquidations, oracle index/mark |
| `nunchi-cbc` (future) | Uniform-price batch clearing client — not in CLOB or perps |

## Landed in `jl/clearinghouse-perps-modular`

- [x] `nunchi-clearinghouse` crate with `RegisterPerpsMarket` + `SettleFill`
- [x] `apply_fill_settlement` on perps — deterministic `(owner, market, side)` positions
- [x] CLOB lot → perps `PRICE_SCALE` quantity conversion at settlement
- [x] `OpenPosition` / `ClosePosition` gated behind `mock-execution` feature
- [x] Integration tests: CLOB match → clearinghouse settle → long/short OI

## Next PRs (replaces open #79 / #80)

1. **Wire into `examples/coins-chain`** — transaction tags for clearinghouse + perps refactor
2. **Block proposer path** — batch `SettleFill` from memclob `pending_fills()`
3. **Reduce-only CLOB orders** — perps close flow via opposite-side fills
4. **Spot settlement domain** — `SettlementDomain::Spot` in clearinghouse
5. **CBC client** — batch settlement into clearinghouse (separate crate)

## Production hardening (carried from original #80)

- Market admin controls (`SetMarketStatus`, `UpdateRiskParams`)
- Operator tooling for oracle payload + settlement demo
- Expanded adversarial tests (partial close, insurance draw, multi-market)
- Fee model and protocol revenue accounting
- Wire-tag reconciliation with Jacob before merge

## Merge readiness

- [ ] `cargo test -p nunchi-clearinghouse`
- [ ] `cargo test -p nunchi-perpetuals --features mock-execution`
- [ ] `cargo test -p nunchi-clob`
- [ ] coins-chain integration test for CLOB → clearinghouse → perps path
- [ ] Close superseded PRs #79 and #80 with links to new stack
