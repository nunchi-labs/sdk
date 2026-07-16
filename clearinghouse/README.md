# nunchi-clearinghouse

`nunchi-clearinghouse` routes deterministic CLOB `Fill` records to settlement
consumers. It sits between `nunchi-clob` (matching) and domain modules such as
`nunchi-perpetuals` (margin, funding, liquidations).

## Responsibilities

- Register settlement markets that link a CLOB market to a consumer domain
- Idempotently settle CLOB fills into perpetuals position state
- Apply counterparty updates atomically for both maker and taker

## Non-responsibilities

- Order matching or book state (`nunchi-clob`)
- Margin math, funding, or liquidation (`nunchi-perpetuals`)
- Cooperative batch clearing for house liquidity (future `nunchi-cbc` client)

## v1 operations

- `RegisterPerpsMarket` — bind `clob_market` → `perps_market`
- `SettleFill` — read a CLOB fill and apply perps settlement for both parties

## Execution flow

```
Trader → CLOB PlaceOrder → Fill
Proposer/anyone → Clearinghouse SettleFill → Perps apply_fill_settlement (maker + taker)
```
