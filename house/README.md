# nunchi-house

`nunchi-house` is the house vault module of the Nunchi hybrid AMM stack. It owns the capital and policy surface that the off-chain automated bin manager and the cooperative batch clearing module operate against.

The module owns:

- vault capital accounting (free balance plus per-market clearing reservations)
- per-vault risk policy: market allowlist, per-market allocation cap, net inventory cap, and the house leverage ceiling
- vault operating modes (`live`, `frozen`, `halt`)
- the registry of submitter keys authorized to manage a vault's liquidity
- signed net inventory per vault per market

It intentionally does not own quoting strategy, bin construction, order matching, batch clearing, funding, or liquidations. The "house" is an HLP analogue in the house-liquidity sense only: it carries none of HLP's liquidation-vault or backstop roles.

## v1 operations

- `CreateVault`
- `Deposit` / `Withdraw`
- `SetVaultPolicy`
- `SetAuthorizedSubmitter`
- `SetVaultMode`

All operations are gated to the vault owner. Withdrawals additionally require a live vault with a flat book; margin-coverage-based partial withdrawal needs an oracle valuation and arrives with chain-level oracle wiring.

## Clearing API

The cooperative batch clearing module composes this crate through checked entry points rather than raw state access:

- `authorized_submitter` answers whether a key may manage a vault's liquidity.
- `reserve_clearing_quote` / `release_clearing_quote` move free balance into and out of per-market reservations that back the worst-case cost of pending buy intents.
- `validate_clearing_fill` is the pure policy core: mode gates, market allowlist, net inventory cap, and the leverage ceiling, applied only to exposure-increasing fills so vaults can always trade back toward flat.
- `settle_clearing_fill` re-runs the same validation against persisted state and applies the fill.

## Current integration boundary

Balances are internal accounting units until chain-level wiring connects deposits and withdrawals to the coins module, mirroring how the CLOB records fills without moving funds. The crate does not allocate a chain transaction wrapper tag yet; that is coordinated against the final module set.

The repository taxonomy also reserves a broader `vaults` module ("many types of capital, traded by an authorised offchain party"). Whether this crate folds into that module or stays standalone is an open review question in the hybrid AMM PRD.
