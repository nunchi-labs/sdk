# PRD: Hybrid AMM — House Module + Cooperative Batch Clearing + Off-Chain Bin Manager

- **Status:** draft for review
- **Date:** 2026-07-07
- **Owner:** Jae (@JaeLeex)
- **Depends on:** #117 `nunchi-clob` (this branch stacks on `jae/spot-clob-module`; retarget to `main` after #117 lands)
- **Sources:** 07-03 dev standup decision; internal CBC chain-spec + ABM operator spec drafts (2026-06-11); "Nunchi Perp AMM Funding-Rate Model" whitepaper draft (2026-06-30)

## Thesis

Layer Uniswap-v3-style binned house liquidity **onto** the CLOB as ordinary resting orders — the reverse of Osmosis, which bolted book features onto an AMM. Users get AMM-like immediacy; capital providers get CLOB-grade risk controls: explicit inventory caps, a finite house leverage ceiling, oracle-mode-aware operation, cancel/reprice rights, and public uniform-price clearing for residual inventory.

The hybrid AMM is **not** one module. It is two new on-chain modules plus one off-chain operator, all clients of the book that #117 ships:

1. **`house`** (on-chain): house vault capital, per-market allocation policy, leverage ceiling, operating mode, authorized-submitter registry. "HLP-analogue" in the *house* sense only — explicitly none of HLP's liquidation-vault/backstop/ADL roles (those stay in `perpetuals`).
2. **`cbc`** (on-chain): cooperative batch clearing — accepts signed liquidity-management intents from the house and allowlisted MMs, clears them at one deterministic uniform price per market per batch, settles against house/CLOB/perps accounting.
3. **ABM** (off-chain, Nunchi-run): the proprietary automated bin manager. Converts vault policy, oracle state, book depth, inventory, funding, and volatility into signed CLOB place/cancel operations and CBC intents. Never a chain module; the chain sees only signed intents and enforceable policy.

This supersedes the pre-chain EVM lineage (`packages/exchange` `BinManager` + `AMM` contracts, catalogued as a single `daeji::amm` module) with a strategy/settlement split.

## Module boundaries

| Layer | Residency | Owns | Explicitly does not own |
|---|---|---|---|
| `clob` (#117) | on-chain | market metadata, price-time matching, open orders, fills | settlement, margin, house liquidity, bins, batch clearing |
| `house` (new) | on-chain | vault accounts/tranches, `VaultPolicy` caps, house leverage ceiling, `LIVE/FROZEN/HALT` vault mode, submitter allowlist | quoting decisions, bin selection, matching, liquidations |
| `cbc` (new) | on-chain | batch params, intent validation, uniform clearing price, fill allocation, settlement, batch events | strategy inference, bin logic, external hedging, oracle computation |
| ABM | off-chain | bin widths, capital scoring, fair-value blend, skew, toxicity, hedging heuristics | anything consensus-relevant |

The CLOB never learns that an order is a "bin": each bin level is an ordinary `ClobOperation::PlaceOrder` and dies by `CancelOrder` or TTL refresh. The digest-backed `AssetId`/`MarketId` design in #117 already anticipates this — house and CBC agree on ids without coupling matching to settlement.

## Bin construction (ABM, off-chain)

```text
fair_value  = blend(oracle_price, microprice, external_ref, session_ref)
half_spread = base_spread × vol_mult × drawdown_mult × toxicity_mult × regime_mult
levels      = geometric_ladder(fair_value, half_spread, num_levels, size_decay)
```

Risk adjustments before emission: widen on oracle degradation, skew away from inventory, pull the inventory-increasing side at soft cap, micro-clip at hard cap, reduce-only in `FROZEN`, cancel-all in `HALT`. Every emitted action is signed by an authorized house submitter and carries nonce + TTL so stale ladders cannot replay into a moved market.

## CBC clearing

**v1 — uniform-price batch auction.** Per market, on a configured cadence: `OpenBatch → SubmitIntent* → CloseBatch → clear → settle`. The clearing price maximizes executable quantity; every executable fill receives that one price; ties break deterministically toward the registry-approved oracle price.

**v1.1 — risk-weighted KKT clearing.** Transfers minimize a quadratic inventory-risk objective:

```text
min_x  Σ_j [ γ_j/2 · (I_j + x_j)² + c_j·|x_j| ]   s.t.  Σ_j x_j = 0,   γ_j = γ_base,j · L_eff_j
```

Uniform pricing is the trust model: a hostile public submitter cannot PVP another participant's price-time edge when all fills clear at one price, so the house path needs **no TEE**. TEE clearing remains a future option for private RFQ / confidential MM competition, not a v1 dependency.

### Intent and policy schemas (wire-level, from the CBC spec)

```text
BatchIntent {                          VaultPolicy {
  submitter                              allowed_markets
  market_id                              max_market_allocation
  side                                   max_net_inventory
  quantity                               max_leverage
  limit_price                            min_margin_coverage
  max_slippage_bps                       submitter_allowlist
  reduce_only                            mode              // LIVE | FROZEN | HALT
  vault_account                        }
  expiry_height
  nonce                                BatchParams {
  signature                              cadence_blocks
}                                        max_batch_notional
                                         max_submitter_notional
                                         oracle_band_bps
                                         min_clearing_qty
                                         price_tick / size_tick
                                         allocation_rule
                                         stale_mode_behavior
                                       }
```

## Load-bearing invariant: the house leverage ceiling

```text
L_max_house = min(L_operator, 1 / MMR_market,session)
L_eff_j     = min(L_user_j, L_max_house)
```

The cap keeps `γ_j` bounded (finite drift in the clearing system) and bounds residual house exposure through stale-oracle, liquidation, and hedge-unwind windows. External hedges are **not** atomic with chain settlement; the gap is modeled, not hidden:

```text
Loss_gap ≲ Q_max · P_t · σ_p · √W,   W = max(τ_cancel, W_hedge)
```

Margin coverage buffers must absorb this residual with high probability. Funding (perps markets only — owned by `perpetuals`, not by this stack) is anchored as a bounded multi-anchor process `f_t = clip[−f_max, f_max](w_E·f_ext + w_M·f_mid + w_O·f_oracle + w_I·f_imbalance + b_t)`; the hybrid AMM contributes only the imbalance-pressure input.

## Worked example

Market BASE/QUOTE, oracle price 100.00, `oracle_band_bps = 50`. ABM state: `base_spread = 8bps`, `vol_mult = 1.5` (others 1.0) → `half_spread = 12bps`; 3 levels/side, geometric offsets 12/21/37 bps, top size 500 BASE, `size_decay = 0.7`; house inventory **+1,200 BASE** (soft cap 2,000) → skew multiplies bid sizes by 0.7.

| Level | Bid px | Bid size | Ask px | Ask size |
|---|---|---|---|---|
| 1 | 99.88 | 350 | 100.12 | 500 |
| 2 | 99.79 | 245 | 100.21 | 350 |
| 3 | 99.63 | 172 | 100.37 | 245 |

Each row is one signed `PlaceOrder` (GTC, tick-rounded `u128` price); regime change ⇒ `CancelOrder` + re-emit.

End of window, inventories: house +1,200; MM_A −700; MM_B −300. CBC intents: house sell 1,200 @ limit ≥ 99.90; MM_A buy 700 @ ≤ 100.06; MM_B buy 300 @ ≤ 100.02. Any price in [99.90, 100.02] executes 1,000; tie-break lands on the oracle price **100.00**, inside the band. Settlement is conservation-preserving: house −1,000 BASE / +100,000 QUOTE; MM_A +700 / −70,000; MM_B +300 / −30,000. The house's +200 residual stays under `max_net_inventory` and is carried or hedged externally under the `Loss_gap` bound. No participant's strategy is revealed — only signed intents and one public clearing price.

## Interaction with the open #117 review thread

The review question on #117 — gossip placements p2p and keep books in validator memory, committing only fills (dYdX-v4 shape) — changes *where* the ladder rests but not this design. ABM outputs are venue-agnostic signed intents, so the ladder path works against an on-chain or in-memory book unchanged. CBC is unaffected: batch intents and clearing results must be state-committed under either book residency, and per-cadence batches amortize state cost. One honest consequence: with off-chain placement, `house` policy caps cannot be checked per-placement; enforcement moves to settlement time (fills debit house accounts) plus ABM self-enforcement. Flagged as open question 7.

## Sequencing, scope, non-goals

**Landing order:** #117 (`clob`) → this PRD → `house` crate → `cbc` crate → perps interactions. Both crates follow the established module pattern (`transaction` ops + `ledger` + `db` + `rpc` + `genesis` + tests, commonware codec, `stability_scope!(ALPHA)`). Wire-tag allocation stays coordinated against the *final* module set (`perpetuals/ROADMAP.md` §1) — this PRD adds two modules to that set. Nothing here may delay the ~1-week devnet (perps ships oracle-marked as-is).

**v1:** house-only or allowlisted-MM intents, auction-form clearing, oracle-band + vault-policy validation, mode enforcement, settlement, reconciliation events. KKT clearing, external-MM expansion, and commit-reveal privacy are v1.1+.

**Non-goals:** no HLP liquidation/backstop/ADL semantics anywhere in this stack; no bins or AMM math inside `nunchi-clob`; no TEE dependency; no spot-module implementation; no proprietary strategy parameters on-chain.

## Proposed operations

```text
house: SetVaultPolicy, SetAuthorizedSubmitter, SetVaultMode, Deposit, Withdraw
cbc:   RegisterMarketBatchParams, SetMarketClearingMode,          // governance
       SubmitBatchIntent, CancelBatchIntent,                      // submitter
       CloseAndClearBatch                                         // keeper/validator
events: BatchOpened, IntentAccepted, IntentRejected, BatchCleared, BatchSettlementApplied
```

Invariants: no unapproved submitter moves vault liquidity; no batch exceeds policy caps or settles outside the oracle band or in `HALT`; `FROZEN` accepts reduce-only house fills; settlement reconciles zero-sum against CLOB/perps/house ledgers; every fill is auditable from public inputs.

## Open questions

1. Crate split: standalone `house` vs. folding policy into a broader vault module — v1 proposal is one `house` crate owning both capital and policy.
2. Reserve `γ_j`/`c_j` fields in the v1 `BatchIntent` codec, or add them in v1.1 with a codec version bump?
3. Fill allocation rule at the clearing price: pro-rata vs. price-time vs. deterministic submitter-weight tie-break.
4. `lambda_hedge`: module parameter, vault policy field, or ABM-internal only?
5. External MMs in v1, or house-only with the allowlist path activated later?
6. Self-trade: `nunchi-clob` intentionally does not enforce STP — the house ladder can cross its own CBC settlement flow. Handle in ABM, or add an owner-exclusion flag to `PlaceOrder`?
7. Book residency (from the #117 thread): if placement moves off-chain, confirm settlement-time enforcement of house caps is acceptable.
8. First market for the full stack: the initial perps market, SPX expected-move, or BTC-FR.
