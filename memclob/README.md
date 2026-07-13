# nunchi-memclob

Validator-local, in-memory central limit order books with P2P gossip — modeled after [dYdX v4](https://docs.dydx.exchange/introduction-onboarding_faqs).

## Architecture

Each validator runs a `MemBookEngine` that is **not** committed to consensus directly. Signed order instructions (`PlaceOrder`, `CancelOrder`, `CreateMarket`) propagate over a dedicated P2P channel using the same wire format as `nunchi-clob` transactions. Every honest node applies the same deterministic matching rules, so local books stay eventually consistent.

When a validator proposes a block, it drains `pending_fills()` from its memclob and includes those fills for on-chain settlement via `nunchi-clob::ClobLedger`.

```
Trader ──submit──► MemClobHandle ──► MemBookEngine (RAM)
                         │
                         └── P2P gossip (Recipients::All) ──► peer validators

Proposer ──pending_fills()──► block ──finalize──► ClobLedger (QMDB)
```

## Relationship to `nunchi-clob`

| Layer | Crate | Role |
|-------|-------|------|
| Short-term | `nunchi-memclob` | In-memory book + P2P order gossip |
| Long-term | `nunchi-clob` | Deterministic on-chain book state + fills |

Memclob reuses `nunchi_clob::Transaction` for wire compatibility so the same signed bytes can later be replayed into chain state at block boundaries.

## Integration

- P2P channel: `examples/coins-chain` registers `channels::MEMCLOB = 7`
- Start with `MemClob::start_p2p(context, p2p_sender, p2p_receiver)`
- Query open book via `MemClobHandle::book(market, side)`
- Proposer pulls `MemClobHandle::pending_fills(limit)`
