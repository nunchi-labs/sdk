# Coins chain example

`nunchi-coins-chain` is a complete proof-of-authority reference chain for the
Nunchi SDK. It combines the coins ledger with the CLOB, mempool, DKG resharing,
bridge, oracle, RPC, state sync, and indexer components.

## Run a local network

Build the node binary, then generate and start a four-validator local network:

```sh
cargo build -p nunchi-coins-chain --bin coins-chain-node
cargo run -p narae -- up coins-chain
```

The same workflow can be run in two steps when the generated configuration
should be kept for inspection:

```sh
cargo run -p narae -- generate coins-chain --validators 4 --out testnet
cargo run -p narae -- run testnet
```

To start a node directly, use one of the generated validator configurations:

```sh
cargo run -p nunchi-coins-chain --bin coins-chain-node -- \
  --config testnet/validator-0.toml
```

## Layout

- `src/runtime.rs` dispatches transactions to the SDK modules.
- `src/engine.rs` wires the consensus engine.
- `src/execution.rs` executes state changes and exposes `NodeHandle`.
- `src/application.rs` proposes, verifies, and finalizes blocks.
- `src/testnet.rs` generates local validator configurations and starts a node.
- `src/indexer/` streams finalized chain events to the indexer.

## RPC

Each generated validator exposes JSON-RPC at `http://127.0.0.1:8545` by
default. For example, query the chain status with:

```sh
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain.status","params":[]}' \
  http://127.0.0.1:8545
```

Use the `coins-chain-tool` binary to construct and submit coin transactions:

```sh
cargo run -p nunchi-coins-chain --bin coins-chain-tool -- --help
```
