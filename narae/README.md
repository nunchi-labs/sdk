# narae

`narae` is a local testnet runner with a ratatui log dashboard. It generates standalone
validator configs for an example chain (trusted key setup plus an initial threshold deal),
launches one `coins-chain-node` process per validator, and tails their logs side by side.

Generate configs and start a 4-validator coins-chain devnet in one step (the node binary must
be built first; narae will tell you if it's missing):

```sh
cargo build -p nunchi-coins-chain --bin coins-chain-node
cargo run -p narae -- up coins-chain
```

Or split generation and running:

```sh
cargo run -p narae -- generate coins-chain --validators 4 --out testnet
cargo run -p narae -- run testnet
```

`generate` writes one `validator-N.toml` per node plus a `narae.toml` manifest into the output
directory. Each node listens for peers on `--base-port + N` (default 30000) and serves the
aggregated JSON-RPC on `--base-rpc-port + N` (default 8545), e.g.:

```sh
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain.status","params":[]}' \
  http://127.0.0.1:8545
```

Inside the dashboard: `↑`/`↓` (or `j`/`k`) select a node, `PgUp`/`PgDn` scroll its logs, `/`
filters log lines, `r` restarts and `s` stops the selected node, `S` stops all nodes, and `q`
quits (stopping all nodes).

The node binary can also be run directly, which is what `narae` does under the hood:

```sh
cargo run -p nunchi-coins-chain --bin coins-chain-node -- --config testnet/validator-0.toml
```
