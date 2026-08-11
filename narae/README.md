# narae

`narae` is a local testnet runner with a ratatui log dashboard. It launches one
`coins-chain-node` process per local validator and secondary node and tails their
logs side by side.
Deployment-oriented config generation lives in `xtask`.

Generate configs and start a 4-validator coins-chain devnet in one step (the node binary must
be built first; narae will tell you if it's missing):

```sh
cargo build -p nunchi-coins-chain --bin coins-chain-node
cargo run -p narae -- up coins-chain
```

To include non-voting secondary nodes, add `--secondaries`:

```sh
cargo run -p narae -- generate coins-chain --validators 4 --secondaries 2 --out testnet
cargo run -p narae -- run testnet
```

Or split generation and running:

```sh
cargo run -p narae -- generate coins-chain --validators 4 --out testnet
cargo run -p narae -- run testnet
```

`generate` is local-only and writes one `validator-N.toml` per validator, one
`secondary-N.toml` per secondary node, and a `narae.toml` manifest into the
output directory. Each node listens for peers on `--base-port + N` (default
30000), serves the aggregated JSON-RPC on `--base-rpc-port + N` (default 8545),
and exposes Prometheus metrics on `--base-metrics-port + N` (default 9090), e.g.:

```sh
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain.status","params":[]}' \
  http://127.0.0.1:8545

curl -s http://127.0.0.1:9090/metrics
```

Inside the dashboard: `↑`/`↓` (or `j`/`k`) select a node, `PgUp`/`PgDn` scroll its logs, `/`
filters log lines, `r` restarts and `s` stops the selected node, `S` stops all nodes, and `q`
quits (stopping all nodes).

The node binary can also be run directly, which is what `narae` does under the hood:

```sh
cargo run -p nunchi-coins-chain --bin coins-chain-node -- --config testnet/validator-0.toml
```

For a non-voting secondary node, point the binary at a `secondary-N.toml`
config instead:

```sh
cargo run -p nunchi-coins-chain --bin coins-chain-node -- --config testnet/secondary-0.toml
```
