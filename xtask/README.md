# xtask

`xtask` provides workspace automation and deployment setup tasks. Its current
task generates local validator configurations for the coins-chain example.
`narae` consumes the generated manifest to run the local testnet, while
`coins-chain-node` runs each validator.

## Generate a local coins-chain testnet

Run the workspace binary with Cargo:

```sh
cargo run -p xtask -- generate coins-chain
```

The command writes `narae.toml` and one validator configuration per node to
`testnet/`. Change the validator count or networking ports when needed:

```sh
cargo run -p xtask -- generate coins-chain \
  --validators 8 \
  --base-port 40000
```

Build `coins-chain-node` before starting the generated network with `narae`:

```sh
cargo build -p nunchi-coins-chain --bin coins-chain-node
cargo run -p narae -- run testnet
```

## Library use

Library consumers can construct the same local configuration with
`nunchi_xtask::coins_chain::Generate::local`, then call `run` to write the
manifest. This is useful for tools that need to choose their own output
directory or port ranges.
