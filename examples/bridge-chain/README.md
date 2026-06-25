# Bridge Chain Example

This example runs two independent bridge-chain instances and a relayer between
them. Each chain has its own validator set, DKG threshold output, p2p namespace,
storage directory, p2p ports, and RPC ports.

Build the binaries:

```bash
cargo build -p nunchi-bridge-chain --bins
```

Generate two four-validator chains:

```bash
target/debug/bridge-chain-node \
  --out /tmp/nunchi-bridge-demo \
  --validators 4 \
  --base-port-a 56000 \
  --base-rpc-port-a 56545 \
  --base-port-b 57000 \
  --base-rpc-port-b 57545
```

Run each validator in its own process:

```bash
target/debug/bridge-chain-a-node --config /tmp/nunchi-bridge-demo/chain-a/validator-0.toml
target/debug/bridge-chain-a-node --config /tmp/nunchi-bridge-demo/chain-a/validator-1.toml
target/debug/bridge-chain-a-node --config /tmp/nunchi-bridge-demo/chain-a/validator-2.toml
target/debug/bridge-chain-a-node --config /tmp/nunchi-bridge-demo/chain-a/validator-3.toml

target/debug/bridge-chain-b-node --config /tmp/nunchi-bridge-demo/chain-b/validator-0.toml
target/debug/bridge-chain-b-node --config /tmp/nunchi-bridge-demo/chain-b/validator-1.toml
target/debug/bridge-chain-b-node --config /tmp/nunchi-bridge-demo/chain-b/validator-2.toml
target/debug/bridge-chain-b-node --config /tmp/nunchi-bridge-demo/chain-b/validator-3.toml
```

The chain A and chain B validators are separate binaries. A chain A config is
rejected by `bridge-chain-b-node`, and a chain B config is rejected by
`bridge-chain-a-node`.

Start the relayer after both chains are producing finalizations:

```bash
target/debug/bridge-relayer \
  --left http://127.0.0.1:56545 \
  --right http://127.0.0.1:57545
```

Useful RPC methods:

- `bridge.status`
- `bridge.latestFinalization`
- `bridge.finalization` with `{ "height": 1 }`
- `bridge.submitFinalization` with `{ "finalization": "<hex>" }`
- `bridge.latestAccepted`
