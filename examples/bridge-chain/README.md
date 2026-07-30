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

## Peer addresses

Validator configs accept either IP socket addresses or DNS hostnames with ports
for advertised and bootstrapper P2P addresses:

```toml
dialable_address = "validator-0.bridge.example.com:30000"

[[bootstrappers]]
public_key = "..."
address = "validator-1.bridge.example.com:30001"
```

IPv4 uses normal socket syntax, while IPv6 literals must be bracketed, for
example `[2001:db8::10]:30000`. URLs and paths are not valid peer addresses.
`listen_address` and `rpc_address` remain IP socket addresses because the node
binds them locally.

DNS is resolved on each new connection attempt. If a connection closes and the
same hostname now resolves to a different IP, the running node can reconnect
without restarting. DNS changes do not replace a healthy connection. Changing
the configured hostname or port requires updating the TOML and restarting the
node.

DNS TTL, propagation, resolver caching, firewall rules, NAT, and exposed ports
remain deployment concerns. DNS selects an endpoint; the configured public key
and authenticated P2P handshake still determine the peer identity.

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
