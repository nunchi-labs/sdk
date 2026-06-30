# coins-chain Docker Deployment

This runs one `coins-chain-node` validator per server with Docker and Docker
Compose. The P2P port is public, while RPC and metrics bind to loopback by
default.

Build and generate four remote configs from the repo root:

```sh
cargo run -p narae -- generate coins-chain \
  --validators 4 \
  --out testnet/hetzner \
  --bind-ip 0.0.0.0 \
  --public-host <server-0-ip> \
  --public-host <server-1-ip> \
  --public-host <server-2-ip> \
  --public-host <server-3-ip> \
  --storage-dir /var/lib/nunchi/coins-chain
```

Deploy to the hosts:

```sh
examples/coins-chain/deploy/deploy-hosts.sh \
  testnet/hetzner \
  root@<server-0-ip> root@<server-1-ip> root@<server-2-ip> root@<server-3-ip>
```

Open firewall access between validators for the P2P ports:

```text
30000/tcp and 30000/udp on server 0
30001/tcp and 30001/udp on server 1
30002/tcp and 30002/udp on server 2
30003/tcp and 30003/udp on server 3
```

RPC and metrics are bound to `127.0.0.1` by compose. Use SSH forwarding to query
a node:

```sh
ssh -L 8545:127.0.0.1:8545 root@<server-0-ip>
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain.status","params":[]}' \
  http://127.0.0.1:8545
```

Set `RPC_BIND=0.0.0.0` before running `deploy-hosts.sh` only if the RPC endpoint
is protected by a firewall or private network.
