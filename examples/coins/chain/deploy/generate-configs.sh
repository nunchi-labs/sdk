#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  examples/coins/chain/deploy/generate-configs.sh <xtask generate coins-chain args...>

Example:
  cargo run -p nunchi-coins-chain --bin coins-chain-tool -- genesis \
    --out testnet/deploy/genesis.json \
    --accounts 8

  examples/coins/chain/deploy/generate-configs.sh \
    --validators 4 \
    --out testnet/deploy \
    --genesis-path testnet/deploy/genesis.json \
    --bind-ip 0.0.0.0 \
    --public-host 203.0.113.10 \
    --public-host 203.0.113.11 \
    --public-host 203.0.113.12 \
    --public-host 203.0.113.13 \
    --storage-dir /var/lib/nunchi/coins-chain

Environment:
  COINS_CHAIN_TOOLS_IMAGE  Tools image tag. Default: nunchi-xtask:latest
EOF
}

if [[ $# -eq 0 ]]; then
  usage
  exit 2
fi

repo_root=$(git rev-parse --show-toplevel)
tools_image=${COINS_CHAIN_TOOLS_IMAGE:-nunchi-xtask:latest}

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$repo_root:/workspace" \
  -w /workspace \
  "$tools_image" \
  generate coins-chain "$@"
