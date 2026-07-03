#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  examples/coins/chain/deploy/deploy-hosts.sh <image-tar> <testnet-dir> <ssh-host>...

Example:
  cargo run -p nunchi-coins-chain --bin coins-chain-tool -- genesis \
    --out testnet/deploy/genesis.json \
    --accounts 8

  cargo run -p xtask -- generate coins-chain \
    --validators 4 \
    --out testnet/deploy \
    --genesis-path testnet/deploy/genesis.json \
    --bind-ip 0.0.0.0 \
    --public-host 203.0.113.10 \
    --public-host 203.0.113.11 \
    --public-host 203.0.113.12 \
    --public-host 203.0.113.13 \
    --storage-dir /var/lib/nunchi/coins-chain

  examples/coins/chain/deploy/deploy-hosts.sh \
    /tmp/nunchi-coins-chain/coins-chain-node.tar \
    testnet/deploy \
    root@203.0.113.10 root@203.0.113.11 root@203.0.113.12 root@203.0.113.13
EOF
}

if [[ $# -lt 3 ]]; then
  usage
  exit 2
fi

image_tar=$1
testnet_dir=$2
shift 2
hosts=("$@")
repo_root=$(git rev-parse --show-toplevel)
image=${COINS_CHAIN_IMAGE:-nunchi-coins-chain:latest}
indexer_image=${COINS_INDEXER_IMAGE:-nunchi-coins-indexer:latest}
remote_dir=${COINS_CHAIN_REMOTE_DIR:-/opt/nunchi/coins-chain}

if [[ ! -d "$testnet_dir" ]]; then
  echo "testnet directory not found: $testnet_dir" >&2
  exit 1
fi

if [[ ! -f "$image_tar" ]]; then
  echo "image tar not found: $image_tar" >&2
  exit 1
fi

validator_count=$(find "$testnet_dir" -maxdepth 1 -name 'validator-*.toml' | wc -l)
if [[ "${#hosts[@]}" -ne "$validator_count" ]]; then
  echo "expected $validator_count ssh hosts, got ${#hosts[@]}" >&2
  exit 1
fi

manifest="$testnet_dir/narae.toml"
indexer_identity=""
indexer_output=""
indexer_participants=""
if [[ -f "$manifest" ]]; then
  indexer_identity=$(sed -n -E 's/^identity = "([^"]+)"$/\1/p' "$manifest")
  indexer_output=$(sed -n -E 's/^output = "([^"]+)"$/\1/p' "$manifest")
  indexer_participants=$(sed -n -E 's/^participants = ([0-9]+)$/\1/p' "$manifest")
fi

for index in "${!hosts[@]}"; do
  host=${hosts[$index]}
  config="$testnet_dir/validator-$index.toml"
  if [[ ! -f "$config" ]]; then
    echo "missing config for validator $index: $config" >&2
    exit 1
  fi

  p2p_port=$(sed -n -E 's/^listen_address = ".*:([0-9]+)"$/\1/p' "$config")
  rpc_port=$(sed -n -E 's/^rpc_address = ".*:([0-9]+)"$/\1/p' "$config")
  metrics_port=$(sed -n -E 's/^metrics_address = ".*:([0-9]+)"$/\1/p' "$config")
  genesis_path=$(sed -n -E 's/^genesis_path = "([^"]+)"$/\1/p' "$config")
  if [[ -z "$p2p_port" || -z "$rpc_port" || -z "$metrics_port" ]]; then
    echo "failed to read ports from $config" >&2
    exit 1
  fi
  genesis_source=""
  if [[ -n "$genesis_path" ]]; then
    if [[ "$genesis_path" = /* ]]; then
      genesis_source="$genesis_path"
    else
      genesis_source="$(dirname "$config")/$genesis_path"
    fi
    if [[ ! -f "$genesis_source" && -f "$testnet_dir/genesis.json" ]]; then
      genesis_source="$testnet_dir/genesis.json"
    fi
    if [[ ! -f "$genesis_source" ]]; then
      echo "missing genesis file for validator $index: $genesis_path" >&2
      exit 1
    fi
  fi

  echo "deploying validator-$index to $host"
  ssh "$host" "mkdir -p '$remote_dir' '$remote_dir/data' && chown -R 10001:10001 '$remote_dir/data'"
  scp "$image_tar" "$host:$remote_dir/image.tar"
  scp "$repo_root/examples/coins/chain/deploy/compose.yaml" "$host:$remote_dir/compose.yaml"
  scp "$config" "$host:$remote_dir/validator.toml"
  if [[ -n "$genesis_source" ]]; then
    scp "$genesis_source" "$host:$remote_dir/genesis.json"
    ssh "$host" "sed -i -E 's|^genesis_path = \".*\"$|genesis_path = \"/etc/nunchi/coins-chain/genesis.json\"|' '$remote_dir/validator.toml'"
  fi
  ssh "$host" "cat > '$remote_dir/.env' <<EOF
COINS_CHAIN_IMAGE=$image
COINS_INDEXER_IMAGE=$indexer_image
INDEXER_IDENTITY=$indexer_identity
INDEXER_OUTPUT=$indexer_output
INDEXER_PARTICIPANTS=$indexer_participants
P2P_PORT=$p2p_port
RPC_PORT=$rpc_port
METRICS_PORT=$metrics_port
RPC_BIND=${RPC_BIND:-127.0.0.1}
METRICS_BIND=${METRICS_BIND:-127.0.0.1}
NODE_EXPORTER_BIND=${NODE_EXPORTER_BIND:-127.0.0.1}
NODE_EXPORTER_PORT=${NODE_EXPORTER_PORT:-9100}
NODE_EXPORTER_TAG=${NODE_EXPORTER_TAG:-v1.8.2}
EOF
docker load -i '$remote_dir/image.tar'
cd '$remote_dir'
if docker compose version >/dev/null 2>&1; then
  docker compose up -d
elif command -v docker-compose >/dev/null 2>&1; then
  docker-compose up -d
else
  echo 'docker compose plugin or docker-compose is required' >&2
  exit 1
fi
"
done
