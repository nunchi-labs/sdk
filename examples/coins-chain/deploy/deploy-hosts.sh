#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  examples/coins-chain/deploy/deploy-hosts.sh <testnet-dir> <ssh-host>...

Example:
  cargo run -p narae -- generate coins-chain \
    --validators 4 \
    --out testnet/deploy \
    --bind-ip 0.0.0.0 \
    --public-host 203.0.113.10 \
    --public-host 203.0.113.11 \
    --public-host 203.0.113.12 \
    --public-host 203.0.113.13 \
    --storage-dir /var/lib/nunchi/coins-chain

  examples/coins-chain/deploy/deploy-hosts.sh \
    testnet/deploy \
    root@203.0.113.10 root@203.0.113.11 root@203.0.113.12 root@203.0.113.13
EOF
}

if [[ $# -lt 2 ]]; then
  usage
  exit 2
fi

testnet_dir=$1
shift
hosts=("$@")
repo_root=$(git rev-parse --show-toplevel)
image=${COINS_CHAIN_IMAGE:-nunchi-coins-chain:latest}
remote_dir=${COINS_CHAIN_REMOTE_DIR:-/opt/nunchi/coins-chain}
image_tar=$(mktemp "${TMPDIR:-/tmp}/coins-chain-image.XXXXXX.tar")

cleanup() {
  rm -f "$image_tar"
}
trap cleanup EXIT

if [[ ! -d "$testnet_dir" ]]; then
  echo "testnet directory not found: $testnet_dir" >&2
  exit 1
fi

validator_count=$(find "$testnet_dir" -maxdepth 1 -name 'validator-*.toml' | wc -l)
if [[ "${#hosts[@]}" -ne "$validator_count" ]]; then
  echo "expected $validator_count ssh hosts, got ${#hosts[@]}" >&2
  exit 1
fi

echo "building $image"
docker build -t "$image" -f "$repo_root/examples/coins-chain/Dockerfile" "$repo_root"

echo "saving $image"
docker save "$image" -o "$image_tar"

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
  if [[ -z "$p2p_port" || -z "$rpc_port" || -z "$metrics_port" ]]; then
    echo "failed to read ports from $config" >&2
    exit 1
  fi

  echo "deploying validator-$index to $host"
  ssh "$host" "mkdir -p '$remote_dir' '$remote_dir/data'"
  scp "$image_tar" "$host:$remote_dir/image.tar"
  scp "$repo_root/examples/coins-chain/deploy/compose.yaml" "$host:$remote_dir/compose.yaml"
  scp "$config" "$host:$remote_dir/validator.toml"
  ssh "$host" "cat > '$remote_dir/.env' <<EOF
COINS_CHAIN_IMAGE=$image
P2P_PORT=$p2p_port
RPC_PORT=$rpc_port
METRICS_PORT=$metrics_port
RPC_BIND=${RPC_BIND:-127.0.0.1}
METRICS_BIND=${METRICS_BIND:-127.0.0.1}
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
