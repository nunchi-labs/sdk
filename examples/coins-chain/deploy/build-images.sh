#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  examples/coins-chain/deploy/build-images.sh <out-dir>

Environment:
  COINS_CHAIN_IMAGE        Runtime image tag. Default: nunchi-coins-chain:latest
  COINS_CHAIN_TOOLS_IMAGE  Tools image tag. Default: nunchi-xtask:latest
EOF
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

out_dir=$1
repo_root=$(git rev-parse --show-toplevel)
runtime_image=${COINS_CHAIN_IMAGE:-nunchi-coins-chain:latest}
tools_image=${COINS_CHAIN_TOOLS_IMAGE:-nunchi-xtask:latest}

mkdir -p "$out_dir"

echo "building runtime image: $runtime_image"
docker build \
  --target runtime \
  -t "$runtime_image" \
  -f "$repo_root/examples/coins-chain/Dockerfile" \
  "$repo_root"

echo "saving runtime image"
docker save "$runtime_image" -o "$out_dir/coins-chain-node.tar"

echo "building tools image: $tools_image"
docker build \
  --target tools \
  -t "$tools_image" \
  -f "$repo_root/examples/coins-chain/Dockerfile" \
  "$repo_root"

echo "wrote $out_dir/coins-chain-node.tar"
