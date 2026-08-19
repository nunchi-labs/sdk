#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
EXT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
ROOT=$(cd "$EXT_DIR/../.." && pwd)
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/target"}
BIN_DIR="$TARGET_DIR/debug"

TOOL="$BIN_DIR/coins-chain-tool"
NODE="$BIN_DIR/coins-chain-node"
XTASK="$BIN_DIR/xtask"

if [[ ! -x "$TOOL" || ! -x "$NODE" || ! -x "$XTASK" ]]; then
  echo "building coins-chain binaries..."
  cargo build --locked -p nunchi-coins-chain --bins -p xtask
fi

WORKDIR=${NUNCHI_LIVE_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/nunchi-wallet-live.XXXXXX")}
mkdir -p "$WORKDIR"
NODE_PIDS=()

cleanup() {
  local pid
  for pid in "${NODE_PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${NODE_PIDS[@]:-}"; do
    wait "$pid" 2>/dev/null || true
  done
  if [[ -z "${NUNCHI_LIVE_KEEP:-}" ]]; then
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

RPC_PORT=${NUNCHI_LIVE_RPC_PORT:-18545}
P2P_PORT=${NUNCHI_LIVE_P2P_PORT:-31000}
METRICS_PORT=${NUNCHI_LIVE_METRICS_PORT:-19190}
VALIDATORS=${NUNCHI_LIVE_VALIDATORS:-4}

GENESIS="$WORKDIR/genesis.json"
ACCOUNTS="$WORKDIR/accounts.json"
TESTNET="$WORKDIR/testnet"

echo "writing funded genesis into $WORKDIR"
"$TOOL" genesis --out "$GENESIS" --accounts-out "$ACCOUNTS" --accounts 2 --seed 10000

echo "generating ${VALIDATORS}-validator local testnet"
"$XTASK" generate coins-chain \
  --validators "$VALIDATORS" \
  --out "$TESTNET" \
  --genesis-path "$GENESIS" \
  --base-port "$P2P_PORT" \
  --base-rpc-port "$RPC_PORT" \
  --base-metrics-port "$METRICS_PORT" \
  --seed 1

export RUST_LOG=${RUST_LOG:-warn}

echo "starting validators"
shopt -s nullglob
for config in "$TESTNET"/validator-*.toml; do
  "$NODE" --config "$config" &
  NODE_PIDS+=("$!")
done
shopt -u nullglob

if [[ ${#NODE_PIDS[@]} -eq 0 ]]; then
  echo "no validator configs written to $TESTNET" >&2
  exit 1
fi

RPC_URL="http://127.0.0.1:${RPC_PORT}"
echo "waiting for $RPC_URL"
for _ in $(seq 1 90); do
  if curl -sf -X POST "$RPC_URL" \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"chain.status","params":[]}' \
    | grep -q applied_height; then
    echo "rpc is up"
    export NUNCHI_LIVE_RPC="$RPC_URL"
    export NUNCHI_LIVE_ACCOUNTS="$ACCOUNTS"
    cd "$EXT_DIR"
    npm run test:live
    exit 0
  fi
  sleep 1
done

echo "coins-chain RPC did not become ready at $RPC_URL" >&2
exit 1
