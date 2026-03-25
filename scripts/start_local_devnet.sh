#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RPC_URL="${CLAWCHAIN_EVM_RPC_URL:-http://127.0.0.1:8545}"
CHAIN_ID="${CLAWCHAIN_EVM_CHAIN_ID:-31337}"
HOST="${CLAWCHAIN_EVM_HOST:-127.0.0.1}"
PORT="${CLAWCHAIN_EVM_PORT:-8545}"

if command -v anvil >/dev/null 2>&1; then
  exec anvil --host "$HOST" --port "$PORT" --chain-id "$CHAIN_ID"
fi

if command -v docker >/dev/null 2>&1; then
  IMAGE="${CLAWCHAIN_FOUNDRY_IMAGE:-ghcr.io/foundry-rs/foundry:latest}"
  exec docker run --rm -it --network host "$IMAGE" anvil --host "$HOST" --port "$PORT" --chain-id "$CHAIN_ID"
fi

cat >&2 <<EOF
No local anvil binary or docker fallback is available.
Expected RPC URL: $RPC_URL
Project root: $ROOT_DIR
EOF
exit 1
