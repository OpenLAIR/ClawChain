#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-8888}"
HOST="${HOST:-127.0.0.1}"

cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR"

echo "[clawchain] starting UI on http://${HOST}:${PORT}"
exec python -m clawchain.agent_proxy_cli ui --host "$HOST" --port "$PORT"
