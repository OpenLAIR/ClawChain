#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-8888}"
ACCESS_MODE="${ACCESS_MODE:-auto}"
HOST_OVERRIDE="${HOST:-}"

if command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  echo "[clawchain] python or python3 is required on PATH" >&2
  exit 1
fi

resolve_primary_ipv4() {
  if command -v hostname >/dev/null 2>&1; then
    local token
    for token in $(hostname -I 2>/dev/null); do
      case "$token" in
        127.*|169.254.*|172.17.*|::* )
          continue
          ;;
        *.*)
          printf '%s\n' "$token"
          return 0
          ;;
      esac
    done
  fi
  printf '127.0.0.1\n'
}

if [[ -n "$HOST_OVERRIDE" ]]; then
  HOST="$HOST_OVERRIDE"
  RESOLVED_MODE="manual"
elif [[ "$ACCESS_MODE" == "remote" ]]; then
  HOST="0.0.0.0"
  RESOLVED_MODE="remote"
elif [[ "$ACCESS_MODE" == "local" ]]; then
  HOST="127.0.0.1"
  RESOLVED_MODE="local"
elif [[ "$ACCESS_MODE" == "auto" ]]; then
  if [[ -n "${SSH_CONNECTION:-}" || -n "${SSH_CLIENT:-}" || -n "${SSH_TTY:-}" ]]; then
    HOST="0.0.0.0"
    RESOLVED_MODE="remote"
  else
    HOST="127.0.0.1"
    RESOLVED_MODE="local"
  fi
else
  echo "[clawchain] unsupported ACCESS_MODE: $ACCESS_MODE" >&2
  echo "[clawchain] use ACCESS_MODE=auto|local|remote" >&2
  exit 2
fi

PRIMARY_IP="$(resolve_primary_ipv4)"
REMOTE_URL="http://${PRIMARY_IP}:${PORT}"
LOCAL_URL="http://127.0.0.1:${PORT}"
SSH_USER="${USER:-<user>}"

cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

echo "[clawchain] access mode: ${RESOLVED_MODE}"
echo "[clawchain] starting UI on ${LOCAL_URL}"
if [[ "$HOST" == "0.0.0.0" ]]; then
  echo "[clawchain] remote browser URL: ${REMOTE_URL}"
  echo "[clawchain] ssh tunnel fallback: ssh -L ${PORT}:127.0.0.1:${PORT} ${SSH_USER}@${PRIMARY_IP}"
else
  echo "[clawchain] remote browser cannot use 127.0.0.1 directly"
  echo "[clawchain] if you are on another machine, use: ssh -L ${PORT}:127.0.0.1:${PORT} ${SSH_USER}@${PRIMARY_IP}"
fi

exec "$PYTHON_BIN" -m clawchain.agent_proxy_cli ui --host "$HOST" --port "$PORT" --replace-existing
