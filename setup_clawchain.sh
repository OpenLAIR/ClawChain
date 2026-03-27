#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-${PORT:-8888}}"
ACCOUNT_ID="${CLAWCHAIN_ACCOUNT_ID:-local-operator}"
PASSWORD="${CLAWCHAIN_PASSWORD:-local-operator}"
WORKSPACE="${CLAWCHAIN_WORKSPACE:-$ROOT_DIR}"
ROOT_PARENT="${CLAWCHAIN_ROOT_PARENT:-}"
REQUIRE_CHAIN="${CLAWCHAIN_REQUIRE_CHAIN:-0}"
SKIP_CHAIN="${CLAWCHAIN_SKIP_CHAIN_BOOTSTRAP:-0}"
AUTO_INSTALL_FOUNDRY="${CLAWCHAIN_AUTO_INSTALL_FOUNDRY:-1}"
ANVIL_PATH="${CLAWCHAIN_ANVIL_PATH:-}"
FORGE_PATH="${CLAWCHAIN_FORGE_PATH:-}"
DEPLOYER_PRIVATE_KEY="${CLAWCHAIN_DEPLOYER_PRIVATE_KEY:-}"

is_truthy() {
  local value="${1:-}"
  case "${value,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

if command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  echo "[setup] neither python nor python3 is available on PATH" >&2
  exit 1
fi

if [[ -n "$ROOT_PARENT" ]]; then
  ACCOUNT_ROOT="$ROOT_PARENT/$ACCOUNT_ID"
else
  ACCOUNT_ROOT="$HOME/.clawchain-agent/$ACCOUNT_ID"
fi
CONFIG_PATH="$ACCOUNT_ROOT/agent-proxy.config.json"
WORKSPACE="$(cd "$WORKSPACE" && pwd)"

cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

run_cmd() {
  printf '[setup]'
  for token in "$@"; do
    printf ' %q' "$token"
  done
  printf '\n'
  "$@"
}

if [[ -f "$CONFIG_PATH" ]]; then
  run_cmd "$PYTHON_BIN" -m clawchain.agent_proxy_cli service-stop "$CONFIG_PATH" || true
fi

deploy_args=(
  "$PYTHON_BIN" -m clawchain.agent_proxy_cli deploy
  "$ACCOUNT_ID" "$PASSWORD"
  --workspace "$WORKSPACE"
  --no-start-service
)
if [[ -n "$ROOT_PARENT" ]]; then
  deploy_args+=(--root-dir "$ROOT_PARENT")
fi
if ! is_truthy "$AUTO_INSTALL_FOUNDRY"; then
  deploy_args+=(--no-auto-install-foundry)
fi
if [[ -n "$ANVIL_PATH" ]]; then
  deploy_args+=(--anvil-path "$ANVIL_PATH")
fi
if [[ -n "$FORGE_PATH" ]]; then
  deploy_args+=(--forge-path "$FORGE_PATH")
fi
run_cmd "${deploy_args[@]}"

chain_ok=0
if ! is_truthy "$SKIP_CHAIN"; then
  chain_args=(
    "$PYTHON_BIN" -m clawchain.agent_proxy_cli chain-connect
    "$ACCOUNT_ID"
    --bootstrap-local-evm
  )
  if [[ -n "$ROOT_PARENT" ]]; then
    chain_args+=(--root-dir "$ROOT_PARENT")
  fi
  if [[ -n "$DEPLOYER_PRIVATE_KEY" ]]; then
    chain_args+=(--deployer-private-key "$DEPLOYER_PRIVATE_KEY")
  fi
  if run_cmd "${chain_args[@]}"; then
    chain_ok=1
  elif is_truthy "$REQUIRE_CHAIN"; then
    echo "[setup] chain bootstrap failed and CLAWCHAIN_REQUIRE_CHAIN is enabled" >&2
    exit 1
  else
    echo "[setup] chain bootstrap failed; continuing with local setup and UI startup" >&2
  fi
fi

run_cmd "$PYTHON_BIN" -m clawchain.agent_proxy_cli service-start "$CONFIG_PATH"
run_cmd "$PYTHON_BIN" -m clawchain.agent_proxy_cli service-status "$CONFIG_PATH"
if [[ "$chain_ok" == "1" ]]; then
  chain_status_args=("$PYTHON_BIN" -m clawchain.agent_proxy_cli chain-status "$ACCOUNT_ID")
  if [[ -n "$ROOT_PARENT" ]]; then
    chain_status_args+=(--root-dir "$ROOT_PARENT")
  fi
  run_cmd "${chain_status_args[@]}" || true
fi

echo "[setup] account: $ACCOUNT_ID"
echo "[setup] account root: $ACCOUNT_ROOT"
echo "[setup] config path: $CONFIG_PATH"
echo "[setup] workspace: $WORKSPACE"
if is_truthy "$SKIP_CHAIN"; then
  echo "[setup] chain bootstrap: skipped"
elif [[ "$chain_ok" == "1" ]]; then
  echo "[setup] chain bootstrap: ok"
else
  echo "[setup] chain bootstrap: warning"
fi
echo "[setup] launching UI on port $PORT"
exec bash "$ROOT_DIR/run_clawchain_ui.sh" "$PORT"
