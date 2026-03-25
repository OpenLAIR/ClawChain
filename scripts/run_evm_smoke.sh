#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="${CLAWCHAIN_EVM_MANIFEST_PATH:-$ROOT_DIR/runs/clawchain_chain_probe/deployment.json}"

cd "$ROOT_DIR"
python -m clawchain.deployment_preflight_example
python -m clawchain.deployment_verification_example
python -m clawchain.chain_readback_example

cat <<EOF

Smoke sequence completed.
Manifest path: $MANIFEST_PATH
If deployment verification still reports rpc_unreachable or contract_code_missing,
start a devnet and deploy CommitmentAnchor before rerunning this script.
EOF
