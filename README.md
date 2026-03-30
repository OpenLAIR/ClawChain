<div align="center">
  <img src="assets/logo/ClawChain.png" alt="ClawChain logo" width="148">
  <h1>ClawChain</h1>
  <p><strong>Secure, recoverable, and traceable runtime control for high-privilege AI coding agents.</strong></p>
  <p>
    This isolated repository is the integration lab for the generalized shell-agent adapter layer that extends ClawChain beyond Codex.
  </p>
  <p>
    <a href="README.zh-CN.md">中文说明</a> · <a href="DEVELOPER.md">Developer Guide</a>
  </p>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/Validated-Codex-111827?style=for-the-badge" alt="Validated Codex" />
  <img src="https://img.shields.io/badge/Validated-Claude%20Code-C2410C?style=for-the-badge" alt="Validated Claude Code" />
  <img src="https://img.shields.io/badge/Chain-EVM%2031337-7C3AED?style=for-the-badge" alt="EVM 31337" />
</p>

## Dashboard

<p align="center">
  <img src="assets/screenshots/dashboard.png" alt="ClawChain dashboard" width="1200">
</p>

The dashboard is the operator surface for session discovery, `Join Monitor`, dangerous-operation review, restore, proof export, and chain inspection.

## What This Repo Is

This repository is not the stable mainline release repository.

It is the isolated integration branch where ClawChain is being generalized from a Codex-first path into a reusable shell-agent control layer. The current focus of this fork is to make the integration interface extensible and validate a real Claude Code workflow before merging the changes back into the main project.

## Why ClawChain Exists

High-privilege coding agents can execute real commands on real machines. That creates four practical failures that are hard to manage in a normal terminal workflow:

- execution becomes opaque
- evidence is easy to lose
- recovery is incomplete after destructive actions
- post-incident tracing is difficult

ClawChain turns those sessions into a monitored runtime with controlled onboarding, dangerous-operation capture, snapshot-backed recovery, proof export, and optional EVM anchoring.

## Validated In This Fork

### Stable and validated now

- Codex main path remains available and has been regression-checked after the adapter refactor.
- Claude Code has been integrated through the new shell-agent adapter path.
- Claude Code end-to-end validation has passed for `Join Monitor -> delete -> Restore -> proof -> verify`.
- Linux and Windows setup, service, UI, and local EVM bootstrap have been validated in this branch.

### In progress

- Gemini CLI is planned next on top of the same adapter layer.
- Additional shell-style agents can be added by registering a new agent profile instead of copying the old Codex-specific launcher logic.

## What Changed In This Fork

- A generalized shell-agent profile layer for launcher, resume, handoff, and environment setup
- Claude Code integration built on the shared adapter path instead of Codex-only wiring
- Stronger Claude session-id detection and routing behavior
- UI fixes for mixed native/managed terminals and session-card misrouting
- Faster live session inspection on Linux by reducing expensive process metadata calls

## Core Capabilities

- discover a live agent session
- bring that session into a monitored control path
- detect destructive operations before loss becomes permanent
- preserve snapshot-backed recovery material
- restore affected files or directories
- export readable proof logs
- verify proof fields locally and on an EVM backend

## Requirements

- Python 3.12
- `pip`
- Git
- For local chain bootstrap:
  - preferred: Foundry (`anvil`, `forge`)
  - optional fallback: Docker when available

## Installation

```bash
conda create -y -n ClawChain python=3.12 pip
conda activate ClawChain
cd <repo-root>
pip install -r requirements.txt
pip install -e .
```

## Quick Start

### Windows

```bat
setup_clawchain.cmd 8888
```

### Linux / macOS

```bash
bash setup_clawchain.sh 8888
```

The setup flow does the following:

1. stops an old ClawChain service for the selected account if it exists
2. creates or refreshes the account configuration
3. bootstraps local EVM if possible
4. starts the background service
5. verifies service status
6. launches the UI

If you want setup to fail unless local chain bootstrap succeeds:

### Windows strict mode

```bat
set CLAWCHAIN_REQUIRE_CHAIN=1
setup_clawchain.cmd 8888
```

### Linux / macOS strict mode

```bash
CLAWCHAIN_REQUIRE_CHAIN=1 bash setup_clawchain.sh 8888
```

## Open the UI

### Same machine

```text
http://127.0.0.1:8888
```

### Remote Linux host

If you run Linux setup from SSH, `run_clawchain_ui.sh` automatically switches to a remote-friendly bind and prints the remote browser URL.

## First Claude Workflow To Validate

1. Start a fresh Claude Code session.
2. Open the ClawChain UI.
3. Click `Join Monitor`.
4. Continue in the ClawChain-managed terminal, not the original native terminal.
5. Perform a delete-style destructive action.
6. Confirm the operation appears in history.
7. Run `Restore`.
8. Export the proof log.
9. Confirm the exported proof shows EVM fields when local chain bootstrap is enabled.

For a successful anchored proof, you should typically see:

- `anchor_backend: "evm:31337"`
- `anchor_mode: "evm-anchored"`
- `anchor_status: "confirmed"`
- `anchor_lookup_found: true`
- `anchor_field_checks.session_id = true`
- `anchor_field_checks.batch_seq_no = true`
- `anchor_field_checks.merkle_root = true`

## Useful Commands

### UI only

```bash
python -m clawchain.agent_proxy_cli ui --host 127.0.0.1 --port 8888
```

### Manual chain bootstrap

```bash
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

### Chain status

```bash
python -m clawchain.agent_proxy_cli chain-status local-operator
```

### Claude adapter smoke

```bash
python scripts/smoke_claude_adapter.py
```

### Platform smoke

#### Linux / macOS

```bash
bash scripts/run_linux_smoke.sh
bash scripts/run_linux_smoke.sh --bootstrap-local-evm
```

#### Windows

```bat
powershell -ExecutionPolicy Bypass -File scripts/run_windows_smoke.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_windows_smoke.ps1 --bootstrap-local-evm
```

## Repository Layout

- `clawchain/`
  Main runtime, monitoring, recovery, proof, UI, and agent integration logic.
- `assets/`
  GitHub-facing logo, diagrams, and dashboard screenshots.
- `contracts/`
  `CommitmentAnchor.sol` and ABI used by local EVM anchoring.
- `scripts/`
  Platform smoke scripts, dangerous-ops validation, and Claude adapter smoke.
- `setup_clawchain.cmd`
  One-click Windows setup entrypoint.
- `setup_clawchain.sh`
  One-click Linux/macOS setup entrypoint.
- `DEVELOPER.md`
  Detailed architecture, development workflow, and test guide.

## Branch Status

This branch is intended for isolated integration and validation. It is the place to stabilize the generalized agent-adapter layer before merging the work back into the main ClawChain repository.
