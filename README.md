<div align="center">
  <img src="assets/logo/ClawChain.png" alt="ClawChain logo" width="148">
  <h1>ClawChain</h1>
  <p><strong>Secure, recoverable, and traceable runtime control for high-privilege AI coding agents.</strong></p>
  <p>
    ClawChain turns opaque agent sessions into monitored execution flows with controlled handoff, snapshot-backed recovery, readable proof export, and EVM-verifiable evidence.
  </p>
  <p>
    <a href="README.zh-CN.md">中文说明</a> · <a href="DEVELOPER.md">Developer Guide</a>
  </p>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/Validated-Codex-111827?style=for-the-badge" alt="Validated Codex" />
  <img src="https://img.shields.io/badge/Validated-Claude%20Code-C2410C?style=for-the-badge" alt="Validated Claude Code" />
  <img src="https://img.shields.io/badge/Recovery-Snapshot%20Backed-0F766E?style=for-the-badge" alt="Snapshot-backed recovery" />
  <img src="https://img.shields.io/badge/Chain-EVM%2031337-7C3AED?style=for-the-badge" alt="EVM 31337" />
</p>

## Dashboard

<p align="center">
  <img src="assets/screenshots/dashboard.png" alt="ClawChain dashboard" width="1200">
</p>

The dashboard is the main operator surface for session discovery, `Join Monitor`, dangerous-operation review, restore, proof export, and chain inspection.

## Overview

ClawChain is a runtime safety layer for AI coding agents that can execute real commands on real machines.

It is designed to solve four practical failures that appear when a high-privilege agent is allowed to operate directly in a terminal:

- execution is opaque while the session is running
- evidence is easy to lose after destructive actions
- recovery is incomplete when important files disappear
- post-incident tracing is difficult and fragmented

ClawChain turns those sessions into a controlled runtime with:

- monitored onboarding and controlled handoff
- dangerous-operation capture
- snapshot-backed recovery
- readable proof export
- optional EVM anchoring and verification

This is not a generic blockchain demo. The chain backend is used to strengthen proof integrity for risky agent actions. The product itself is the control plane around monitoring, recovery, evidence, and verification.

## Validated Agent Support

### Validated now

- Codex
  End-to-end monitored workflow with restore, proof export, and chain verification.
- Claude Code
  Real session detection, controlled relaunch, monitored restore flow, proof export, and EVM verification.

### Adapter-ready path

The runtime is structured to support additional shell-style agent integrations through a shared adapter layer. Future agents can be added by extending the profile model instead of cloning launcher logic.

## Core Capabilities

- discover a live agent session
- bring that session into a monitored control path
- detect destructive operations before loss becomes permanent
- preserve snapshot-backed recovery material
- restore affected files or directories
- export readable proof logs per monitored session
- verify proof fields locally and on an EVM backend
- inspect sessions, activity, restore actions, proof state, and chain status in one UI

## Supported Platforms

- Linux
- Windows
- macOS setup path via the Unix shell flow

Linux and Windows have both been validated on the main monitored workflow, including setup, service, UI, recovery, proof export, and local EVM bootstrap.

## Repository Layout

- `clawchain/`
  Runtime, monitoring, recovery, proof, UI, chain integration, and agent adapter logic.
- `assets/`
  GitHub-facing logo, diagrams, and dashboard screenshots.
- `contracts/`
  `CommitmentAnchor.sol` and ABI used by local EVM anchoring.
- `scripts/`
  Platform smoke scripts, EVM smoke, and adapter validation helpers.
- `setup_clawchain.cmd`
  One-click Windows setup entrypoint.
- `setup_clawchain.sh`
  One-click Linux/macOS setup entrypoint.
- `DEVELOPER.md`
  Detailed architecture, implementation notes, and test guide.

## Requirements

- Python 3.12
- `pip`
- Git
- For local chain bootstrap:
  - preferred: Foundry (`anvil`, `forge`)
  - optional fallback: Docker where available

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
3. bootstraps local EVM when available
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

If setup is launched from an SSH session, `run_clawchain_ui.sh` automatically switches to a remote-friendly bind and prints the correct browser URL.

## First Monitored Workflow

### Codex or Claude Code

1. Start a fresh agent session.
2. Open the ClawChain UI.
3. Click `Join Monitor`.
4. Continue only in the ClawChain-managed terminal.
5. Perform a delete-style destructive action.
6. Confirm the operation appears in history.
7. Run `Restore`.
8. Export the proof log.
9. Confirm the exported proof shows EVM fields when local chain bootstrap is enabled.

For a successfully anchored proof, you should typically see:

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

### EVM smoke

```bash
bash scripts/run_evm_smoke.sh
```

## Foundry Notes

ClawChain prefers local Foundry on all platforms.

Bootstrap order:

1. explicit `anvil` and `forge` paths
2. managed toolchain under the account-local Foundry directory
3. automatic Foundry download from official releases
4. optional Docker fallback where available

### Windows manual Foundry fallback

If Foundry auto-download does not succeed on Windows, install it manually and rerun chain bootstrap.

#### Option 1: download the official release asset directly

Open the latest Foundry release page:

- <https://github.com/foundry-rs/foundry/releases/latest>

Download the Windows asset named like:

- `foundry_v<version>_win32_amd64.zip`

Extract `anvil.exe` and `forge.exe`, then either:

- place them on your `PATH`, or
- copy them into the ClawChain-managed toolchain directory for the current account

Default managed directory:

```text
%USERPROFILE%\.clawchain-agent\local-operator\_internal\chain\toolchains\foundry\bin
```

#### Option 2: configure explicit binary paths

```bat
set CLAWCHAIN_ANVIL_PATH=C:\path\to\anvil.exe
set CLAWCHAIN_FORGE_PATH=C:\path\to\forge.exe
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

If bootstrap still fails, run:

```bat
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

Then inspect the diagnostics fields in the JSON output:

- `bootstrap_diagnostics.anvil_path`
- `bootstrap_diagnostics.forge_path`
- `bootstrap_diagnostics.managed_foundry_bin_dir`
- `bootstrap_diagnostics.managed_foundry_bin_contents`
- `bootstrap_diagnostics.managed_foundry_install_error`

## Proof Expectations

For a newly anchored session proof:

- `format = clawchain-proof-log.v2`
- `exported_at` is a full ISO 8601 timestamp
- `session.status = monitored`
- snapshot locations point into `recovery-vault/recovery-snapshots`
- restored operations show `restored = true`
- `proof_cards[].anchor_backend = evm:31337`
- `proof_cards[].anchor_mode = evm-anchored`
- `proof_cards[].anchor_status = confirmed`

## More Detail

- [README.zh-CN.md](README.zh-CN.md)
- [DEVELOPER.md](DEVELOPER.md)
