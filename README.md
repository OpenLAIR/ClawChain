<div align="center">
  <img src="assets/logo/clawchain-logo.svg" alt="ClawChain logo" width="128" height="128">
  <h1>ClawChain</h1>
  <p><strong>Secure, recoverable, and verifiable runtime control for high-privilege AI coding agents.</strong></p>
  <p>
    ClawChain turns opaque terminal agent sessions into monitored, restorable, and EVM-verifiable execution flows.
  </p>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/Runtime-Agent%20Safety-111827?style=for-the-badge" alt="Runtime Agent Safety" />
  <img src="https://img.shields.io/badge/Recovery-Snapshot%20Backed-0F766E?style=for-the-badge" alt="Snapshot-backed recovery" />
  <img src="https://img.shields.io/badge/Chain-EVM%20Verifiable-7C3AED?style=for-the-badge" alt="EVM verifiable" />
</p>

## Overview

ClawChain is a runtime safety layer for AI coding agents that can execute real commands on a real machine.

Its current product goal is straightforward:

- discover a live agent session
- bring it into a monitored control path
- detect destructive delete-style operations
- preserve recovery material before loss becomes permanent
- restore affected files or directories
- export a readable proof log
- anchor and verify proof fields on an EVM backend

This repository is not a generic blockchain demo. The chain is used to strengthen proof integrity for risky agent actions. The product itself is the control plane around monitoring, recovery, evidence, and verification.

## Current Scope

### Stable today

- Codex is the primary end-to-end supported agent path.
- Linux and Windows both support the main monitored workflow.
- One-click setup scripts exist for Linux/macOS and Windows.
- Snapshot-backed delete recovery, readable proof export, and EVM verification work together.

### Intentionally narrow

- Recovery is currently focused on destructive delete-style operations.
- Other risk classes may be recorded for audit without claiming broad rollback support.
- Multi-agent coverage exists in the codebase, but not all integrations should be treated as equally mature.

## Key Capabilities

- Monitored session onboarding with controlled resume and handoff commands
- Snapshot-backed delete recovery through a recovery vault
- Readable proof export per monitored session
- Encrypted local proof archive for downloaded proof logs
- Local EVM bootstrap for chain anchoring and verification
- Cross-platform service and daemon flow for Linux and Windows
- UI for sessions, activity, restore, proof export, and chain status

## Repository Layout

- `clawchain/`
  Main runtime, monitoring, recovery, proof, UI, and chain integration logic.
- `contracts/`
  `CommitmentAnchor.sol` and ABI used by local EVM anchoring.
- `scripts/`
  Smoke scripts and validation helpers.
- `demo/delete-smoke/`
  Tiny assets for delete and restore validation.
- `setup_clawchain.cmd`
  One-click Windows setup entrypoint.
- `setup_clawchain.sh`
  One-click Linux/macOS setup entrypoint.
- `DEVELOPER.md`
  Detailed developer workflow, architecture, and testing guide.

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
```

```bash
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

The setup scripts do the following:

1. stop an old local ClawChain service for the selected account if it exists
2. create or refresh the account configuration
3. try local EVM bootstrap
4. start the ClawChain background service
5. verify service status
6. launch the UI

By default, setup is best-effort for chain bootstrap. If you want setup to fail unless local EVM bootstrap succeeds:

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

If you run Linux setup from an SSH session, `run_clawchain_ui.sh` automatically switches to a remote-friendly binding and prints the remote browser URL.

## First Monitored Workflow

1. Start or locate a live Codex session.
2. Open the ClawChain UI.
3. Click `Join Monitor`.
4. Perform a delete-style destructive action.
5. Confirm the operation appears in history.
6. Use `Restore`.
7. Export the proof log.
8. Confirm the exported proof shows EVM fields when local chain bootstrap is enabled.

For a freshly anchored proof, the exported proof should typically include:

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

### Windows UI launcher

```bat
run_clawchain_ui.cmd 8888
```

### Linux/macOS UI launcher

```bash
bash run_clawchain_ui.sh 8888
```

### Manual chain bootstrap

```bash
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

### Chain status

```bash
python -m clawchain.agent_proxy_cli chain-status local-operator
```

### Smoke validation

#### Linux / macOS

```bash
bash scripts/run_linux_smoke.sh
bash scripts/run_linux_smoke.sh --bootstrap-local-evm
```

#### Windows

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_windows_smoke.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_windows_smoke.ps1 --bootstrap-local-evm
```

## Windows Foundry Manual Fallback

ClawChain prefers local Foundry on Windows. If automatic Foundry download fails, the usual cause is that the machine cannot reach GitHub Releases or the release asset download is blocked by local network policy.

ClawChain's managed Foundry location for the default account is:

```text
%USERPROFILE%\.clawchain-agent\local-operator\_internal\chain\toolchains\foundry\bin
```

ClawChain only needs two binaries there:

- `anvil.exe`
- `forge.exe`

### Option A: Download the latest official Windows asset with PowerShell

Run the following in PowerShell:

```powershell
$toolRoot = Join-Path $env:USERPROFILE ".clawchain-agent\local-operator\_internal\chain\toolchains\foundry"
$binDir = Join-Path $toolRoot "bin"
$zipPath = Join-Path $env:TEMP "clawchain-foundry.zip"
$unpackDir = Join-Path $env:TEMP "clawchain-foundry-unpack"

New-Item -ItemType Directory -Force -Path $binDir | Out-Null
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
Remove-Item $unpackDir -Recurse -Force -ErrorAction SilentlyContinue

$release = Invoke-RestMethod -Headers @{ "User-Agent" = "clawchain-manual-foundry" } `
  -Uri "https://api.github.com/repos/foundry-rs/foundry/releases/latest"
$asset = $release.assets |
  Where-Object { $_.name -match 'win32_amd64\.zip$' } |
  Select-Object -First 1
if (-not $asset) { throw "No Windows Foundry asset found in the latest release." }

Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath
Expand-Archive -Path $zipPath -DestinationPath $unpackDir -Force
Copy-Item (Get-ChildItem $unpackDir -Recurse -Filter anvil.exe | Select-Object -First 1).FullName $binDir -Force
Copy-Item (Get-ChildItem $unpackDir -Recurse -Filter forge.exe | Select-Object -First 1).FullName $binDir -Force
```

Then rerun:

```bat
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

### Option B: Download on another machine and copy the binaries manually

If the Windows host cannot reach GitHub at all:

1. Download the latest Windows Foundry release asset from:
   `https://github.com/foundry-rs/foundry/releases/latest`
2. Pick the asset that ends with `win32_amd64.zip`.
3. Extract it.
4. Copy `anvil.exe` and `forge.exe` into:
   `%USERPROFILE%\.clawchain-agent\local-operator\_internal\chain\toolchains\foundry\bin`
5. Rerun:

```bat
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

### Option C: Keep Foundry elsewhere and point ClawChain at it

If you already have Foundry installed in another location, you can point ClawChain at explicit paths:

```bat
set CLAWCHAIN_ANVIL_PATH=C:\tools\foundry\anvil.exe
set CLAWCHAIN_FORGE_PATH=C:\tools\foundry\forge.exe
setup_clawchain.cmd 8888
```

You can also do the same with `deploy`:

```bat
python -m clawchain.agent_proxy_cli deploy local-operator local-operator ^
  --workspace E:\path\to\workspace ^
  --anvil-path C:\tools\foundry\anvil.exe ^
  --forge-path C:\tools\foundry\forge.exe ^
  --no-start-service
```

Official Foundry sources:

- https://github.com/foundry-rs/foundry/releases/latest
- https://api.github.com/repos/foundry-rs/foundry/releases/latest
- https://getfoundry.sh/reference/forge/forge.html

## Troubleshooting

### The UI looks stale or still shows an old process

Re-run the same UI command on the same port. The launcher is designed to replace an older listener on that port.

### Windows setup says chain bootstrap failed

Run the manual diagnostic first:

```bat
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

Read these fields in the JSON output:

- `bootstrap_diagnostics.anvil_path`
- `bootstrap_diagnostics.forge_path`
- `bootstrap_diagnostics.managed_foundry_bin_contents`
- `bootstrap_diagnostics.managed_foundry_install_error`

### Proof export still shows `local-json`

That usually means you exported a proof from an older monitored session created before chain bootstrap completed. Start a new monitored session and export a fresh proof.

## Developer Documentation

For architecture notes, setup internals, testing, acceptance criteria, and debugging guidance, see [DEVELOPER.md](DEVELOPER.md).
