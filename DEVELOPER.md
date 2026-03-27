# ClawChain Developer Guide

This document is for contributors who need to modify ClawChain runtime behavior, UI flows, proof export, chain integration, or cross-platform setup and testing.

README.md stays user-facing and deployment-oriented. This file is intentionally more operational.

## Scope

Use this guide when you need detailed information about:

- local development workflow
- repository architecture
- setup and bootstrap internals
- cross-platform validation
- proof export acceptance criteria
- debugging Windows and Linux differences

## Recommended Environment

- Python 3.12
- `pip install -r requirements.txt`
- `pip install -e .`
- a Conda environment such as `ClawChain`

Useful optional tools:

- Foundry: `anvil`, `forge`
- Docker as a secondary fallback only
- tmux on Linux

## Repository Map

### Runtime modules

- `clawchain/agent_proxy.py`
  Runtime bootstrap, Foundry handling, local EVM setup, session proxy helpers.
- `clawchain/agent_proxy_cli.py`
  Main CLI entrypoint, setup commands, proof building, service flow, chain commands.
- `clawchain/ui_server.py`
  UI backend, proof export, session views, restore actions.
- `clawchain/agent_proxy_config.py`
  Stored config model and persistence.
- `clawchain/agent_proxy_daemon.py`
  Background service daemon plus Windows/Linux IPC behavior.
- `clawchain/host_monitor.py`
  Running agent discovery and session matching.
- `clawchain/runtime/`
  Evidence, recovery, remote sink, and runtime helpers.

### Root scripts

- `setup_clawchain.cmd`
  Windows one-click setup entrypoint.
- `setup_clawchain.ps1`
  Windows setup implementation.
- `setup_clawchain.sh`
  Linux/macOS one-click setup entrypoint.
- `run_clawchain_ui.cmd`
  Windows UI launcher.
- `run_clawchain_ui.sh`
  Linux/macOS UI launcher with remote-access logic.

### Validation scripts

- `scripts/run_windows_smoke.ps1`
- `scripts/run_windows_smoke.cmd`
- `scripts/run_linux_smoke.sh`
- `scripts/platform_smoke.py`

## Runtime Model

ClawChain is easiest to reason about as four connected layers.

### 1. Session discovery and monitoring

- find candidate agent sessions
- convert them into ClawChain session metadata
- support safe resume and handoff into monitoring

### 2. Controlled execution

- route a monitored session into a managed runtime path
- preserve enough metadata to reconnect later
- keep the UI and service aware of the same monitored identity

### 3. Recovery and evidence

- detect delete-style destructive operations
- capture recovery material into the recovery vault
- write recovery catalogs, impact sets, receipts, and submissions
- build proof cards from recovery plus chain metadata

### 4. Chain anchoring and verification

- bootstrap or consume an EVM deployment manifest
- anchor proof commitments on `CommitmentAnchor`
- verify card fields back against the configured backend

## Setup Internals

### Windows setup flow

`setup_clawchain.cmd` delegates to `setup_clawchain.ps1`.

The current PowerShell flow is:

1. stop the old service if present
2. run `deploy` for the chosen account without starting the service
3. run `chain-connect --bootstrap-local-evm` unless disabled
4. run `service-start`
5. run `service-status`
6. run `chain-status` when chain bootstrap succeeded
7. launch the UI

Important environment variables:

- `CLAWCHAIN_ACCOUNT_ID`
- `CLAWCHAIN_PASSWORD`
- `CLAWCHAIN_WORKSPACE`
- `CLAWCHAIN_ROOT_PARENT`
- `CLAWCHAIN_AUTO_INSTALL_FOUNDRY`
- `CLAWCHAIN_ANVIL_PATH`
- `CLAWCHAIN_FORGE_PATH`
- `CLAWCHAIN_SKIP_CHAIN_BOOTSTRAP`
- `CLAWCHAIN_REQUIRE_CHAIN`
- `CLAWCHAIN_DEPLOYER_PRIVATE_KEY`

### Linux/macOS setup flow

`setup_clawchain.sh` mirrors the same sequence with shell-native path handling and remote-friendly UI launch behavior.

### Foundry bootstrap strategy

Preferred order:

1. explicit `anvil_path` and `forge_path`
2. managed toolchain under account-local `toolchains/foundry/bin`
3. automatic Foundry download from official releases
4. optional Docker fallback where still supported

Important principle:

- Docker is not the preferred Windows path.
- Local Foundry is the intended Windows path.

## Windows Foundry Auto-Install Notes

The Windows auto-install logic now matches Foundry release assets using the current upstream naming pattern:

- `win32_amd64.zip`

If that naming changes again, update the matcher in `clawchain/agent_proxy.py` and re-run Windows bootstrap validation.

When `chain-connect --bootstrap-local-evm` fails on Windows, check the diagnostics object for:

- `managed_foundry_bin_dir`
- `managed_foundry_bin_exists`
- `managed_foundry_bin_contents`
- `managed_foundry_install_error`

The managed toolchain directory for the default account is:

```text
%USERPROFILE%\.clawchain-agent\local-operator\_internal\chain\toolchains\foundry\bin
```

README contains the user-facing manual install steps. Keep this file and README aligned whenever the bootstrap path changes.

## Proof Export Notes

Current proof export expectations:

- `exported_at` is full ISO 8601, not time-only
- `session.evidence.snapshot_locations` uses `recovery-vault/recovery-snapshots/...`
- `session_dangerous_operations[].target_root` should match the absolute `proof_cards[].target_root`
- chain state should be reflected back into exported proof evidence when available

Do not change recovery semantics just to fix export presentation. If the issue is representational, prefer export-only normalization.

## Fast Validation Commands

### Syntax checks

```bash
python -m py_compile clawchain/agent_proxy.py clawchain/agent_proxy_cli.py clawchain/ui_server.py
```

### Linux smoke

```bash
bash scripts/run_linux_smoke.sh
bash scripts/run_linux_smoke.sh --bootstrap-local-evm
```

### Windows smoke

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_windows_smoke.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_windows_smoke.ps1 --bootstrap-local-evm
```

## Manual Acceptance Flow

### Linux acceptance

1. Run `bash setup_clawchain.sh 8888`
2. Confirm `python -m clawchain.agent_proxy_cli chain-status local-operator` returns `ok: true`
3. Open the printed UI URL
4. Join a fresh Codex session
5. Trigger a delete action
6. Restore it
7. Export the proof log
8. Confirm proof fields show EVM anchor data

### Windows acceptance

1. Run `setup_clawchain.cmd 8888`
2. Confirm `python -m clawchain.agent_proxy_cli chain-status local-operator` returns `ok: true`
3. Open `http://127.0.0.1:8888`
4. Join a fresh Codex session
5. Trigger a delete action
6. Restore it
7. Export the proof log
8. Confirm the exported proof shows a fresh `evm:31337` anchor, not `local-json`

## Proof Export Acceptance Criteria

For a newly anchored session proof, all of the following should hold:

- `format = clawchain-proof-log.v2`
- `exported_at` is a full ISO 8601 timestamp
- `session.status = monitored`
- at least one `session_dangerous_operations` entry exists for the delete action
- `restored = true` for the restored operation
- snapshot locations point into `recovery-vault/recovery-snapshots`
- `session_dangerous_operations[].target_root` matches `proof_cards[].target_root`
- `proof_cards[].anchor_backend = evm:31337`
- `proof_cards[].anchor_mode = evm-anchored`
- `proof_cards[].anchor_status = confirmed`
- `proof_cards[].anchor_lookup_found = true`
- `proof_cards[].anchor_field_checks.session_id = true`
- `proof_cards[].anchor_field_checks.batch_seq_no = true`
- `proof_cards[].anchor_field_checks.merkle_root = true`

## Common Debugging Patterns

### `chain-connect` fails on Windows

Run:

```bat
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

Inspect:

- `bootstrap_diagnostics.anvil_path`
- `bootstrap_diagnostics.forge_path`
- `bootstrap_diagnostics.managed_foundry_bin_dir`
- `bootstrap_diagnostics.managed_foundry_bin_contents`
- `bootstrap_diagnostics.managed_foundry_install_error`

### Setup succeeds but a new proof still exports `local-json`

Common causes:

- you exported a proof from an older session
- the session config was created before `chain-connect` updated account configs
- the UI was not restarted after setup changes

### UI appears stale after code changes

Restart the UI launcher, not just the background service:

```bat
run_clawchain_ui.cmd 8888
```

```bash
bash run_clawchain_ui.sh 8888
```

### Windows setup reaches UI but chain status is empty

That usually means `deploy` succeeded but `chain-connect` did not write a manifest. Confirm:

- `manifest_path` exists in `chain-status`
- `evm_enabled_config_count` is greater than zero
- the new monitored session proof shows EVM fields instead of `local-json`

## Change Checklist

When you change setup, proof export, or chain bootstrap behavior, run this checklist:

1. `py_compile` on touched Python files
2. Linux smoke without EVM
3. Linux smoke with EVM when available
4. Windows `chain-connect --bootstrap-local-evm`
5. Windows full setup
6. New monitored session proof export on Windows
7. Verify proof fields and target path consistency
8. Update README.md if user-facing behavior changed
9. Update this file if developer workflow changed

## External References

- https://github.com/foundry-rs/foundry/releases/latest
- https://api.github.com/repos/foundry-rs/foundry/releases/latest
- https://getfoundry.sh/reference/forge/forge.html
