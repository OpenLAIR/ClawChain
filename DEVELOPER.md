# ClawChain Developer Guide

This document is for contributors who need to modify ClawChain runtime behavior, UI flows, proof export, chain integration, or cross-platform validation.

README is user-facing and deployment-oriented. This file is the engineering reference.

## Scope

Use this guide when you need detailed information about:

- repository architecture
- the generalized agent-adapter model
- Codex and Claude Code runtime behavior
- setup and bootstrap internals
- proof export expectations
- cross-platform validation and debugging

## Current Support Model

ClawChain currently has two validated agent paths:

- Codex
  Preserved through the existing Codex rollout path.
- Claude Code
  Integrated through the shared shell-agent adapter path.

The runtime is structured so future shell-style agents can be added by extending the profile model instead of duplicating launcher logic.

## Recommended Environment

- Python 3.12
- `pip install -r requirements.txt`
- `pip install -e .`
- a Conda environment such as `ClawChain`

Useful optional tools:

- Foundry: `anvil`, `forge`
- Docker as a fallback only
- tmux on Linux
- Claude Code installed and authenticated for real CLI validation

## Repository Map

### Adapter and runtime modules

- `clawchain/agent_profiles.py`
  Agent profile registry. Extend this first when adding a new shell-style agent.
- `clawchain/shell_agent_integration.py`
  Shared launcher, resume, handoff, environment, and shim generation for shell agents.
- `clawchain/host_monitor.py`
  Live process discovery, session matching, managed/native state detection, and mixed-session handling.
- `clawchain/agent_proxy_cli.py`
  Main CLI entrypoint, prepare/onboard/service flow, proof building, and chain commands.
- `clawchain/ui_server.py`
  UI backend, session views, proof export, restore actions, and mixed-session warnings.
- `clawchain/agent_proxy.py`
  Runtime bootstrap, Foundry handling, local EVM setup, and proxy helpers.
- `clawchain/agent_proxy_daemon.py`
  Background service daemon with Linux/Windows IPC behavior.
- `clawchain/agent_proxy_config.py`
  Stored config model and persistence.

### Codex-specific modules still retained

- `clawchain/codex_integration.py`
  Codex-specific integration helpers.
- `clawchain/codex_rollout.py`
  Codex rollout capture model.
- `clawchain/codex_rollout_monitor.py`
  Codex-specific rollout watcher.

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

- `scripts/smoke_claude_adapter.py`
  Claude-oriented adapter smoke.
- `scripts/platform_smoke.py`
  Cross-platform setup/service/proof smoke driver.
- `scripts/run_linux_smoke.sh`
- `scripts/run_windows_smoke.ps1`
- `scripts/run_windows_smoke.cmd`
- `scripts/run_evm_smoke.sh`

## Runtime Model

ClawChain can be understood as two execution families sharing one recovery, proof, and chain backend.

### 1. Codex rollout path

Codex still uses a dedicated rollout monitoring path.

Use this path when:

- you need existing Codex behavior preserved
- the profile uses `watcher_kind = codex-rollout`
- you are regression-checking shared runtime changes against Codex

### 2. Generalized shell-agent path

Claude Code is the first validated user of the shared shell-agent path.

This path is responsible for:

- launcher generation
- controlled resume and handoff
- environment injection
- dangerous command shims
- managed terminal detection
- mixed native/managed session warnings

Design target:

- future shell-style agents should be added by extending `agent_profiles.py`
- shared launcher logic should stay in `shell_agent_integration.py`
- Codex-only rollout assumptions should not leak into the shared adapter path

## Adapter Design Rules

### Agent profiles own agent identity

A profile should define:

- executable name
- agent id
- launcher template
- resume behavior
- handoff behavior
- watcher kind
- agent-specific session-id extraction rules when needed

Do not bury agent-specific identity assumptions inside `ui_server.py` or `agent_proxy_cli.py` if they belong in the profile layer.

### Shared shell-agent integration owns controlled execution

`shell_agent_integration.py` should remain the common place for:

- wrapper generation
- controlled PATH and environment setup
- shim installation
- account/session directory layout
- managed launcher creation

Do not fork the launcher flow per agent unless the shared path cannot express the behavior.

### Codex-specific behavior stays isolated

If a change is only needed for Codex rollout capture, keep it inside the Codex-specific modules.

## Claude Code Notes

Claude integration has a few critical behavior rules.

### Session identity

Claude session matching should prefer real Claude session identifiers instead of path-based placeholders.

Expected sources include:

- `~/.claude/sessions/<pid>.json`
- Claude project session files under `~/.claude/projects/...`

Goal:

- prefer a real `resume:<session-id>` identity when available
- avoid collapsing unrelated Claude sessions into the same `path:*` fingerprint

### Managed vs native terminals

Claude can easily end up with both:

- the original native terminal
- the ClawChain-managed terminal after `Join Monitor`

A successful `Join Monitor` does not make commands typed in the old native terminal recoverable. UI and monitoring logic must make this visible.

### Join Monitor expectations

A Claude session should only be treated as truly routed when the managed process is actually present. If takeover did not succeed, do not mark the session as safely monitored.

## Setup And Bootstrap Internals

### Windows setup flow

`setup_clawchain.cmd` delegates to `setup_clawchain.ps1`.

Current PowerShell sequence:

1. stop the old service if present
2. run `deploy` without starting the service
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
4. optional Docker fallback where supported

Important principle:

- Docker is not the preferred Windows path
- local Foundry is the intended primary path on all platforms

## Proof Export Expectations

Current proof export expectations:

- `exported_at` is full ISO 8601, not time-only
- `session.evidence.snapshot_locations` points into `recovery-vault/recovery-snapshots/...`
- `session_dangerous_operations[].target_root` matches the absolute `proof_cards[].target_root`
- chain state is reflected back into exported proof evidence when available
- fresh Claude and Codex proofs should have the same exported structure once anchored

If the issue is presentation-only, prefer export normalization over changing the recovery model.

## Fast Validation Commands

### Syntax checks

```bash
python -m py_compile \
  clawchain/agent_profiles.py \
  clawchain/shell_agent_integration.py \
  clawchain/agent_proxy.py \
  clawchain/agent_proxy_cli.py \
  clawchain/host_monitor.py \
  clawchain/ui_server.py
```

### Claude adapter smoke

```bash
python scripts/smoke_claude_adapter.py
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

### EVM smoke

```bash
bash scripts/run_evm_smoke.sh
```

## Manual Acceptance Flows

### Codex regression flow

Use this when changing shared runtime infrastructure to ensure Codex did not regress.

1. Run setup for the current platform.
2. Confirm `chain-status local-operator` returns `ok: true`.
3. Open the UI.
4. Join a fresh Codex session.
5. Trigger a delete action.
6. Restore it.
7. Export the proof log.
8. Confirm the proof shows EVM anchor data.

### Claude acceptance flow

Use this when changing Claude integration, session identity logic, or mixed-session handling.

1. Start a fresh Claude Code session.
2. Open the UI.
3. Click `Join Monitor`.
4. Continue only in the ClawChain-managed Claude terminal.
5. Trigger a delete-style destructive action.
6. Confirm the action appears in history.
7. Restore it.
8. Export the proof log.
9. Confirm the proof shows a fresh `evm:31337` anchor, not `local-json`.

### Mixed-session warning check

Use this when modifying `host_monitor.py` or `ui_server.py`.

1. Start a native Claude terminal.
2. Join the same session into ClawChain.
3. Keep both native and managed terminals alive.
4. Confirm the UI marks the session as mixed or warns that commands in the native terminal are not captured.
5. Confirm session cards do not jump to unrelated sessions.

## Proof Acceptance Criteria

For a newly anchored Codex or Claude session proof, all of the following should hold:

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

### Claude session shows the wrong identity

Check:

- whether `~/.claude/sessions/<pid>.json` exists for the live process
- whether the process cwd matches the expected project path
- whether project-session lookup is accidentally borrowing a different workspace session
- whether the UI is displaying an old registry row instead of the current live session

### Delete happened but nothing was recorded

Usually one of these is true:

- the operation was performed in the original native Claude terminal, not the managed terminal
- `Join Monitor` did not complete actual process takeover
- the session was detected but still `detected-only`, not `managed`

Check live session state before changing recovery logic.

### Session card opens the wrong session

Focus on:

- `host_monitor.py` fingerprint generation
- old `path:*` rows in the session registry
- UI `session_ref` generation for non-concrete rows
- mixed native/managed rows collapsing into the same card

## Maintenance Checklist

Before publishing significant runtime changes, confirm all of the following:

- Codex regression flow passes
- Claude acceptance flow passes
- Windows setup with chain bootstrap passes
- Linux setup with chain bootstrap passes
- proof export shape remains stable
- README, README.zh-CN, and DEVELOPER docs are updated together
- no Claude-specific workaround has leaked into Codex-only rollout logic
