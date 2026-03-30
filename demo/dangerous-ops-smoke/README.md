# Dangerous-Operations Smoke Test

This folder contains fixture files used by `scripts/dangerous_ops_smoke.py` to
exercise six "dangerous" risk categories defined in `clawchain/risk_catalog.py`.

## Fixture files

| File | Used by scenario |
|---|---|
| `notes.txt` | Scenario 1 — `destructive_delete` (file is deleted; ClawChain snapshots it for restore) |
| `rename-me.txt` | Scenario 2 — `destructive_move` (file is renamed via shell `mv`/`ren`) |
| `config.json` | Scenario 3 — `config_integrity_mutation` (file is overwritten with tampered JSON) |
| `data.csv` | Scenarios 4 & 5 — `in_place_file_edit` then `destructive_truncate` |
| `secret.env` | Scenario 6 — `secret_access` (file is read via shell `cat`/`type`) |

## Running the smoke test

### Windows (PowerShell)

```powershell
.\scripts\run_dangerous_ops_smoke.ps1
```

### Windows / Linux (Python directly)

```bash
python scripts/dangerous_ops_smoke.py
```

### Run a subset of scenarios

```bash
python scripts/dangerous_ops_smoke.py --scenarios delete,config_overwrite
```

Available scenario names: `delete`, `move_rename`, `config_overwrite`, `inplace_edit`, `truncate`, `secret_access`

### Skip the UI

```bash
python scripts/dangerous_ops_smoke.py --no-ui
```

## What the test does

1. Initialises a temporary ClawChain account and config (`config-init`).
2. Starts the ClawChain background service (`service-start`).
3. Copies these fixture files into a temp workspace so originals are never modified.
4. Routes each dangerous action through the daemon via `daemon-tool-json` — the
   same path a live Codex/Gemini/Cursor session would use.
5. Waits briefly after each action so the rollout watcher can record the event.
6. Exports a proof manifest and verifies it (`proof` + `verify`).
7. Optionally starts the UI on port 8894 so you can inspect `Dangerous Operations`
   in the dashboard.
8. Stops the service and prints a PASS/FAIL summary for each scenario.

## Risk categories exercised

| # | Scenario | `risk_reason` | Restorable? |
|---|---|---|---|
| 1 | Delete file | `destructive_delete` | Yes |
| 2 | Rename file | `destructive_move` | No |
| 3 | Overwrite config | `config_integrity_mutation` | No |
| 4 | In-place edit | `in_place_file_edit` | No |
| 5 | Truncate file | `destructive_truncate` | No |
| 6 | Read secrets file | `secret_access` | No |

For scenario 1, ClawChain will show a **Restore** button in the UI under
`Dangerous Operations`. The other five scenarios appear as audit-only records.
