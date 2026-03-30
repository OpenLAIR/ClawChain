#!/usr/bin/env python3
"""ClawChain dangerous-operations smoke test.

Scenarios (all sourced from risk_catalog.py):
  1. destructive_delete        - delete a file          (restorable)
  2. destructive_move          - rename/move a file     (audit-only)
  3. config_integrity_mutation - overwrite config file  (audit-only)
  4. in_place_file_edit        - in-place text edit     (audit-only)
  5. destructive_truncate      - truncate file to zero  (audit-only)
  6. secret_access             - read a .env file       (audit-only)

Usage:
    python scripts/dangerous_ops_smoke.py
    python scripts/dangerous_ops_smoke.py --scenarios delete,config_overwrite
    python scripts/dangerous_ops_smoke.py --no-ui
    python scripts/dangerous_ops_smoke.py --output-dir PATH
"""
from __future__ import annotations
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_SRC = REPO_ROOT / "demo" / "dangerous-ops-smoke"


def _env() -> dict[str, str]:
    env = os.environ.copy()
    cur = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(REPO_ROOT) if not cur else f"{REPO_ROOT}{os.pathsep}{cur}"
    return env


def _display(argv: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    import shlex
    return " ".join(shlex.quote(p) for p in argv)


def _run(
    argv: list[str], *, inp: str | None = None, allow_failure: bool = False
) -> subprocess.CompletedProcess[str]:
    print(f"[smoke] $ {_display(argv)}")
    r = subprocess.run(
        argv, input=inp, text=True, capture_output=True,
        cwd=str(REPO_ROOT), env=_env(), check=False,
    )
    if r.stdout.strip():
        print(r.stdout.strip())
    if r.returncode != 0 and not allow_failure:
        raise RuntimeError(r.stderr.strip() or f"exit {r.returncode}")
    return r


def _jrun(
    argv: list[str], *, inp: str | None = None, allow_failure: bool = False
) -> dict[str, object]:
    r = _run(argv, inp=inp, allow_failure=allow_failure)
    try:
        d = json.loads(r.stdout or "{}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"bad JSON from {argv[0]}: {r.stdout!r}") from e
    if r.returncode != 0 and not allow_failure:
        raise RuntimeError(str(d))
    return dict(d)


def _kill(pid: int | None) -> None:
    if not pid or pid <= 0:
        return
    if os.name == "nt":
        sr = Path(os.environ.get("SystemRoot") or r"C:\Windows")
        tk = shutil.which("taskkill") or str(sr / "System32" / "taskkill.exe")
        try:
            subprocess.run([tk, "/PID", str(pid), "/T", "/F"],
                           check=False, capture_output=True)
        except OSError:
            pass
        return
    try:
        os.kill(pid, 15)
    except OSError:
        return
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return
        time.sleep(0.05)
    try:
        os.kill(pid, 9)
    except OSError:
        pass


def _poll_http(url: str, timeout: float = 20.0) -> str:
    deadline, last_err = time.time() + timeout, None
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=1.0) as resp:  # noqa: S310
                return resp.read().decode("utf-8", errors="replace")
        except URLError as e:
            last_err = e
            time.sleep(0.25)
    raise RuntimeError(f"UI not ready at {url}: {last_err}")


def _ui_proc(port: int) -> subprocess.Popen[str]:
    argv = [sys.executable, "-m", "clawchain.agent_proxy_cli",
            "ui", "--host", "127.0.0.1", "--port", str(port)]
    print(f"[smoke] $ {_display(argv)}")
    kw: dict[str, object] = {
        "cwd": str(REPO_ROOT), "env": _env(),
        "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "text": True,
    }
    if os.name == "nt":
        f = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) or 0)
        f |= int(getattr(subprocess, "CREATE_NO_WINDOW", 0) or 0)
        if f:
            kw["creationflags"] = f
    else:
        kw["start_new_session"] = True
    return subprocess.Popen(argv, **kw)  # type: ignore[arg-type]


def _copy_fixtures(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for s in FIXTURES_SRC.iterdir():
        if s.is_file() and s.suffix != ".md":
            shutil.copy2(s, dest / s.name)
    print(f"[smoke] fixtures -> {dest}")


def _dtool(
    ep: str, *,
    sid: str, rid: str, acct: str,
    name: str, params: dict[str, object], ws: Path,
) -> dict[str, object]:
    payload = {"session_id": sid, "run_id": rid, "tool_name": name,
               "params": params, "actor_id": acct, "cwd": str(ws)}
    return _jrun(
        [sys.executable, "-m", "clawchain.agent_proxy_cli",
         "daemon-tool-json", ep],
        inp=json.dumps(payload, ensure_ascii=True),
        allow_failure=True,
    )


# ---------------------------------------------------------------------------
# Scenario 1 - destructive_delete  (restorable)
# ---------------------------------------------------------------------------

def scenario_delete(ep: str, ws: Path, sid: str, rid: str, acct: str) -> dict[str, object]:
    """Delete notes.txt -- ClawChain snapshots it and allows restore."""
    print("\n[scenario 1] destructive_delete -- fs.delete notes.txt")
    t = ws / "notes.txt"
    resp = _dtool(ep, sid=sid, rid=rid, acct=acct, name="fs.delete",
                  params={"path": str(t)}, ws=ws)
    gone = not t.exists()
    print(f"  deleted on disk: {gone} | ok: {resp.get('ok')}")
    return {"scenario": "destructive_delete", "ok": resp.get("ok"),
            "target_deleted": gone, "response": resp}


# ---------------------------------------------------------------------------
# Scenario 2 - destructive_move / rename
# ---------------------------------------------------------------------------

def scenario_move_rename(ep: str, ws: Path, sid: str, rid: str, acct: str) -> dict[str, object]:
    """Rename rename-me.txt to renamed-output.txt via fs.move."""
    print("\n[scenario 2] destructive_move -- rename rename-me.txt")
    src = ws / "rename-me.txt"
    dst = ws / "renamed-output.txt"
    resp = _dtool(ep, sid=sid, rid=rid, acct=acct, name="fs.move",
                  params={"src": str(src), "dst": str(dst)}, ws=ws)
    moved = dst.exists() and not src.exists()
    print(f"  renamed on disk: {moved} | ok: {resp.get('ok')}")
    return {"scenario": "destructive_move", "ok": resp.get("ok"),
            "file_renamed": moved, "response": resp}


# ---------------------------------------------------------------------------
# Scenario 3 - config_integrity_mutation
# ---------------------------------------------------------------------------

def scenario_config_overwrite(ep: str, ws: Path, sid: str, rid: str, acct: str) -> dict[str, object]:
    """Overwrite config.json with tampered content via fs.write_text."""
    print("\n[scenario 3] config_integrity_mutation -- overwrite config.json")
    t = ws / "config.json"
    content = json.dumps(
        {"app": "demo-app", "log_level": "debug",
         "api_endpoint": "https://evil.example.com", "max_retries": 99},
        indent=2,
    )
    resp = _dtool(ep, sid=sid, rid=rid, acct=acct, name="fs.write_text",
                  params={"path": str(t), "content": content}, ws=ws)
    cur = t.read_text(encoding="utf-8") if t.exists() else ""
    ow = "evil.example.com" in cur
    print(f"  config overwritten: {ow} | ok: {resp.get('ok')}")
    return {"scenario": "config_integrity_mutation", "ok": resp.get("ok"),
            "config_overwritten": ow, "response": resp}


# ---------------------------------------------------------------------------
# Scenario 4 - in_place_file_edit
# ---------------------------------------------------------------------------

def scenario_inplace_edit(ep: str, ws: Path, sid: str, rid: str, acct: str) -> dict[str, object]:
    """Edit data.csv in-place: replace 'alpha' with 'ALPHA'."""
    print("\n[scenario 4] in_place_file_edit -- replace alpha->ALPHA in data.csv")
    t = ws / "data.csv"
    ts = str(t)
    current = t.read_text(encoding="utf-8") if t.exists() else "id,name,value\n1,alpha,100\n"
    modified = current.replace("alpha", "ALPHA")
    resp = _dtool(ep, sid=sid, rid=rid, acct=acct, name="fs.write_text",
                  params={"path": ts, "content": modified}, ws=ws)
    cur = t.read_text(encoding="utf-8") if t.exists() else ""
    edited = "ALPHA" in cur
    print(f"  in-place edit applied: {edited} | ok: {resp.get('ok')}")
    return {"scenario": "in_place_file_edit", "ok": resp.get("ok"),
            "edit_applied": edited, "response": resp}


# ---------------------------------------------------------------------------
# Scenario 5 - destructive_truncate
# ---------------------------------------------------------------------------

def scenario_truncate(ep: str, ws: Path, sid: str, rid: str, acct: str) -> dict[str, object]:
    """Truncate data.csv to zero bytes."""
    print("\n[scenario 5] destructive_truncate -- truncate data.csv to zero bytes")
    t = ws / "data.csv"
    ts = str(t)
    resp = _dtool(ep, sid=sid, rid=rid, acct=acct, name="fs.write_text",
                  params={"path": ts, "content": ""}, ws=ws)
    sz = t.stat().st_size if t.exists() else -1
    truncated = sz == 0
    print(f"  truncated (size={sz}): {truncated} | ok: {resp.get('ok')}")
    return {"scenario": "destructive_truncate", "ok": resp.get("ok"),
            "file_truncated": truncated, "response": resp}


# ---------------------------------------------------------------------------
# Scenario 6 - secret_access
# ---------------------------------------------------------------------------

def scenario_secret_access(ep: str, ws: Path, sid: str, rid: str, acct: str) -> dict[str, object]:
    """Read secret.env via shell -- triggers secret_access detection."""
    print("\n[scenario 6] secret_access -- read secret.env")
    t = ws / "secret.env"
    ts = str(t)
    if os.name == "nt":
        cmd = "powershell -Command \"Get-Content -Path '" + ts + "'\""
    else:
        cmd = "cat '" + ts + "'"
    resp = _dtool(ep, sid=sid, rid=rid, acct=acct, name="system.run",
                  params={"cmd": cmd}, ws=ws)
    print(f"  ok: {resp.get('ok')}")
    return {"scenario": "secret_access", "ok": resp.get("ok"), "response": resp}


# ---------------------------------------------------------------------------
# Proof export & verify
# ---------------------------------------------------------------------------

def _export_and_verify(
    account: str, registry_root: Path, manifest_path: Path
) -> dict[str, object]:
    proof = _jrun([
        sys.executable, "-m", "clawchain.agent_proxy_cli",
        "proof", "--account", account,
        "--root-dir", str(registry_root),
        "--limit", "20",
        "--save-manifest", str(manifest_path),
    ])
    if not proof.get("ok") or not manifest_path.exists():
        raise RuntimeError(f"proof export failed: {proof}")
    verify = _jrun([
        sys.executable, "-m", "clawchain.agent_proxy_cli",
        "verify", "--manifest", str(manifest_path),
        "--account", account,
        "--root-dir", str(registry_root),
    ])
    if not verify.get("ok"):
        raise RuntimeError(f"proof verify failed: {verify}")
    return verify


# ---------------------------------------------------------------------------
# Blockchain / chain-log verification
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict]:
    """Read a JSONL file; return [] if missing."""
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def _read_json_list(path: Path) -> list[dict]:
    """Read a JSON file containing a list; return [] if missing."""
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return [r for r in payload if isinstance(r, dict)]
    except Exception:  # noqa: BLE001
        pass
    return []


def verify_blockchain_logs(
    *,
    account_root: Path,
    session_id: str,
    scenario_names: list[str],
) -> dict[str, object]:
    """
    Inspect on-disk chain data files and confirm the blockchain layer
    recorded each dangerous operation.

    Checks:
      1. events.jsonl       -- ToolInvocationRequested events written for session
      2. events.jsonl       -- PolicyDecision (risk classification) events exist
      3. events.jsonl       -- RecoveryPlanned events exist (for restorable ops)
      4. receipts.json      -- at least one anchor receipt written for session
      5. recovery-impact-sets.jsonl -- each expected risk_reason has a record
      6. risk-signals CLI   -- `risk-signals` command returns matching entries
    """
    print(f"\n{'='*60}")
    print("[chain-verify] Verifying blockchain / chain logs")
    print("=" * 60)

    # ClawChainPaths.from_root(account_root/"runtime") -> local = runtime/local
    local_dir     = account_root / "runtime" / "local"
    event_store   = local_dir / "events.jsonl"
    receipt_store = local_dir / "receipts.json"
    impact_store  = local_dir / "recovery-impact-sets.jsonl"

    print(f"[chain-verify] local_dir     : {local_dir}")
    print(f"[chain-verify] event_store   : exists={event_store.exists()}")
    print(f"[chain-verify] receipt_store : exists={receipt_store.exists()}")
    print(f"[chain-verify] impact_store  : exists={impact_store.exists()}")

    checks: dict[str, object] = {}
    all_ok = True

    # -- 1 & 2 & 3: event log --------------------------------------------------
    events = _read_jsonl(event_store)
    session_events   = [e for e in events if str(e.get("session_id")) == session_id]
    invoke_events    = [e for e in session_events if e.get("event_type") == "ToolInvocationRequested"]
    policy_events    = [e for e in session_events if e.get("event_type") == "PolicyDecision"]
    recovery_planned = [e for e in session_events if e.get("event_type") == "RecoveryPlanned"]

    c_events   = bool(session_events)
    c_invokes  = len(invoke_events) >= len(scenario_names)
    c_policy   = len(policy_events) > 0
    checks["events_written"]               = c_events
    checks["invoke_events_count"]          = len(invoke_events)
    checks["policy_decision_events_count"] = len(policy_events)
    checks["recovery_planned_count"]       = len(recovery_planned)
    checks["invoke_events_ok"]             = c_invokes
    checks["policy_decision_events_ok"]    = c_policy

    _show("events.jsonl written for session", c_events)
    _show(f"ToolInvocationRequested >= {len(scenario_names)} (got {len(invoke_events)})", c_invokes)
    _show(f"PolicyDecision events present (got {len(policy_events)})", c_policy)
    if recovery_planned:
        print(f"  [INFO] RecoveryPlanned events: {len(recovery_planned)}")
    if not c_events:
        all_ok = False
    if not c_invokes:
        all_ok = False
    if not c_policy:
        all_ok = False

    # -- 4: receipts -----------------------------------------------------------
    receipts = _read_json_list(receipt_store)
    session_receipts = [r for r in receipts if str(r.get("session_id")) == session_id]
    c_receipts = len(session_receipts) > 0
    checks["anchor_receipts_count"] = len(session_receipts)
    checks["anchor_receipts_ok"]    = c_receipts
    _show(f"Anchor receipts in receipts.json (got {len(session_receipts)})", c_receipts)
    if not c_receipts:
        all_ok = False

    # -- 5: impact-sets --------------------------------------------------------
    # Only scenarios that triggered protections will generate impact-set records.
    # Determine which scenarios actually produced protections by inspecting
    # their ToolInvocationRequested counterparts via RecoveryPlanned events.
    risk_reasons_with_recovery = {
        str(e.get("payload", {}).get("risk_reason"))
        for e in session_events
        if e.get("event_type") == "RecoveryPlanned"
    }
    impact_rows = _read_jsonl(impact_store)
    session_impacts = [r for r in impact_rows if str(r.get("session_id")) == session_id]
    recorded_risks  = {str(r.get("risk_reason")) for r in session_impacts}
    # Only expect impact-sets for scenarios that had recoveries
    all_expected    = {_SCENARIO_RISK_REASONS[n] for n in scenario_names if n in _SCENARIO_RISK_REASONS}
    expected_risks  = all_expected & (risk_reasons_with_recovery | recorded_risks)
    missing_risks   = expected_risks - recorded_risks
    c_impacts = not missing_risks
    checks["impact_sets_count"]          = len(session_impacts)
    checks["risk_reasons_with_recovery"] = sorted(risk_reasons_with_recovery)
    checks["recorded_risk_reasons"]      = sorted(recorded_risks)
    checks["expected_risk_reasons"]      = sorted(expected_risks)
    checks["missing_risk_reasons"]       = sorted(missing_risks)
    checks["audit_only_risk_reasons"]    = sorted(all_expected - expected_risks)
    checks["impact_sets_ok"]             = c_impacts
    _show(
        f"Impact-sets cover all recoverable risk reasons "
        f"(recorded={sorted(recorded_risks)}, missing={sorted(missing_risks)}, "
        f"audit-only={sorted(all_expected - expected_risks)})",
        c_impacts,
    )
    if not c_impacts:
        all_ok = False

    # -- 6: impact-set-list CLI ------------------------------------------------
    # Use `impact-set-list <config-path> --session ID` to confirm risk reasons
    # were recorded via the official CLI (not just raw file inspection).
    config_candidates = list(account_root.glob("agent-proxy.config.json"))
    impact_set_cli_check: dict[str, object] = {"skipped": True}
    if config_candidates:
        cfg_path = config_candidates[0]
        isl = _jrun(
            [sys.executable, "-m", "clawchain.agent_proxy_cli",
             "impact-set-list", str(cfg_path), "--session", session_id],
            allow_failure=True,
        )
        cli_sets = [s for s in isl.get("impact_sets", []) if isinstance(s, dict)]
        cli_risks = {str(s.get("risk_reason")) for s in cli_sets}
        c_cli = bool(cli_risks)
        impact_set_cli_check = {
            "skipped": False,
            "impact_set_count": len(cli_sets),
            "risk_reasons_detected": sorted(cli_risks),
            "ok": c_cli,
        }
        _show(
            f"impact-set-list CLI returned impact sets (got {len(cli_sets)}, "
            f"risks={sorted(cli_risks)})",
            c_cli,
        )
        if not c_cli:
            all_ok = False
    else:
        print("  [INFO] impact-set-list CLI: no config found, skipping")
    checks["impact_set_cli"] = impact_set_cli_check

    checks["chain_verify_ok"] = all_ok
    print(f"\n[chain-verify] {'ALL CHECKS PASSED' if all_ok else 'SOME CHECKS FAILED'}")
    return checks


def _show(label: str, ok: bool) -> None:
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {label}")


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

SCENARIOS: list[tuple[str, object]] = [
    ("delete",           scenario_delete),
    ("move_rename",      scenario_move_rename),
    ("config_overwrite", scenario_config_overwrite),
    ("inplace_edit",     scenario_inplace_edit),
    ("truncate",         scenario_truncate),
    ("secret_access",    scenario_secret_access),
]

# Map scenario key -> risk_reason expected in chain logs
_SCENARIO_RISK_REASONS: dict[str, str] = {
    "delete":           "destructive_delete",
    "move_rename":      "destructive_move",
    "config_overwrite": "config_integrity_mutation",
    "inplace_edit":     "in_place_file_edit",
    "truncate":         "destructive_truncate",
    "secret_access":    "secret_access",
}

SCENARIO_NAMES = ", ".join(n for n, _ in SCENARIOS)


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def _write_report(
    *,
    output_dir: Path,
    summary: dict[str, object],
    chain_checks: dict[str, object],
    all_ok: bool,
) -> Path:
    """Write a human-readable + JSON report to output_dir/smoke-report.txt."""
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "smoke-report.txt"
    json_path   = output_dir / "smoke-report.json"

    banner = "=" * 60
    if all_ok:
        verdict = f"\n{banner}\n  RESULT: *** ALL TESTS PASSED ***\n{banner}\n"
    else:
        verdict = f"\n{banner}\n  RESULT: *** SOME TESTS FAILED ***\n{banner}\n"

    lines: list[str] = []
    lines.append(banner)
    lines.append("  ClawChain Dangerous-Ops Smoke Test Report")
    lines.append(f"  Generated : {time.strftime('%Y-%m-%d %H:%M:%S')}") 
    lines.append(f"  Platform  : {summary.get('platform')}")  
    lines.append(f"  Account   : {summary.get('account')}")
    lines.append(f"  Root dir  : {summary.get('root_dir')}")
    lines.append(banner)
    lines.append("")
    lines.append("SCENARIO RESULTS")
    lines.append("-" * 40)
    for r in summary.get("results", []):
        tag = "PASS" if r.get("ok") else "FAIL"
        lines.append(f"  [{tag}] {r.get('scenario', '?')}")
    lines.append("")
    lines.append("BLOCKCHAIN / CHAIN-LOG VERIFICATION")
    lines.append("-" * 40)
    bool_keys = [
        "events_written",
        "invoke_events_ok",
        "policy_decision_events_ok",
        "anchor_receipts_ok",
        "impact_sets_ok",
        "chain_verify_ok",
    ]
    for k in bool_keys:
        if k in chain_checks:
            tag = "PASS" if chain_checks[k] else "FAIL"
            lines.append(f"  [{tag}] {k}")
    rs = chain_checks.get("impact_set_cli", {})
    if isinstance(rs, dict) and not rs.get("skipped"):
        tag = "PASS" if rs.get("ok") else "FAIL"
        lines.append(f"  [{tag}] impact_set_cli (count={rs.get('impact_set_count', 0)})")
    lines.append("")
    lines.append("CHAIN-LOG DETAILS")
    lines.append("-" * 40)
    for k in ["invoke_events_count", "policy_decision_events_count",
              "recovery_planned_count", "anchor_receipts_count",
              "impact_sets_count", "recorded_risk_reasons",
              "missing_risk_reasons"]:
        if k in chain_checks:
            lines.append(f"  {k}: {chain_checks[k]}")
    lines.append("")
    lines.append(verdict)

    text = "\n".join(lines)
    report_path.write_text(text, encoding="utf-8")
    full_report = {"summary": summary, "chain_checks": chain_checks}
    json_path.write_text(
        json.dumps(full_report, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(verdict)
    print(f"[smoke] Report written to : {report_path}")
    print(f"[smoke] JSON report       : {json_path}")
    return report_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="ClawChain dangerous-operations multi-scenario smoke test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available scenarios: {SCENARIO_NAMES}",
    )
    parser.add_argument("--account", default=None,
                        help="ClawChain account id (default: auto)")
    parser.add_argument("--password", default="smoke-password")
    parser.add_argument("--workspace", default=str(REPO_ROOT))
    parser.add_argument("--root-dir", default=None,
                        help="Root dir for ClawChain state (default: temp)")
    parser.add_argument("--session", default="dangerous-ops-smoke")
    parser.add_argument("--run", default="dangerous-ops-run")
    parser.add_argument("--port", type=int, default=8894,
                        help="Port for the ClawChain UI (default: 8894)")
    parser.add_argument("--scenarios", default="all",
                        help=f"Comma-separated scenario names or 'all'. Options: {SCENARIO_NAMES}")
    parser.add_argument("--no-ui", action="store_true",
                        help="Skip starting the ClawChain UI process")
    parser.add_argument("--output-dir", default=None,
                        help="Directory to write smoke-report.txt and smoke-report.json")
    args = parser.parse_args()

    platform = "windows" if os.name == "nt" else "linux"
    account = args.account or f"dangerous-ops-{platform}"

    registry_root = (
        Path(args.root_dir).expanduser().resolve() if args.root_dir
        else Path(tempfile.gettempdir()) / f"clawchain-dangerous-ops-{int(time.time())}"
    )
    workspace = Path(args.workspace).expanduser().resolve()
    registry_root.mkdir(parents=True, exist_ok=True)
    account_root = registry_root / account
    account_root.mkdir(parents=True, exist_ok=True)

    fixture_ws = account_root / "fixtures"
    _copy_fixtures(fixture_ws)

    config_path = account_root / "agent-proxy.config.json"
    state_path  = account_root / "agent-proxy-service.json"
    manifest    = account_root / "proof-manifest.json"

    output_dir = (
        Path(args.output_dir).expanduser().resolve() if args.output_dir
        else account_root / "smoke-results"
    )

    # Select scenarios
    if args.scenarios == "all":
        selected = SCENARIOS
    else:
        want = {n.strip() for n in args.scenarios.split(",")}
        selected = [(n, fn) for n, fn in SCENARIOS if n in want]
        if not selected:
            print(f"[smoke] ERROR: no matching scenarios for {args.scenarios!r}")
            print(f"[smoke] Available: {SCENARIO_NAMES}")
            return 1

    selected_keys = [n for n, _ in selected]

    ui: subprocess.Popen[str] | None = None
    results: list[dict[str, object]] = []
    chain_checks: dict[str, object] = {}

    try:
        # ---- bootstrap ----
        _jrun([
            sys.executable, "-m", "clawchain.agent_proxy_cli", "config-init",
            account, args.password,
            "--config", str(config_path),
            "--root-dir", str(account_root),
            "--workspace", str(workspace),
            "--session", args.session,
            "--run", args.run,
            "--no-auto-evm",
        ])

        svc = _jrun([sys.executable, "-m", "clawchain.agent_proxy_cli",
                     "service-start", str(config_path)])
        if not svc.get("ok"):
            raise RuntimeError(f"service-start failed: {svc}")

        status = _jrun([sys.executable, "-m", "clawchain.agent_proxy_cli",
                        "service-status", str(config_path)])
        if not status.get("ok") or not status.get("running"):
            raise RuntimeError(f"service not running: {status}")

        state = json.loads(state_path.read_text(encoding="utf-8"))
        ep = str(state.get("socket_path") or "")
        if not ep:
            raise RuntimeError(f"no socket endpoint in: {state}")

        # ---- run scenarios ----
        for name, fn in selected:
            print(f"\n{'='*60}")
            print(f"[smoke] scenario: {name}")
            print("=" * 60)
            try:
                result = fn(ep, fixture_ws, args.session, args.run, account)  # type: ignore[operator]
                results.append(result)
            except Exception as exc:  # noqa: BLE001
                print(f"[smoke] {name!r} raised: {exc}")
                results.append({"scenario": name, "ok": False, "error": str(exc)})
            time.sleep(0.5)  # let the rollout watcher process the event

        # ---- proof ----
        print(f"\n{'='*60}\n[smoke] exporting and verifying proof\n{'='*60}")
        pv = _export_and_verify(account, registry_root, manifest)
        print(f"[smoke] proof verify ok: {pv.get('ok')}")

        # ---- blockchain log verification ----
        chain_checks = verify_blockchain_logs(
            account_root=account_root,
            session_id=args.session,
            scenario_names=selected_keys,
        )

        # ---- optional UI ----
        if not args.no_ui:
            ui = _ui_proc(args.port)
            body = _poll_http(f"http://127.0.0.1:{args.port}/")
            if "ClawChain Console" not in body:
                raise RuntimeError("UI responded but did not contain expected page")
            print(f"[smoke] UI live at http://127.0.0.1:{args.port}/")

        # ---- scenario summary ----
        print(f"\n{'='*60}\n[smoke] SCENARIO RESULTS\n{'='*60}")
        all_scenarios_ok = True
        for r in results:
            tag = "PASS" if r.get("ok") else "FAIL"
            if not r.get("ok"):
                all_scenarios_ok = False
            print(f"  [{tag}] {r.get('scenario', '?')}")

        all_ok = all_scenarios_ok and bool(chain_checks.get("chain_verify_ok"))

        summary = {
            "ok": all_ok,
            "platform": platform,
            "account": account,
            "root_dir": str(registry_root),
            "fixture_workspace": str(fixture_ws),
            "scenarios_run": [r.get("scenario") for r in results],
            "results": results,
            "proof_manifest": str(manifest),
            "ui_url": f"http://127.0.0.1:{args.port}/" if not args.no_ui else None,
        }

        _write_report(
            output_dir=output_dir,
            summary=summary,
            chain_checks=chain_checks,
            all_ok=all_ok,
        )

        print(json.dumps(summary, ensure_ascii=True, indent=2))
        return 0 if all_ok else 1

    finally:
        if ui is not None:
            ui.terminate()
            try:
                ui.wait(timeout=3)
            except subprocess.TimeoutExpired:
                ui.kill()
        if config_path.exists():
            _run([sys.executable, "-m", "clawchain.agent_proxy_cli",
                  "service-stop", str(config_path)], allow_failure=True)


if __name__ == "__main__":
    raise SystemExit(main())

                