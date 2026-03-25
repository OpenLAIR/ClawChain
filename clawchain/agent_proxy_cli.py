from __future__ import annotations

from pathlib import Path
from hashlib import sha256
from dataclasses import asdict, is_dataclass, replace
import json
import os
import select
import shutil
import shlex
import signal
import subprocess
import sys
import time

from .agent_proxy import (
    AgentProxyConfig,
    AgentProxyPaths,
    TransparentAgentProxy,
    _bootstrap_local_evm_manifest,
    _bootstrap_local_evm_manifest_with_config,
)
from .agent_proxy_config import AgentProxyStoredConfig, load_agent_proxy_config, write_agent_proxy_config
from .agent_proxy_daemon import AgentProxyDaemon, AgentProxyDaemonClient
from .codex_integration import bootstrap_codex_cli_integration
from .host_monitor import aggregate_running_agents, detect_running_agents, list_known_agents, monitor_agents
from .real_agent_harness import build_real_agent_harness_plan
from .risk_catalog import risk_definition, risk_label
from .runtime.anchor import (
    EvmChainProbe,
    EvmCommitmentLookup,
    EvmDeploymentManifest,
    EvmDeploymentVerificationReport,
    RpcEvmBroadcaster,
    load_evm_deployment_manifest,
    resolve_commitment_anchor_abi_path,
    resolve_commitment_anchor_source_path,
    verify_evm_deployment_manifest,
    write_evm_deployment_manifest,
)
from .runtime.recovery import RecoveryCatalogStore, RecoveryImpactSetCatalogStore
from .runtime.recovery import RecoveryPlan, RecoveryProtectionBundle
from .session_state import SessionRegistryEntry, SessionState, detect_stale_pids, is_pid_alive, resolve_state_from_registry, safe_transition
from .system import ClawChainPaths


def _registry_root() -> Path:
    raw = os.environ.get("CLAWCHAIN_AGENT_HOME")
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".clawchain-agent"


def _default_registry_path(account_id: str, *, root_dir: Path | None = None) -> Path:
    base = root_dir.expanduser() if root_dir is not None else _registry_root()
    return base / account_id / "session-registry.json"


def _load_session_registry(account_id: str, *, root_dir: Path | None = None) -> list[SessionRegistryEntry]:
    path = _default_registry_path(account_id, root_dir=root_dir)
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return list(payload.get("sessions", []))
    except Exception:  # noqa: BLE001
        return []


def _load_session_registry_compat(account_id: str, *, root_dir: Path | None = None) -> list[SessionRegistryEntry]:
    if root_dir is None:
        return _load_session_registry(account_id)
    return _load_session_registry(account_id, root_dir=root_dir)


def _write_session_registry(account_id: str, sessions: list[SessionRegistryEntry], *, root_dir: Path | None = None) -> Path:
    path = _default_registry_path(account_id, root_dir=root_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"sessions": sessions}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return path


def _upsert_session_registry(account_id: str, entry: SessionRegistryEntry, *, root_dir: Path | None = None) -> Path:
    rows = _load_session_registry(account_id, root_dir=root_dir)
    key = (str(entry.get("agent_id") or ""), str(entry.get("session_id") or ""))
    updated = []
    replaced = False
    for row in rows:
        row_key = (str(row.get("agent_id") or ""), str(row.get("session_id") or ""))
        if row_key == key:
            updated.append({**row, **entry})
            replaced = True
        else:
            updated.append(row)
    if not replaced:
        updated.append(entry)
    return _write_session_registry(account_id, updated, root_dir=root_dir)


def _persist_prepared_sessions(
    *,
    account_id: str,
    prepared: list[dict[str, object]],
    fallback_items: dict[str, dict[str, object]] | None = None,
    root_dir: Path | None = None,
) -> None:
    fallback_items = fallback_items or {}
    for result in prepared:
        config_path = result.get("config_path")
        if not config_path:
            continue
        session_id = str(result.get("session_id") or "")
        if not session_id:
            continue
        fallback = fallback_items.get(session_id, {})
        existing = next(
            (row for row in _load_session_registry_compat(account_id, root_dir=root_dir)
             if str(row.get("session_id") or "") == session_id),
            None,
        )
        prior_state = resolve_state_from_registry(existing) if existing else SessionState.UNMANAGED
        target_state = SessionState.PREPARED if config_path else SessionState.FAILED
        tx = safe_transition(prior_state, SessionState.ENROLLING, reason="prepare_started")
        if tx is not None:
            tx = safe_transition(SessionState.ENROLLING, target_state, reason="prepare_completed")
        _upsert_session_registry(
            account_id,
            {
                "agent_id": result.get("agent_id") or fallback.get("agent_id"),
                "session_id": session_id,
                "session_name": result.get("session_name") or fallback.get("session_name") or session_id,
                "session_fingerprint": result.get("session_fingerprint") or fallback.get("session_fingerprint"),
                "path_hint": result.get("path_hint") or fallback.get("path_hint"),
                "config_path": config_path,
                "session_state": target_state.value,
                "capture_mode": result.get("capture_mode") or fallback.get("capture_mode"),
                "attach_command": result.get("attach_command") or fallback.get("attach_command"),
                "controlled_session_name": result.get("controlled_session_name") or fallback.get("controlled_session_name"),
                "handoff_command": result.get("handoff_command") or fallback.get("handoff_command"),
                "handoff_script_path": result.get("handoff_script_path") or fallback.get("handoff_script_path"),
                "last_seen_ts_ms": result.get("last_seen_ts_ms") or fallback.get("last_seen_ts_ms"),
            },
            root_dir=root_dir,
        )


def _update_tracked_pids(
    *,
    account_id: str,
    sessions: list[dict[str, object]],
    registry_rows: list[SessionRegistryEntry],
    root_dir: Path | None = None,
) -> None:
    now_ms = int(time.time() * 1000)
    for item in sessions:
        matched = _registry_lookup(registry_rows=registry_rows, item=item)
        if matched is None:
            continue
        session_id = str(matched.get("session_id") or "")
        if not session_id:
            continue
        pids_from_item: list[int] = []
        raw_pids = item.get("pids")
        if isinstance(raw_pids, list):
            pids_from_item = [int(p) for p in raw_pids if p is not None]
        elif item.get("pid") is not None:
            pids_from_item = [int(item["pid"])]
        if not pids_from_item:
            continue
        existing_pids: list[int] = list(matched.get("tracked_pids") or [])
        merged = list(dict.fromkeys(existing_pids + pids_from_item))
        if merged != existing_pids or matched.get("last_seen_ts_ms") is None:
            _upsert_session_registry(
                account_id,
                {
                    **matched,
                    "tracked_pids": merged,
                    "last_seen_ts_ms": now_ms,
                },
                root_dir=root_dir,
            )


def _detect_stale_sessions(
    *,
    account_id: str,
    root_dir: Path | None = None,
) -> list[SessionRegistryEntry]:
    rows = _load_session_registry_compat(account_id, root_dir=root_dir)
    stale_entries: list[SessionRegistryEntry] = []
    for row in rows:
        state = resolve_state_from_registry(row)
        if state not in (SessionState.PREPARED, SessionState.MONITORED):
            continue
        tracked = list(row.get("tracked_pids") or [])
        if not tracked:
            continue
        alive, stale = detect_stale_pids(tracked)
        if stale and not alive:
            _upsert_session_registry(
                account_id,
                {
                    **row,
                    "tracked_pids": [],
                    "session_state": SessionState.TERMINATED.value,
                },
                root_dir=root_dir,
            )
            stale_entries.append(row)
        elif stale:
            _upsert_session_registry(
                account_id,
                {
                    **row,
                    "tracked_pids": alive,
                },
                root_dir=root_dir,
            )
    return stale_entries


def _resolve_config_path(raw: str | None) -> Path:
    if raw is not None:
        return Path(raw)
    env_path = os.environ.get("CLAWCHAIN_AGENT_PROXY_CONFIG")
    if env_path:
        return Path(env_path)
    raise RuntimeError("config path is required; pass --config PATH or set CLAWCHAIN_AGENT_PROXY_CONFIG")


def _session_id_from_args_or_config(raw: str | None, *, stored: AgentProxyStoredConfig) -> str:
    return str(raw or stored.default_session_id)


def _normalize_profile_id(agent_id: str) -> str:
    mapping = {
        "codex": "codex-cli",
        "codex-cli": "codex-cli",
        "claude": "claude-code",
        "claude-code": "claude-code",
        "cursor": "cursor-agent",
        "cursor-agent": "cursor-agent",
        "openclaw": "openclaw",
        "openhands": "openhands",
        "cline": "cline",
        "github-copilot-agent": "github-copilot-agent",
        "replit-agent": "replit-agent",
    }
    return mapping.get(agent_id, agent_id)


def _package_root_str() -> str:
    return str(Path(__file__).resolve().parents[1])


def _to_jsonable(value):
    if is_dataclass(value):
        return {key: _to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _load_session_events(*, event_store_path: Path, session_id: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    if not event_store_path.exists():
        return rows
    with event_store_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if str(row.get("session_id")) == session_id:
                rows.append(row)
    return rows


def _build_timeline_rows(*, events: list[dict[str, object]]) -> list[dict[str, object]]:
    timeline_rows: list[dict[str, object]] = []
    for event in events:
        event_type = str(event.get("event_type"))
        payload = dict(event.get("payload", {}))
        if event_type == "ToolInvocationRequested":
            timeline_rows.append(
                {
                    "ts": event.get("timestamp_ms"),
                    "kind": "invoke",
                    "summary": f"{payload.get('tool_name')} {payload.get('params')}",
                }
            )
        elif event_type == "PolicyDecision":
            timeline_rows.append(
                {
                    "ts": event.get("timestamp_ms"),
                    "kind": "policy",
                    "summary": f"{payload.get('decision')} {payload.get('tool_name')}",
                }
            )
        elif event_type == "RecoveryPlanned":
            timeline_rows.append(
                {
                    "ts": event.get("timestamp_ms"),
                    "kind": "recovery-planned",
                    "summary": f"{payload.get('risk_reason')} -> {payload.get('target_path')}",
                }
            )
        elif event_type in {"RecoveryStarted", "RecoveryCompleted", "RecoveryVerified"}:
            timeline_rows.append(
                {
                    "ts": event.get("timestamp_ms"),
                    "kind": event_type,
                    "summary": f"{payload.get('source_kind')} -> {payload.get('target_path')}",
                }
            )
    return timeline_rows


def _command_summary_from_invoke(event: dict[str, object]) -> str:
    payload = dict(event.get("payload", {}))
    tool_name = str(payload.get("tool_name") or "")
    params = payload.get("params", {})
    if tool_name == "system.run" and isinstance(params, dict):
        cmd = params.get("cmd")
        if isinstance(cmd, (list, tuple)):
            return " ".join(str(part) for part in cmd)
    return f"{tool_name} {params}"


def _format_ts_label(raw_ts: object) -> str:
    try:
        value = int(raw_ts)
    except (TypeError, ValueError):
        return "-"
    return time.strftime("%H:%M:%S", time.localtime(value / 1000.0))


def _parse_since_to_ms(raw_since: str, *, now_ms: int | None = None) -> int:
    text = raw_since.strip().lower()
    if not text:
        raise ValueError("empty since value")
    units = {
        "s": 1000,
        "m": 60 * 1000,
        "h": 60 * 60 * 1000,
        "d": 24 * 60 * 60 * 1000,
    }
    suffix = text[-1]
    if suffix not in units:
        raise ValueError(f"unsupported since suffix: {raw_since}")
    amount = int(text[:-1])
    if amount < 0:
        raise ValueError(f"negative since value: {raw_since}")
    now_value = int(time.time() * 1000) if now_ms is None else int(now_ms)
    return now_value - amount * units[suffix]


def _extract_target_from_summary(summary: object) -> str | None:
    text = str(summary or "")
    if "->" not in text:
        return None
    return text.split("->", 1)[1].strip()


def _is_review_visible_path(path_text: str) -> bool:
    if not path_text:
        return False
    normalized = path_text.replace("\\", "/")
    if "/.git/" in normalized and not normalized.endswith("/.git"):
        return False
    return _is_review_visible_target(Path(normalized).name)


def _is_review_visible_target(name: str) -> bool:
    if not name:
        return False
    if name in {".git", ".env"}:
        return True
    lowered = name.lower()
    if lowered.endswith(".sample"):
        return False
    if all(ch in "0123456789abcdef" for ch in lowered) and len(lowered) >= 16:
        return False
    if name in {"HEAD", "index", "master", "description", "COMMIT_EDITMSG", "exclude"}:
        return False
    return not name.startswith(".git")


def _natural_language_operation_summary(*, risk_reason: str, target_root: str) -> str:
    target_name = Path(target_root).name or target_root
    if target_name.endswith("_ws"):
        target_label = f"{target_name} workspace"
    else:
        target_label = target_name
    _REASON_TEMPLATES: dict[str, str] = {
        "destructive_delete": "delete {target} recursively",
        "destructive_git_clean": "clean untracked files in {target}",
        "destructive_git_reset": "hard reset repository state in {target}",
        "destructive_move": "move/rename files in {target}",
        "sensitive_file_move": "move sensitive file in {target}",
        "config_integrity_mutation": "overwrite config in {target}",
        "destructive_permission_change": "remove all permissions on {target}",
        "sensitive_permission_change": "change permissions on sensitive {target}",
        "sensitive_ownership_change": "change ownership of sensitive {target}",
        "ownership_change": "change ownership in {target}",
        "secret_access": "access secret in {target}",
        "wildcard_destructive_scope": "wildcard operation in {target}",
        "destructive_find_delete": "find-and-delete in {target}",
        "destructive_truncate": "truncate file in {target}",
        "destructive_overwrite": "overwrite data in {target}",
        "dependency_force_reinstall": "force-reinstall dependency in {target}",
        "in_place_file_edit": "in-place edit file in {target}",
        "sensitive_path_access": "access sensitive path in {target}",
    }
    template = _REASON_TEMPLATES.get(risk_reason)
    if template:
        return template.format(target=target_label)
    label = risk_label(risk_reason)
    item = risk_definition(risk_reason)
    if item is not None:
        return f"{label.lower()} in {target_label}"
    return f"{risk_reason} on {target_label}"


def _format_recovery_sources(recovery_count: int) -> str:
    if recovery_count == 0:
        return "no recovery"
    if recovery_count == 1:
        return "1 recovery point"
    return f"{recovery_count} recovery points"


def _restore_scope_summary(*, paths: list[str]) -> list[str]:
    summary: list[str] = []
    normalized = [Path(path) for path in paths]
    workspace_root = None
    for path in normalized:
        if path.name == ".git":
            workspace_root = path.parent
            break
    if workspace_root is None and normalized:
        workspace_root = normalized[0].parent
    if any(path.name == ".git" for path in normalized):
        summary.append(".git")
    top_level_names: list[str] = []
    danger_keep = False
    for path in normalized:
        if workspace_root is None:
            continue
        try:
            rel_parts = path.relative_to(workspace_root).parts
        except ValueError:
            continue
        if not rel_parts:
            continue
        if rel_parts[:2] == ("danger", "keep.txt"):
            danger_keep = True
            continue
        name = rel_parts[0]
        if name == ".git":
            continue
        if name not in top_level_names:
            top_level_names.append(name)
    summary.extend(top_level_names[:6])
    if danger_keep:
        summary.append("danger/keep.txt")
    return summary[:8]


def _summarize_monitoring_status(sessions: list[dict[str, object]]) -> str:
    if not sessions:
        return "none"
    statuses = {str(item.get("monitoring_status") or "") for item in sessions}
    if len(statuses) == 1:
        return next(iter(statuses))
    return "mixed"


def _review_lines(
    *,
    config_path: Path,
    session_id: str,
    impact_sets: list[dict[str, object]],
    full: bool = False,
) -> list[str]:
    lines = [f"[clawchain] review session={session_id}"]
    if not impact_sets:
        lines.append("[clawchain] dangerous operations: none")
        return lines
    lines.append("[clawchain] dangerous operations:")
    for index, item in enumerate(impact_sets[:8], start=1):
        operation_summary = _natural_language_operation_summary(
            risk_reason=str(item.get("risk_reason") or ""),
            target_root=str(item.get("target_root") or ""),
        )
        lines.append(
            f"  [{index}] {_format_ts_label(item.get('created_ts_ms'))} "
            f"{operation_summary} "
            f"(recoveries={len(item.get('recovery_ids', ()))} id={item.get('impact_set_id')})"
        )
        if full:
            visible_nodes: list[str] = []
            seen_nodes: set[str] = set()
            for node in item.get("target_name_hints", ()):
                node_text = str(node)
                if not _is_review_visible_target(node_text) or node_text in seen_nodes:
                    continue
                seen_nodes.add(node_text)
                visible_nodes.append(node_text)
            if visible_nodes:
                lines.append(f"      nodes: {', '.join(visible_nodes[:6])}")
            lines.append(f"      risk: {item.get('risk_reason') or '-'}")
            lines.append(f"      protected: {_format_recovery_sources(len(item.get('recovery_ids', ())))}")
        lines.append(
            "      restore: "
            f"python -m clawchain.agent_proxy_cli restore --config {config_path} "
            f"--session {session_id} --pick {index} --approve"
        )
    return lines


def _filter_impact_sets(
    *,
    impact_sets: list[dict[str, object]],
    risk_filter: str | None = None,
    since_ms: int | None = None,
    limit: int | None = None,
) -> list[dict[str, object]]:
    rows = list(impact_sets)
    if risk_filter is not None:
        rows = [row for row in rows if str(row.get("risk_reason") or "") == risk_filter]
    if since_ms is not None:
        rows = [row for row in rows if int(row.get("created_ts_ms") or 0) >= since_ms]
    if limit is not None:
        rows = rows[: max(limit, 0)]
    return rows


def _collect_registry_review_entries(*, account_id: str, root_dir: Path | None = None) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    try:
        registry_rows = _load_session_registry(account_id, root_dir=root_dir)
    except TypeError:
        registry_rows = _load_session_registry(account_id)
    for row in registry_rows:
        config_path = row.get("config_path")
        session_id = str(row.get("session_id") or "")
        if not config_path or not session_id:
            continue
        config_file = Path(str(config_path))
        if not config_file.exists():
            continue
        try:
            stored = load_agent_proxy_config(config_file)
            base_dir = getattr(stored, "base_dir", None)
        except Exception:  # noqa: BLE001
            continue
        impact_sets: list[dict[str, object]]
        if base_dir:
            catalog = RecoveryImpactSetCatalogStore(
                Path(str(base_dir)).expanduser() / "runtime" / "local" / "recovery-impact-sets.jsonl"
            )
            impact_sets = [
                {
                    "impact_set_id": record.impact_set_id,
                    "created_ts_ms": record.created_ts_ms,
                    "target_root": record.target_root,
                    "risk_reason": record.risk_reason,
                    "recovery_ids": tuple(record.recovery_ids),
                }
                for record in catalog.read_all()
                if record.session_id == session_id
            ]
            impact_sets.sort(key=lambda item: int(item["created_ts_ms"]), reverse=True)
        else:
            try:
                proxy = TransparentAgentProxy.create(stored.to_proxy_config())
            except Exception:  # noqa: BLE001
                continue
            try:
                impact_sets = _collect_impact_sets(proxy=proxy, session_id=session_id)
            finally:
                proxy.close()
        for impact_set in impact_sets:
            entries.append(
                {
                    "session_id": session_id,
                    "session_name": row.get("session_name") or session_id,
                    "agent_id": row.get("agent_id") or "-",
                    "config_path": str(config_file),
                    "impact_set_id": impact_set["impact_set_id"],
                    "created_ts_ms": impact_set["created_ts_ms"],
                    "target_root": impact_set["target_root"],
                    "risk_reason": impact_set["risk_reason"],
                    "recovery_ids": tuple(impact_set.get("recovery_ids", ())),
                }
            )
    entries.sort(key=lambda item: int(item.get("created_ts_ms") or 0), reverse=True)
    return entries

def _load_json_rows_for_proof(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    if isinstance(payload, list):
        return [dict(row) for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        return [dict(row) for row in payload["rows"] if isinstance(row, dict)]
    return []


def _path_digest(path: Path) -> str | None:
    if not path.exists():
        return None
    if path.is_file():
        try:
            return sha256(path.read_bytes()).hexdigest()
        except Exception:  # noqa: BLE001
            return None
    if path.is_dir():
        digest = sha256()
        try:
            for child in sorted(p for p in path.rglob('*') if p.is_file()):
                rel = child.relative_to(path).as_posix().encode('utf-8')
                digest.update(rel)
                digest.update(b'\0')
                digest.update(sha256(child.read_bytes()).digest())
        except Exception:  # noqa: BLE001
            return None
        return digest.hexdigest()
    return None


def _proof_artifact_hashes(card: dict[str, object]) -> dict[str, object]:
    snapshot_paths = [str(item) for item in card.get('snapshot_paths', []) if item]
    return {
        'receipt_sha256': _path_digest(Path(str(card.get('receipt') or ''))),
        'submission_sha256': _path_digest(Path(str(card.get('submission') or ''))),
        'recovery_catalog_sha256': _path_digest(Path(str(card.get('recovery_catalog') or ''))),
        'impact_catalog_sha256': _path_digest(Path(str(card.get('impact_catalog') or ''))),
        'snapshot_digests': {p: _path_digest(Path(p)) for p in snapshot_paths},
    }


def _build_proof_manifest(*, account_id: str, cards: list[dict[str, object]]) -> dict[str, object]:
    manifest_cards = []
    for card in cards:
        manifest_cards.append({
            'session_id': card.get('session_id'),
            'session_name': card.get('session_name'),
            'impact_set_id': card.get('impact_set_id'),
            'summary': card.get('summary'),
            'risk_reason': card.get('risk_reason'),
            'target_root': card.get('target_root'),
            'git_source': list(card.get('git_source', []) or []),
            'snapshot_paths': list(card.get('snapshot_paths', []) or []),
            'receipt': card.get('receipt'),
            'submission': card.get('submission'),
            'anchor_reference': card.get('anchor_reference'),
            'anchor_backend': card.get('anchor_backend'),
            'anchor_mode': card.get('anchor_mode'),
            'batch_seq_no': card.get('batch_seq_no'),
            'merkle_root': card.get('merkle_root'),
            'commitment_type': card.get('commitment_type'),
            'encrypted_bundle_ref': card.get('encrypted_bundle_ref'),
            'artifact_hashes': _proof_artifact_hashes(card),
        })
    return {
        'format': 'clawchain-proof-manifest.v1',
        'account_id': account_id,
        'count': len(manifest_cards),
        'cards': manifest_cards,
        'github_verification': {
            'how_to_publish': 'Commit this manifest to GitHub alongside your project history. The verify command can recompute local artifact hashes and compare them against this committed manifest.',
            'how_to_verify': 'Run `python -m clawchain.agent_proxy_cli verify --manifest <path>` on a machine holding the local ClawChain recovery artifacts.',
        },
    }


def _save_proof_manifest(*, manifest: dict[str, object], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    return output_path


def _verify_proof_manifest(*, manifest_path: Path, account_id: str | None = None, root_dir: Path | None = None) -> dict[str, object]:
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if str(manifest.get('format') or '') != 'clawchain-proof-manifest.v1':
        return {'ok': False, 'error': 'unsupported_manifest_format'}
    effective_account = str(account_id or manifest.get('account_id') or os.environ.get('CLAWCHAIN_AGENT_ACCOUNT_ID') or 'local-operator')
    entries = _collect_registry_review_entries(account_id=effective_account, root_dir=root_dir)
    cards = [_build_proof_card(row) for row in entries]
    current_by_key = {
        (str(card.get('session_id') or ''), str(card.get('impact_set_id') or '')): card
        for card in cards
    }
    results = []
    all_ok = True
    for item in manifest.get('cards', []):
        if not isinstance(item, dict):
            continue
        key = (str(item.get('session_id') or ''), str(item.get('impact_set_id') or ''))
        current = current_by_key.get(key)
        if current is None:
            results.append({'session_id': key[0], 'impact_set_id': key[1], 'ok': False, 'error': 'local_card_missing'})
            all_ok = False
            continue
        expected_hashes = dict(item.get('artifact_hashes') or {})
        actual_hashes = _proof_artifact_hashes(current)
        fields_ok = {
            'anchor_reference': str(item.get('anchor_reference') or '') == str(current.get('anchor_reference') or ''),
            'git_source': list(item.get('git_source') or []) == list(current.get('git_source') or []),
            'snapshot_paths': list(item.get('snapshot_paths') or []) == list(current.get('snapshot_paths') or []),
            'batch_seq_no': item.get('batch_seq_no') == current.get('batch_seq_no'),
            'merkle_root': str(item.get('merkle_root') or '') == str(current.get('merkle_root') or ''),
            'commitment_type': str(item.get('commitment_type') or '') == str(current.get('commitment_type') or ''),
        }
        hashes_ok = expected_hashes == actual_hashes
        ok = hashes_ok and all(fields_ok.values())
        if not ok:
            all_ok = False
        results.append({
            'session_id': key[0],
            'impact_set_id': key[1],
            'ok': ok,
            'field_checks': fields_ok,
            'expected_hashes': expected_hashes,
            'actual_hashes': actual_hashes,
            'current_anchor_reference': current.get('anchor_reference'),
        })
    return {
        'ok': all_ok,
        'manifest_path': str(manifest_path),
        'account_id': effective_account,
        'count': len(results),
        'results': results,
    }


def _build_proof_card(entry: dict[str, object]) -> dict[str, object]:
    config_file = Path(str(entry.get("config_path") or ""))
    if not config_file.exists():
        return {
            "session_id": entry.get("session_id"),
            "session_name": entry.get("session_name"),
            "impact_set_id": entry.get("impact_set_id"),
            "created_ts_ms": entry.get("created_ts_ms"),
            "summary": _natural_language_operation_summary(
                risk_reason=str(entry.get("risk_reason") or ""),
                target_root=str(entry.get("target_root") or ""),
            ),
            "config_path": str(config_file),
            "error": "config_path_missing",
        }
    stored = load_agent_proxy_config(config_file)
    base_dir = getattr(stored, "base_dir", None)
    if not base_dir:
        return {
            "session_id": entry.get("session_id"),
            "session_name": entry.get("session_name"),
            "impact_set_id": entry.get("impact_set_id"),
            "created_ts_ms": entry.get("created_ts_ms"),
            "summary": _natural_language_operation_summary(
                risk_reason=str(entry.get("risk_reason") or ""),
                target_root=str(entry.get("target_root") or ""),
            ),
            "config_path": str(config_file),
            "error": "base_dir_missing",
        }
    base_path = Path(str(base_dir)).expanduser()
    proxy_paths = AgentProxyPaths.from_base_dir(base_path)
    chain_paths = ClawChainPaths.from_root(
        proxy_paths.runtime_root,
        remote_root=proxy_paths.evidence_root,
        vault_root=proxy_paths.vault_root,
    )
    locator_rows = RecoveryCatalogStore(chain_paths.recovery_catalog_path).read_all()
    locator_by_id = {row.recovery_id: row for row in locator_rows}
    recovery_ids = tuple(entry.get("recovery_ids", ()) or ())
    selected_locators = [locator_by_id[rid] for rid in recovery_ids if rid in locator_by_id]
    source_kinds = sorted({row.source_kind for row in selected_locators})
    git_recovery_ids = [row.recovery_id for row in selected_locators if row.source_kind == "git"]
    snapshot_paths = [str(chain_paths.vault_root / "recovery-snapshots" / row.recovery_id) for row in selected_locators if row.source_kind == "snapshot"]
    wanted = set(recovery_ids)
    if entry.get("impact_set_id"):
        wanted.add(str(entry.get("impact_set_id")))
    def _related(rows: list[dict[str, object]]) -> list[dict[str, object]]:
        out = []
        for row in rows:
            subject_id = str(row.get("subject_id") or "")
            event_ids = {str(item) for item in row.get("event_ids", []) if item is not None}
            if subject_id in wanted or wanted.intersection(event_ids):
                out.append(row)
        return out
    receipts = _related(_load_json_rows_for_proof(chain_paths.receipt_store_path))
    submissions = _related(_load_json_rows_for_proof(chain_paths.submission_store_path))
    latest_receipt = receipts[-1] if receipts else {}
    latest_submission = submissions[-1] if submissions else {}
    metadata = dict(latest_receipt.get("metadata") or {})
    return {
        "session_id": entry.get("session_id"),
        "session_name": entry.get("session_name"),
        "impact_set_id": entry.get("impact_set_id"),
        "created_ts_ms": entry.get("created_ts_ms"),
        "risk_reason": entry.get("risk_reason"),
        "target_root": entry.get("target_root"),
        "summary": _natural_language_operation_summary(
            risk_reason=str(entry.get("risk_reason") or ""),
            target_root=str(entry.get("target_root") or ""),
        ),
        "git_source": git_recovery_ids,
        "snapshot_paths": snapshot_paths,
        "receipt": str(chain_paths.receipt_store_path),
        "submission": str(chain_paths.submission_store_path),
        "anchor_reference": latest_receipt.get("anchor_reference") or latest_submission.get("anchor_reference"),
        "anchor_backend": latest_receipt.get("anchor_backend") or latest_submission.get("anchor_backend"),
        "anchor_mode": latest_receipt.get("anchor_mode") or latest_submission.get("anchor_mode"),
        "batch_seq_no": latest_receipt.get("batch_seq_no") or latest_submission.get("batch_seq_no"),
        "merkle_root": latest_receipt.get("merkle_root") or latest_submission.get("merkle_root"),
        "commitment_type": latest_receipt.get("commitment_type") or latest_submission.get("commitment_type"),
        "config_path": str(config_file),
        "encrypted_bundle_ref": metadata.get("encrypted_bundle_ref"),
        "recovery_catalog": str(chain_paths.recovery_catalog_path),
        "impact_catalog": str(chain_paths.recovery_impact_set_catalog_path),
        "remote_evidence": str(proxy_paths.evidence_root),
        "vault_root": str(proxy_paths.vault_root),
        "source_kinds": source_kinds,
    }



def _default_chain_manifest_path(account_id: str, *, root_dir: Path | None = None) -> Path:
    return _default_account_root(account_id, root_dir=root_dir) / "_internal" / "chain" / "deployment.json"


def _iter_account_config_paths(account_id: str, *, root_dir: Path | None = None) -> list[Path]:
    account_root = _default_account_root(account_id, root_dir=root_dir)
    seen: set[Path] = set()
    paths: list[Path] = []
    default_path = _default_account_config_path(account_id, root_dir=root_dir)
    if default_path.exists():
        seen.add(default_path.resolve())
        paths.append(default_path)
    if account_root.exists():
        for candidate in sorted(account_root.rglob('agent-proxy.config.json')):
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            paths.append(candidate)
    return paths


def _resolve_manifest_path_for_stored_config(stored: AgentProxyStoredConfig) -> Path | None:
    manifest_value = getattr(stored, 'evm_manifest_path', None)
    if manifest_value:
        manifest_path = Path(str(manifest_value)).expanduser()
        if manifest_path.exists():
            return manifest_path
    base_dir = getattr(stored, 'base_dir', None)
    if base_dir:
        candidate = Path(str(base_dir)).expanduser() / 'deployment.json'
        if candidate.exists():
            return candidate
    return None


def _build_evm_manifest(
    *,
    manifest_path: Path,
    rpc_url: str,
    chain_id: int,
    contract_address: str,
) -> Path:
    manifest = EvmDeploymentManifest(
        chain_id=chain_id,
        rpc_url=rpc_url,
        contract_address=contract_address,
        source_path=str(resolve_commitment_anchor_source_path()),
        abi_path=str(resolve_commitment_anchor_abi_path()),
        notes='Generated by clawchain.agent_proxy_cli chain-connect',
    )
    write_evm_deployment_manifest(manifest_path, manifest)
    return manifest_path


def _deployment_report_payload(report: EvmDeploymentVerificationReport) -> dict[str, object]:
    probe = report.probe
    return {
        'ok': report.ok,
        'findings': list(report.findings),
        'error': report.error,
        'manifest': {
            'chain_id': report.manifest.chain_id,
            'rpc_url': report.manifest.rpc_url,
            'contract_address': report.manifest.contract_address,
            'contract_name': report.manifest.contract_name,
            'deploy_tx_hash': report.manifest.deploy_tx_hash,
            'source_path': report.manifest.source_path,
            'abi_path': report.manifest.abi_path,
        },
        'probe': (
            {
                'rpc_url': probe.rpc_url,
                'client_version': probe.client_version,
                'chain_id': probe.chain_id,
                'latest_block': probe.latest_block,
                'contract_address': probe.contract_address,
                'contract_code_present': probe.contract_code_present,
                'configured_chain_id': probe.configured_chain_id,
                'chain_id_matches': probe.chain_id_matches,
            }
            if probe is not None
            else None
        ),
    }


def _chain_summary_from_card(card: dict[str, object]) -> dict[str, object]:
    return {
        'session_id': card.get('session_id'),
        'session_name': card.get('session_name'),
        'impact_set_id': card.get('impact_set_id'),
        'summary': card.get('summary'),
        'anchor_backend': card.get('anchor_backend'),
        'anchor_mode': card.get('anchor_mode'),
        'anchor_reference': card.get('anchor_reference'),
        'batch_seq_no': card.get('batch_seq_no'),
        'merkle_root': card.get('merkle_root'),
        'commitment_type': card.get('commitment_type'),
    }


def _resolve_chain_manifest_for_account(
    *,
    account_id: str,
    root_dir: Path | None = None,
    config_path: Path | None = None,
) -> tuple[Path | None, AgentProxyStoredConfig | None, Path | None]:
    candidate_paths = []
    if config_path is not None:
        candidate_paths.append(config_path)
    candidate_paths.extend(_iter_account_config_paths(account_id, root_dir=root_dir))
    seen: set[Path] = set()
    for candidate in candidate_paths:
        resolved_candidate = candidate.expanduser().resolve()
        if resolved_candidate in seen or not candidate.exists():
            continue
        seen.add(resolved_candidate)
        stored = load_agent_proxy_config(candidate)
        manifest_path = _resolve_manifest_path_for_stored_config(stored)
        if manifest_path is not None:
            return manifest_path, stored, candidate
    if config_path is not None and config_path.exists():
        stored = load_agent_proxy_config(config_path)
        return None, stored, config_path
    return None, None, None


def _collect_chain_cards(
    *,
    account_id: str,
    root_dir: Path | None = None,
    session_id: str | None = None,
    impact_set_id: str | None = None,
) -> list[dict[str, object]]:
    registry_entries = _collect_registry_review_entries(account_id=account_id, root_dir=root_dir)
    if session_id is not None:
        registry_entries = [row for row in registry_entries if str(row.get('session_id') or '') == session_id]
    if impact_set_id is not None:
        registry_entries = [row for row in registry_entries if str(row.get('impact_set_id') or '') == impact_set_id]
    cards = [_build_proof_card(row) for row in registry_entries]
    seen_pairs = {
        (str(row.get('session_id') or ''), str(row.get('impact_set_id') or ''))
        for row in registry_entries
    }
    session_name_map = {
        str(row.get('session_id') or ''): str(row.get('session_name') or row.get('session_id') or '')
        for row in registry_entries
        if row.get('session_id')
    }
    for config_path in _iter_account_config_paths(account_id, root_dir=root_dir):
        try:
            stored = load_agent_proxy_config(config_path)
        except Exception:  # noqa: BLE001
            continue
        base_dir = getattr(stored, 'base_dir', None)
        configured_session_id = str(getattr(stored, 'default_session_id', '') or '')
        if not base_dir or not configured_session_id:
            continue
        catalog = RecoveryImpactSetCatalogStore(
            Path(str(base_dir)).expanduser() / 'runtime' / 'local' / 'recovery-impact-sets.jsonl'
        )
        try:
            impact_rows = list(catalog.read_all())
        except Exception:  # noqa: BLE001
            continue
        agent_id = config_path.parent.parent.name if config_path.parent.parent != config_path.parent else '-'
        for record in impact_rows:
            if record.session_id != configured_session_id:
                continue
            if session_id is not None and record.session_id != session_id:
                continue
            if impact_set_id is not None and record.impact_set_id != impact_set_id:
                continue
            key = (record.session_id, record.impact_set_id)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            session_name = session_name_map.get(record.session_id) or record.session_id
            cards.append(_build_proof_card({
                'session_id': record.session_id,
                'session_name': session_name,
                'agent_id': agent_id,
                'config_path': str(config_path),
                'impact_set_id': record.impact_set_id,
                'created_ts_ms': record.created_ts_ms,
                'target_root': record.target_root,
                'risk_reason': record.risk_reason,
                'recovery_ids': tuple(record.recovery_ids),
            }))
    cards = [card for card in cards if not card.get('error')]
    cards.sort(key=lambda row: int(row.get('created_ts_ms') or 0), reverse=True)
    return cards


def _chain_connect_account(
    *,
    account_id: str,
    root_dir: Path | None = None,
    config_path: Path | None = None,
    manifest_path: Path | None = None,
    rpc_url: str | None = None,
    chain_id: int | None = None,
    contract_address: str | None = None,
    bootstrap_local: bool = False,
    deployer_private_key: str | None = None,
) -> dict[str, object]:
    config_paths = []
    if config_path is not None:
        config_paths.append(config_path)
    config_paths.extend(_iter_account_config_paths(account_id, root_dir=root_dir))
    deduped: list[Path] = []
    seen: set[Path] = set()
    for candidate in config_paths:
        resolved = candidate.expanduser().resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(candidate)
    if not deduped:
        default_config = _default_account_config_path(account_id, root_dir=root_dir)
        if not default_config.exists():
            return {'ok': False, 'error': 'account_config_missing', 'account_id': account_id}
        deduped.append(default_config)
    primary_path = deduped[0]
    primary_stored = load_agent_proxy_config(primary_path)

    evm_process = None
    resolved_manifest_path = manifest_path.expanduser() if manifest_path is not None else None
    if bootstrap_local:
        proxy_config = replace(
            primary_stored.to_proxy_config(),
            evm_manifest_path=(
                str(resolved_manifest_path)
                if resolved_manifest_path is not None
                else str(_default_chain_manifest_path(account_id, root_dir=root_dir))
            ),
            evm_rpc_url=rpc_url if rpc_url is not None else primary_stored.evm_rpc_url,
            evm_chain_id=chain_id if chain_id is not None else primary_stored.evm_chain_id,
            evm_contract_address=contract_address if contract_address is not None else None,
            evm_deployer_private_key=(
                deployer_private_key
                if deployer_private_key is not None
                else primary_stored.evm_deployer_private_key
            ),
            auto_bootstrap_evm=True,
        )
        base_dir = Path(primary_stored.base_dir).expanduser() if primary_stored.base_dir else _default_account_root(account_id, root_dir=root_dir)
        resolved_manifest_path, evm_process = _bootstrap_local_evm_manifest_with_config(proxy_config, base_dir)
        if resolved_manifest_path is None:
            return {'ok': False, 'error': 'evm_bootstrap_failed', 'account_id': account_id}
    elif resolved_manifest_path is None and rpc_url and chain_id is not None and contract_address:
        resolved_manifest_path = _build_evm_manifest(
            manifest_path=_default_chain_manifest_path(account_id, root_dir=root_dir),
            rpc_url=rpc_url,
            chain_id=chain_id,
            contract_address=contract_address,
        )

    if resolved_manifest_path is None:
        resolved_manifest_path = _resolve_manifest_path_for_stored_config(primary_stored)
    if resolved_manifest_path is None or not resolved_manifest_path.exists():
        return {'ok': False, 'error': 'evm_manifest_missing', 'account_id': account_id}

    manifest = load_evm_deployment_manifest(resolved_manifest_path)
    report = verify_evm_deployment_manifest(manifest)

    updated_configs = []
    for candidate in deduped:
        stored = load_agent_proxy_config(candidate)
        updated = AgentProxyStoredConfig(
            account_id=stored.account_id,
            password=stored.password,
            base_dir=stored.base_dir,
            path_hint=stored.path_hint,
            default_session_id=stored.default_session_id,
            default_run_id=stored.default_run_id,
            auto_start_sidecar=stored.auto_start_sidecar,
            anchor_strategy=stored.anchor_strategy,
            auto_bootstrap_evm=False,
            evm_manifest_path=str(resolved_manifest_path),
            evm_rpc_url=manifest.rpc_url,
            evm_chain_id=manifest.chain_id,
            evm_contract_address=manifest.contract_address,
            evm_deployer_private_key=stored.evm_deployer_private_key,
            protected_path_prefixes=stored.protected_path_prefixes,
            protected_file_names=stored.protected_file_names,
            allowed_env_names=stored.allowed_env_names,
            allowed_secret_file_paths=stored.allowed_secret_file_paths,
            git_context_mode=stored.git_context_mode,
            git_max_file_count_per_target=stored.git_max_file_count_per_target,
            git_max_total_bytes_per_target=stored.git_max_total_bytes_per_target,
        )
        write_agent_proxy_config(candidate, updated)
        updated_configs.append(str(candidate))

    return {
        'ok': True,
        'account_id': account_id,
        'manifest_path': str(resolved_manifest_path),
        'updated_configs': updated_configs,
        'deployment': _deployment_report_payload(report),
        'local_devnet_pid': evm_process.pid if evm_process is not None else None,
    }


def _chain_status(
    *,
    account_id: str,
    root_dir: Path | None = None,
    config_path: Path | None = None,
) -> dict[str, object]:
    manifest_path, stored, resolved_config = _resolve_chain_manifest_for_account(
        account_id=account_id,
        root_dir=root_dir,
        config_path=config_path,
    )
    config_paths = [str(path) for path in _iter_account_config_paths(account_id, root_dir=root_dir)]
    payload: dict[str, object] = {
        'ok': manifest_path is not None,
        'account_id': account_id,
        'config_path': str(resolved_config) if resolved_config is not None else None,
        'config_count': len(config_paths),
        'config_paths': config_paths,
        'evm_enabled_config_count': 0,
        'manifest_path': str(manifest_path) if manifest_path is not None else None,
        'deployment': None,
        'latest_cards': [],
    }
    enabled_count = 0
    for path_str in config_paths:
        cfg = load_agent_proxy_config(Path(path_str))
        if _resolve_manifest_path_for_stored_config(cfg) is not None or (cfg.evm_rpc_url and cfg.evm_contract_address):
            enabled_count += 1
    payload['evm_enabled_config_count'] = enabled_count
    if manifest_path is not None:
        manifest = load_evm_deployment_manifest(manifest_path)
        payload['deployment'] = _deployment_report_payload(verify_evm_deployment_manifest(manifest))
    cards = _collect_chain_cards(account_id=account_id, root_dir=root_dir)
    payload['latest_cards'] = [_chain_summary_from_card(card) for card in cards[:5]]
    return payload


def _chain_verify(
    *,
    account_id: str,
    root_dir: Path | None = None,
    config_path: Path | None = None,
    session_id: str | None = None,
    impact_set_id: str | None = None,
) -> dict[str, object]:
    cards = _collect_chain_cards(
        account_id=account_id,
        root_dir=root_dir,
        session_id=session_id,
        impact_set_id=impact_set_id,
    )
    if not cards:
        return {'ok': False, 'error': 'chain_card_missing', 'account_id': account_id}
    card = cards[0]
    if not str(card.get('anchor_backend') or '').startswith('evm:'):
        return {'ok': False, 'error': 'card_not_evm_anchored', 'card': _chain_summary_from_card(card)}
    card_config_path = Path(str(card.get('config_path'))) if card.get('config_path') else None
    manifest_path, _stored, _resolved_config = _resolve_chain_manifest_for_account(
        account_id=account_id,
        root_dir=root_dir,
        config_path=config_path or card_config_path,
    )
    if manifest_path is None:
        return {'ok': False, 'error': 'evm_manifest_missing', 'card': _chain_summary_from_card(card)}
    manifest = load_evm_deployment_manifest(manifest_path)
    report = verify_evm_deployment_manifest(manifest)
    if card.get('batch_seq_no') is None or not card.get('merkle_root'):
        return {
            'ok': False,
            'error': 'chain_subject_missing',
            'manifest_path': str(manifest_path),
            'deployment': _deployment_report_payload(report),
            'card': _chain_summary_from_card(card),
        }
    broadcaster = RpcEvmBroadcaster(manifest.rpc_url)
    lookup = broadcaster.lookup_commitment(
        contract_address=manifest.contract_address,
        session_id=str(card.get('session_id') or ''),
        batch_seq_no=int(card.get('batch_seq_no') or 0),
        merkle_root=str(card.get('merkle_root') or ''),
    )
    lookup_payload = {
        'found': lookup.found,
        'session_id': lookup.session_id,
        'batch_seq_no': lookup.batch_seq_no,
        'merkle_root': lookup.merkle_root,
        'anchored_at_block': lookup.anchored_at_block,
        'submitter': lookup.submitter,
    }
    card_root = str(card.get('merkle_root') or '').lower()
    lookup_root = str(lookup.merkle_root or '').lower()
    if card_root.startswith('0x'):
        card_root = card_root[2:]
    if lookup_root.startswith('0x'):
        lookup_root = lookup_root[2:]
    field_checks = {
        'session_id': lookup.session_id == str(card.get('session_id') or ''),
        'batch_seq_no': lookup.batch_seq_no == int(card.get('batch_seq_no') or 0),
        'merkle_root': lookup_root == card_root,
    }
    ok = bool(report.ok and lookup.found and all(field_checks.values()))
    return {
        'ok': ok,
        'account_id': account_id,
        'manifest_path': str(manifest_path),
        'deployment': _deployment_report_payload(report),
        'card': _chain_summary_from_card(card),
        'lookup': lookup_payload,
        'field_checks': field_checks,
    }



def _pending_capture_sessions(*, account_id: str) -> list[SessionRegistryEntry]:
    return [
        row for row in _load_session_registry(account_id)
        if str(row.get("capture_mode") or "") == "pending-relaunch"
    ]


def _review_registry_lines(*, entries: list[dict[str, object]]) -> list[str]:
    lines = ["[clawchain] review all monitored sessions"]
    if not entries:
        lines.append("[clawchain] dangerous operations: none")
        return lines
    lines.append("[clawchain] dangerous operations:")
    for index, item in enumerate(entries[:20], start=1):
        summary = _natural_language_operation_summary(
            risk_reason=str(item.get("risk_reason") or ""),
            target_root=str(item.get("target_root") or ""),
        )
        lines.append(
            f"  [{index}] {_format_ts_label(item.get('created_ts_ms'))} "
            f"[{item.get('session_name')}] {summary}"
        )
        lines.append(
            "      restore: "
            f"python -m clawchain.agent_proxy_cli recover-impact-set-latest "
            f"{item.get('config_path')} {item.get('session_id')} --impact-set-id {item.get('impact_set_id')} --approve"
        )
    return lines


def _filter_registry_entries(
    *,
    entries: list[dict[str, object]],
    risk_filter: str | None = None,
    since_ms: int | None = None,
    limit: int | None = None,
) -> list[dict[str, object]]:
    rows = list(entries)
    if risk_filter is not None:
        rows = [row for row in rows if str(row.get("risk_reason") or "") == risk_filter]
    if since_ms is not None:
        rows = [row for row in rows if int(row.get("created_ts_ms") or 0) >= since_ms]
    if limit is not None:
        rows = rows[: max(limit, 0)]
    return rows


def _history_pending_capture_lines(*, account_id: str) -> list[str]:
    pending = _pending_capture_sessions(account_id=account_id)
    if not pending:
        return []
    names = ", ".join(str(row.get("session_name") or row.get("session_id") or "-") for row in pending[:5])
    return [
        "[clawchain] warning: some monitored sessions are not yet launcher-routed",
        f"[clawchain] pending relaunch sessions: {names}",
    ]


def _guide_lines() -> list[str]:
    return [
        "[clawchain] final user pipeline",
        "[clawchain] 0. deploy an operator account",
        "  python -m clawchain.agent_proxy_cli deploy <account> <password> --no-start-service",
        "[clawchain] 0b. inspect account status",
        "  python -m clawchain.agent_proxy_cli status <account>",
        "[clawchain] 1. supervise agent sessions",
        "  python -m clawchain.agent_proxy_cli supervise codex <account> <password> --no-start-service",
        "[clawchain] 1b. inspect monitored/running sessions",
        "  python -m clawchain.agent_proxy_cli sessions <account>",
        "[clawchain] 2. onboard a detected session",
        "  python -m clawchain.agent_proxy_cli onboard codex <account> <password> --no-start-service",
        "[clawchain] 3. choose Git context",
        "  [1] bind-existing-git",
        "  [2] managed-session-git",
        "[clawchain] 4. recovery source selection",
        "  automatic per dangerous command",
        "[clawchain] 5. review dangerous operations",
        "  python -m clawchain.agent_proxy_cli history --session <session-id>",
        "[clawchain] 6. restore a dangerous operation",
        "  python -m clawchain.agent_proxy_cli restore --session <session-id> --pick <N> --approve",
        "[clawchain] 7. restore the latest whole impact set",
        "  python -m clawchain.agent_proxy_cli restore --session <session-id> --approve",
        "[clawchain] notes",
        "  monitoring scope: agent session",
        "  path hint: detected path only, not a hard boundary",
        "  chain anchoring: operation-level checkpoint",
        "  recovery scope: whole dangerous command impact",
    ]


def _default_account_root(account_id: str, *, root_dir: Path | None = None) -> Path:
    base = root_dir.expanduser() if root_dir is not None else _registry_root()
    return base / account_id


def _default_account_config_path(account_id: str, *, root_dir: Path | None = None) -> Path:
    return _default_account_root(account_id, root_dir=root_dir) / "agent-proxy.config.json"


def _default_proof_repo_dir(account_id: str, *, root_dir: Path | None = None) -> Path:
    return _default_account_root(account_id, root_dir=root_dir) / "proof-manifests"


def _runtime_proxy_config(
    *,
    account_id: str,
    password: str,
    root_dir: Path | None,
    auto_evm: bool,
) -> AgentProxyConfig:
    resolved_root = root_dir.expanduser() if root_dir is not None else None
    if resolved_root is not None:
        config_path = resolved_root / "agent-proxy.config.json"
        if config_path.exists():
            stored = load_agent_proxy_config(config_path)
            return replace(
                stored.to_proxy_config(),
                account_id=account_id,
                password=password,
                base_dir=resolved_root,
                auto_bootstrap_evm=auto_evm,
            )
    return AgentProxyConfig(
        account_id=account_id,
        password=password,
        base_dir=resolved_root,
        auto_bootstrap_evm=auto_evm,
    )


def _git_run(args: list[str], *, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=str(cwd), text=True, capture_output=True, check=check)


def _ensure_local_proof_repo(account_id: str, *, root_dir: Path | None = None, repo_dir: Path | None = None) -> dict[str, object]:
    repo = (repo_dir or _default_proof_repo_dir(account_id, root_dir=root_dir)).expanduser()
    repo.mkdir(parents=True, exist_ok=True)
    git_dir = repo / '.git'
    initialized = git_dir.exists()
    if not initialized:
        init_result = _git_run(['git', 'init', '-b', 'main'], cwd=repo, check=False)
        if init_result.returncode != 0:
            # Older git releases do not support `git init -b`.
            fallback = _git_run(['git', 'init'], cwd=repo, check=False)
            if fallback.returncode != 0:
                raise subprocess.CalledProcessError(
                    fallback.returncode,
                    fallback.args,
                    output=fallback.stdout,
                    stderr=fallback.stderr,
                )
            _git_run(['git', 'symbolic-ref', 'HEAD', 'refs/heads/main'], cwd=repo, check=False)
            _git_run(['git', 'branch', '-M', 'main'], cwd=repo, check=False)
    # ensure deterministic local identity so auto-commit works even without global git config
    _git_run(['git', 'config', 'user.name', 'ClawChain Bot'], cwd=repo)
    _git_run(['git', 'config', 'user.email', 'clawchain@localhost'], cwd=repo)
    readme = repo / 'README.md'
    if not readme.exists():
        readme.write_text('# ClawChain Proof Manifests\n\nThis repository stores exported ClawChain proof manifests for audit and verification.\n', encoding='utf-8')
        _git_run(['git', 'add', 'README.md'], cwd=repo)
        _git_run(['git', 'commit', '-m', 'Initialize ClawChain proof manifest repository'], cwd=repo, check=False)
    return {
        'repo_dir': str(repo),
        'initialized': True,
        'had_existing_repo': initialized,
        'remote_origin': _git_remote_origin(repo),
    }


def _git_remote_origin(repo_dir: Path) -> str | None:
    result = _git_run(['git', 'remote', 'get-url', 'origin'], cwd=repo_dir, check=False)
    if result.returncode != 0:
        return None
    value = (result.stdout or '').strip()
    return value or None


def _publish_manifest_to_repo(*, manifest_path: Path, account_id: str, root_dir: Path | None = None, repo_dir: Path | None = None, push: bool = True) -> dict[str, object]:
    repo_info = _ensure_local_proof_repo(account_id, root_dir=root_dir, repo_dir=repo_dir)
    repo = Path(str(repo_info['repo_dir']))
    manifests_dir = repo / 'manifests'
    manifests_dir.mkdir(parents=True, exist_ok=True)
    target = manifests_dir / manifest_path.name
    target.write_text(manifest_path.read_text(encoding='utf-8'), encoding='utf-8')
    _git_run(['git', 'add', str(target.relative_to(repo))], cwd=repo)
    commit_msg = f'Add ClawChain proof manifest {manifest_path.stem}'
    commit_result = _git_run(['git', 'commit', '-m', commit_msg], cwd=repo, check=False)
    branch_result = _git_run(['git', 'branch', '--show-current'], cwd=repo, check=False)
    branch = (branch_result.stdout or 'main').strip() or 'main'
    push_log = repo / 'last-push.log'
    push_started = False
    push_pid = None
    remote_origin = _git_remote_origin(repo)
    if push and remote_origin:
        with push_log.open('w', encoding='utf-8') as handle:
            proc = subprocess.Popen(['git', 'push', '-u', 'origin', branch], cwd=str(repo), stdout=handle, stderr=subprocess.STDOUT)
        push_started = True
        push_pid = proc.pid
    return {
        'repo_dir': str(repo),
        'manifest_repo_path': str(target),
        'commit_message': commit_msg,
        'commit_created': commit_result.returncode == 0,
        'commit_stdout': (commit_result.stdout or '').strip(),
        'commit_stderr': (commit_result.stderr or '').strip(),
        'remote_origin': remote_origin,
        'push_started': push_started,
        'push_pid': push_pid,
        'push_log_path': str(push_log) if push_started else None,
        'branch': branch,
    }



def _proof_repo_status(*, account_id: str, root_dir: Path | None = None, repo_dir: Path | None = None) -> dict[str, object]:
    repo_info = _ensure_local_proof_repo(account_id, root_dir=root_dir, repo_dir=repo_dir)
    repo = Path(str(repo_info['repo_dir']))
    branch_result = _git_run(['git', 'branch', '--show-current'], cwd=repo, check=False)
    head_result = _git_run(['git', 'rev-parse', 'HEAD'], cwd=repo, check=False)
    status_result = _git_run(['git', 'status', '--short'], cwd=repo, check=False)
    log_result = _git_run(['git', 'log', '--oneline', '-n', '5'], cwd=repo, check=False)
    push_log = repo / 'last-push.log'
    push_log_tail = None
    if push_log.exists():
        lines = push_log.read_text(encoding='utf-8', errors='replace').splitlines()
        push_log_tail = '\\n'.join(lines[-10:]) if lines else ''
    manifests_dir = repo / 'manifests'
    manifests = []
    if manifests_dir.exists():
        manifests = sorted(str(p.relative_to(repo)) for p in manifests_dir.rglob('*.json'))
    return {
        'ok': True,
        'account_id': account_id,
        'repo_dir': str(repo),
        'branch': (branch_result.stdout or '').strip() or 'main',
        'head': (head_result.stdout or '').strip() or None,
        'remote_origin': _git_remote_origin(repo),
        'clean': not bool((status_result.stdout or '').strip()),
        'status': (status_result.stdout or '').strip(),
        'recent_commits': [line for line in (log_result.stdout or '').splitlines() if line.strip()],
        'manifest_count': len(manifests),
        'manifests': manifests,
        'push_log_path': str(push_log) if push_log.exists() else None,
        'push_log_tail': push_log_tail,
    }



def _connect_github_remote(*, account_id: str, remote_url: str, root_dir: Path | None = None, repo_dir: Path | None = None) -> dict[str, object]:
    repo_info = _ensure_local_proof_repo(account_id, root_dir=root_dir, repo_dir=repo_dir)
    repo = Path(str(repo_info['repo_dir']))
    existing = _git_remote_origin(repo)
    if existing:
        result = _git_run(['git', 'remote', 'set-url', 'origin', remote_url], cwd=repo, check=False)
        action = 'updated'
    else:
        result = _git_run(['git', 'remote', 'add', 'origin', remote_url], cwd=repo, check=False)
        action = 'created'
    return {
        'ok': result.returncode == 0,
        'account_id': account_id,
        'repo_dir': str(repo),
        'action': action,
        'remote_origin': _git_remote_origin(repo),
        'stdout': (result.stdout or '').strip(),
        'stderr': (result.stderr or '').strip(),
    }



def _build_backup_health_card(card: dict[str, object]) -> dict[str, object]:
    snapshot_paths = [Path(str(item)) for item in list(card.get('snapshot_paths') or [])]
    existing_snapshots = [str(path) for path in snapshot_paths if path.exists()]
    missing_snapshots = [str(path) for path in snapshot_paths if not path.exists()]
    checks = {
        'receipt_exists': Path(str(card.get('receipt') or '')).exists(),
        'submission_exists': Path(str(card.get('submission') or '')).exists(),
        'recovery_catalog_exists': Path(str(card.get('recovery_catalog') or '')).exists(),
        'impact_catalog_exists': Path(str(card.get('impact_catalog') or '')).exists(),
        'remote_evidence_exists': Path(str(card.get('remote_evidence') or '')).exists(),
        'vault_root_exists': Path(str(card.get('vault_root') or '')).exists(),
    }
    missing = [key for key, ok in checks.items() if not ok]
    if missing_snapshots:
        missing.append('snapshot_paths_missing')
    return {
        'session_id': card.get('session_id'),
        'session_name': card.get('session_name'),
        'impact_set_id': card.get('impact_set_id'),
        'summary': card.get('summary'),
        'source_kinds': list(card.get('source_kinds') or []),
        'git_source_count': len(list(card.get('git_source') or [])),
        'snapshot_count': len(snapshot_paths),
        'existing_snapshot_count': len(existing_snapshots),
        'missing_snapshot_count': len(missing_snapshots),
        'receipt': card.get('receipt'),
        'submission': card.get('submission'),
        'recovery_catalog': card.get('recovery_catalog'),
        'impact_catalog': card.get('impact_catalog'),
        'remote_evidence': card.get('remote_evidence'),
        'vault_root': card.get('vault_root'),
        'anchor_reference': card.get('anchor_reference'),
        'checks': checks,
        'missing': missing,
        'ok': not missing,
    }


def _private_mode(path: Path) -> bool:
    try:
        return path.exists() and (path.stat().st_mode & 0o077) == 0
    except OSError:
        return False


def _build_security_health_card(*, account_id: str, root_dir: Path | None = None) -> dict[str, object]:
    account_root = _default_account_root(account_id, root_dir=root_dir)
    internal_root = account_root / '_internal'
    key_path = internal_root / 'proof-log.key'
    encrypted_archives = sorted(str(path) for path in account_root.rglob('*-proof-log.enc.json')) if account_root.exists() else []
    plaintext_exports = sorted(str(path) for path in account_root.rglob('*-proof-log.json')) if account_root.exists() else []
    insecure_archives = [path for path in encrypted_archives if not _private_mode(Path(path))]
    key_exists = key_path.exists()
    key_private = _private_mode(key_path) if key_exists else False
    checks = {
        'key_exists': key_exists,
        'key_private': key_private,
        'plaintext_exports_absent': len(plaintext_exports) == 0,
        'encrypted_archives_private': len(insecure_archives) == 0,
    }
    missing: list[str] = []
    if encrypted_archives and not key_exists:
        missing.append('proof_key_missing')
    if encrypted_archives and key_exists and not key_private:
        missing.append('proof_key_permissions')
    if plaintext_exports:
        missing.append('plaintext_proof_exports_present')
    if insecure_archives:
        missing.append('encrypted_archive_permissions')
    return {
        'account_root': str(account_root),
        'proof_key_path': str(key_path),
        'encrypted_archive_count': len(encrypted_archives),
        'plaintext_export_count': len(plaintext_exports),
        'encrypted_archives': encrypted_archives[:10],
        'plaintext_exports': plaintext_exports[:10],
        'checks': checks,
        'missing': missing,
        'ok': not missing,
    }


def _integrity_check(*, account_id: str, session_id: str | None = None, impact_set_id: str | None = None, limit: int | None = None, root_dir: Path | None = None, repo_dir: Path | None = None) -> dict[str, object]:
    entries = _collect_registry_review_entries(account_id=account_id, root_dir=root_dir)
    if session_id is not None:
        entries = [row for row in entries if str(row.get('session_id') or '') == session_id]
    if impact_set_id is not None:
        entries = [row for row in entries if str(row.get('impact_set_id') or '') == impact_set_id]
    if limit is not None:
        entries = entries[: max(limit, 0)]
    cards = [_build_proof_card(row) for row in entries]
    backup_cards = [_build_backup_health_card(card) for card in cards]
    repo_status = _proof_repo_status(account_id=account_id, root_dir=root_dir, repo_dir=repo_dir)
    security = _build_security_health_card(account_id=account_id, root_dir=root_dir)
    return {
        'ok': True,
        'account_id': account_id,
        'proof_repo': repo_status,
        'security': security,
        'backup_cards': backup_cards,
        'healthy_count': sum(1 for card in backup_cards if card.get('ok')),
        'unhealthy_count': sum(1 for card in backup_cards if not card.get('ok')),
    }


def _status_lines(
    *,
    account_id: str,
    registry_rows: list[SessionRegistryEntry],
    sessions: list[dict[str, object]],
    config_path: Path,
    service_payload: dict[str, object] | None,
) -> list[str]:
    monitored_count = len(registry_rows)
    running_count = len(sessions)
    unmanaged_count = len(
        [item for item in sessions if _registry_lookup(registry_rows=registry_rows, item=item) is None]
    )
    lines = ["[clawchain] account status"]
    lines.append(f"  account: {account_id}")
    lines.append(f"  config: {config_path}")
    lines.append(f"  monitored_sessions: {monitored_count}")
    lines.append(f"  running_sessions: {running_count}")
    lines.append(f"  unmanaged_sessions: {unmanaged_count}")
    if service_payload is None:
        lines.append("  service: not-configured")
    elif not service_payload.get("ok"):
        lines.append(f"  service: not-running ({service_payload.get('reason') or 'unknown'})")
    else:
        lines.append(
            "  service: "
            f"running={bool(service_payload.get('running'))} "
            f"ping_ok={bool(service_payload.get('ping_ok'))}"
        )
    return lines


def _run_review_interaction(*, config_path: Path, session_id: str, impact_sets: list[dict[str, object]]) -> int:
    if not impact_sets:
        print("[clawchain] no recoverable dangerous operations")
        return 0
    print("[clawchain] [1] 恢复历史节点")
    print("[clawchain] [2] 退出")
    choice = input().strip()
    if choice != "1":
        return 0
    print("[clawchain] 请选择想要恢复的节点编号：")
    raw_pick = input().strip()
    try:
        target_pick = int(raw_pick)
    except ValueError:
        print(f"[clawchain] invalid node pick: {raw_pick}")
        return 2
    return main(
        [
            "restore",
            "--config",
            str(config_path),
            "--session",
            session_id,
            "--pick",
            str(target_pick),
            "--approve",
        ]
    )


def _run_registry_review_interaction(*, entries: list[dict[str, object]]) -> int:
    if not entries:
        print("[clawchain] no recoverable dangerous operations")
        return 0
    print("[clawchain] [1] 恢复历史节点")
    print("[clawchain] [2] 退出")
    choice = input().strip()
    if choice != "1":
        return 0
    print("[clawchain] 请选择想要恢复的节点编号：")
    raw_pick = input().strip()
    try:
        target_pick = int(raw_pick)
    except ValueError:
        print(f"[clawchain] invalid node pick: {raw_pick}")
        return 2
    if target_pick < 1 or target_pick > len(entries):
        print(f"[clawchain] invalid node pick: {raw_pick}")
        return 2
    picked = entries[target_pick - 1]
    return main(
        [
            "recover-impact-set-latest",
            str(picked["config_path"]),
            str(picked["session_id"]),
            "--impact-set-id",
            str(picked["impact_set_id"]),
            "--approve",
        ]
    )


def _collect_latest_impact_set(*, proxy: TransparentAgentProxy, session_id: str) -> dict[str, object] | None:
    if proxy.system.recovery_impact_set_catalog is None:
        return None
    impact_sets = [
        row for row in proxy.system.recovery_impact_set_catalog.read_all()
        if row.session_id == session_id
    ]
    impact_sets.sort(key=lambda row: row.created_ts_ms, reverse=True)
    if not impact_sets:
        return None
    latest = impact_sets[0]
    return {
        "impact_set_id": latest.impact_set_id,
        "created_ts_ms": latest.created_ts_ms,
        "target_root": latest.target_root,
        "risk_reason": latest.risk_reason,
        "recovery_ids": tuple(latest.recovery_ids),
        "target_name_hints": tuple(latest.target_name_hints),
    }


def _collect_impact_sets(*, proxy: TransparentAgentProxy, session_id: str) -> list[dict[str, object]]:
    if proxy.system.recovery_impact_set_catalog is None:
        return []
    impact_sets = [
        row for row in proxy.system.recovery_impact_set_catalog.read_all()
        if row.session_id == session_id
    ]
    impact_sets.sort(key=lambda row: row.created_ts_ms, reverse=True)
    return [
        {
            "impact_set_id": row.impact_set_id,
            "created_ts_ms": row.created_ts_ms,
            "target_root": row.target_root,
            "risk_reason": row.risk_reason,
            "recovery_ids": tuple(row.recovery_ids),
            "target_name_hints": tuple(row.target_name_hints),
        }
        for row in impact_sets
    ]


def _collect_latest_targets(*, proxy: TransparentAgentProxy) -> list[dict[str, object]]:
    if proxy.system.recovery_repository is None:
        return []
    grouped: dict[str, dict[str, object]] = {}
    for row in proxy.system.recovery_repository.catalog_store.read_all():
        key = str(row.target_path_hash)
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = {
                "created_ts_ms": row.created_ts_ms,
                "target_name_hint": row.target_name_hint,
                "source_kinds": {row.source_kind},
            }
            continue
        cast = grouped[key]["source_kinds"]
        assert isinstance(cast, set)
        cast.add(row.source_kind)
        if int(row.created_ts_ms) > int(existing["created_ts_ms"]):
            grouped[key]["created_ts_ms"] = row.created_ts_ms
            grouped[key]["target_name_hint"] = row.target_name_hint
    latest_targets = [
        {
            "created_ts_ms": row["created_ts_ms"],
            "target_name_hint": row["target_name_hint"],
            "source_kinds": tuple(sorted(row["source_kinds"])),
        }
        for row in grouped.values()
    ]
    latest_targets.sort(key=lambda row: int(row["created_ts_ms"]), reverse=True)
    return latest_targets


def _visible_latest_targets(*, latest_targets: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        row for row in latest_targets
        if _is_review_visible_target(str(row.get("target_name_hint") or ""))
    ]


def _resolve_restore_target_from_pick(
    *,
    visible_targets: list[dict[str, object]],
    target_pick: int,
    source_kind: str | None,
) -> tuple[str, str]:
    if target_pick < 1 or target_pick > len(visible_targets):
        raise IndexError(target_pick)
    picked = visible_targets[target_pick - 1]
    target_name = str(picked["target_name_hint"])
    resolved_source = source_kind
    if resolved_source is None:
        resolved_source = "git" if "git" in picked.get("source_kinds", ()) else str(picked.get("source_kinds", ("snapshot",))[0])
    return target_name, resolved_source


def _resolve_impact_set_from_pick(
    *,
    impact_sets: list[dict[str, object]],
    target_pick: int,
) -> dict[str, object]:
    if target_pick < 1 or target_pick > len(impact_sets):
        raise IndexError(target_pick)
    return impact_sets[target_pick - 1]


def _load_recovery_bundle(
    *,
    proxy: TransparentAgentProxy,
    target_name_hint: str,
    source_kind: str | None,
) -> RecoveryProtectionBundle:
    if proxy.system.recovery_repository is None or proxy.system.key_pair is None:
        raise RuntimeError("recovery mode is not enabled")
    records = proxy.system.recovery_repository.catalog_store.read_all()
    matches = [row for row in records if row.target_name_hint == target_name_hint]
    if source_kind is not None:
        matches = [row for row in matches if row.source_kind == source_kind]
    if not matches:
        raise RuntimeError(f"no recovery record found for target {target_name_hint}")
    matches.sort(key=lambda row: row.created_ts_ms, reverse=True)
    latest_hash = matches[0].target_path_hash
    grouped = [row for row in matches if row.target_path_hash == latest_hash]
    grouped.sort(key=lambda row: (row.source_kind != (source_kind or row.source_kind), -row.created_ts_ms))
    plans: list[RecoveryPlan] = []
    for record in grouped:
        plan = proxy.system.recovery_repository.plan_from_record(
            record=record,
            recipient_private_key_pem=proxy.system.key_pair.private_key_pem,
        )
        plans.append(plan)
    return RecoveryProtectionBundle(
        target_path=plans[0].target_path,
        command_preview=f"recover:{target_name_hint}",
        plans=tuple(plans),
    )


def _select_impact_set_protections(
    *,
    proxy: TransparentAgentProxy,
    session_id: str,
) -> tuple[object, tuple[RecoveryProtectionBundle, ...]]:
    return _select_impact_set_protections_by_id(proxy=proxy, session_id=session_id, impact_set_id=None)


def _select_impact_set_protections_by_id(
    *,
    proxy: TransparentAgentProxy,
    session_id: str,
    impact_set_id: str | None,
) -> tuple[object, tuple[RecoveryProtectionBundle, ...]]:
    if proxy.system.recovery_impact_set_catalog is None:
        raise RuntimeError("impact set recovery is not enabled")
    impact_sets = [
        row for row in proxy.system.recovery_impact_set_catalog.read_all()
        if row.session_id == session_id
    ]
    if not impact_sets:
        raise RuntimeError(f"no impact set found for session {session_id}")
    impact_sets.sort(key=lambda row: row.created_ts_ms, reverse=True)
    if impact_set_id is None:
        impact_set = impact_sets[0]
    else:
        matches = [row for row in impact_sets if row.impact_set_id == impact_set_id]
        if not matches:
            raise RuntimeError(f"no impact set found for id {impact_set_id}")
        impact_set = matches[0]
    if proxy.system.recovery_repository is None or proxy.system.key_pair is None:
        raise RuntimeError("recovery mode is not enabled")
    records_by_id = {
        row.recovery_id: row
        for row in proxy.system.recovery_repository.catalog_store.read_all()
    }
    grouped: dict[str, list[RecoveryPlan]] = {}
    for recovery_id in impact_set.recovery_ids:
        record = records_by_id.get(recovery_id)
        if record is None:
            continue
        plan = proxy.system.recovery_repository.plan_from_record(
            record=record,
            recipient_private_key_pem=proxy.system.key_pair.private_key_pem,
        )
        grouped.setdefault(record.target_path_hash, []).append(plan)
    protections: list[RecoveryProtectionBundle] = []
    for plans in grouped.values():
        plans.sort(key=lambda row: (row.source_kind != "git", row.target_path.name))
        protections.append(
            RecoveryProtectionBundle(
                target_path=plans[0].target_path,
                command_preview=f"impact-set:{impact_set.impact_set_id}",
                plans=tuple(plans),
            )
        )
    protections.sort(key=lambda bundle: (bundle.target_path.name != ".git", len(bundle.target_path.parts), str(bundle.target_path)))
    return impact_set, tuple(protections)


def _prepare_detected_sessions(
    *,
    sessions: list[dict[str, object]],
    account_id: str,
    password: str,
    root_dir: Path | None,
    no_start_service: bool,
    git_context_mode: str,
    session_id_override: str | None = None,
) -> list[dict[str, object]]:
    prepared: list[dict[str, object]] = []
    for item in sessions:
        path_hint = item.get("path_hint")
        if not path_hint and str(item.get("agent_id")) != "codex":
            prepared.append(
                {
                    "agent_id": item["agent_id"],
                    "ok": False,
                    "reason": "path_hint_unavailable",
                    "prepare_command": item.get("prepare_command"),
                }
            )
            continue
        forwarded = [
            "prepare",
            str(item["agent_id"]),
            account_id,
            password,
            "--git-context",
            git_context_mode,
        ]
        if path_hint:
            forwarded.extend(["--workspace", str(path_hint)])
        if session_id_override:
            forwarded.extend(["--session", session_id_override])
        session_slug = str(session_id_override or item.get("session_fingerprint") or "session").replace(":", "-").replace("/", "-").replace(" ", "-")
        if root_dir is not None:
            per_agent_root = root_dir / str(item["agent_id"]) / session_slug
            forwarded.extend(["--root-dir", str(per_agent_root)])
        elif session_id_override:
            default_root = Path.home() / ".clawchain-agent" / account_id / str(item["agent_id"]) / session_slug
            forwarded.extend(["--root-dir", str(default_root)])
        if no_start_service:
            forwarded.append("--no-start-service")
        process = subprocess.run(
            [sys.executable, "-m", "clawchain.agent_proxy_cli", *forwarded],
            text=True,
            capture_output=True,
            env={**os.environ, "PYTHONPATH": _package_root_str()},
            check=False,
        )
        prepared_payload = None
        if process.stdout.strip():
            try:
                prepared_payload = json.loads(process.stdout)
            except json.JSONDecodeError:
                prepared_payload = None
        prepared.append(
            {
                "agent_id": item["agent_id"],
                "session_id": session_id_override,
                "session_name": session_id_override,
                "session_fingerprint": item.get("session_fingerprint"),
                "path_hint": path_hint,
                "returncode": process.returncode,
                "prepared_payload": prepared_payload,
                "config_path": (prepared_payload or {}).get("artifacts", {}).get("config_path")
                or (prepared_payload or {}).get("config_path"),
                "launcher_path": (prepared_payload or {}).get("artifacts", {}).get("launcher_path"),
                "env_path": (prepared_payload or {}).get("artifacts", {}).get("env_path"),
                "next_steps": (prepared_payload or {}).get("next_steps"),
                "requires_relaunch": item.get("monitoring_status") != "managed",
                "capture_mode": "pending-relaunch" if item.get("monitoring_status") != "managed" else "launcher-routed",
                "stderr": process.stderr,
            }
        )
    return prepared


def _auto_select_git_context_mode(*, item: dict[str, object]) -> str:
    path_hint = item.get("path_hint")
    if not path_hint:
        return "managed-session-git"
    target = Path(str(path_hint)).expanduser()
    probe_target = target if target.is_dir() else target.parent
    probe = subprocess.run(
        ["git", "-C", str(probe_target), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    return "bind-existing-git" if probe.returncode == 0 else "managed-session-git"


def _relaunch_codex_session(*, item: dict[str, object], prepared_item: dict[str, object]) -> bool:
    launcher_path = prepared_item.get("launcher_path")
    if not launcher_path:
        return False
    command_text = str(item.get("command_text") or item.get("sample_process_summary") or "")
    try:
        tokens = shlex.split(command_text)
    except ValueError:
        tokens = command_text.split()
    if not tokens:
        return False
    while tokens and os.path.basename(tokens[0]) != "codex":
        tokens = tokens[1:]
    if not tokens:
        return False
    forwarded = tokens[1:]
    remaining_pids = [int(pid) for pid in item.get("pids", []) if pid is not None]
    for pid in remaining_pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.time() + 2.0
    while remaining_pids and time.time() < deadline:
        remaining_pids = [pid for pid in remaining_pids if is_pid_alive(pid)]
        if remaining_pids:
            time.sleep(0.05)
    for pid in list(remaining_pids):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    deadline = time.time() + 1.0
    while remaining_pids and time.time() < deadline:
        remaining_pids = [pid for pid in remaining_pids if is_pid_alive(pid)]
        if remaining_pids:
            time.sleep(0.05)

    tmux_bin = shutil.which("tmux")
    session_name = str(prepared_item.get("session_id") or item.get("session_fingerprint") or "codex-session")
    session_name = session_name.replace(":", "-").replace("/", "-").replace(" ", "-")[:48] or "codex-session"
    prepared_item["controlled_session_name"] = session_name
    if tmux_bin:
        launch_cmd = " ".join([shlex.quote("bash"), shlex.quote(str(launcher_path)), *[shlex.quote(part) for part in forwarded]])
        subprocess.run([tmux_bin, "kill-session", "-t", session_name], check=False, capture_output=True, text=True)
        created = subprocess.run(
            [tmux_bin, "new-session", "-d", "-s", session_name, launch_cmd],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": _package_root_str()},
        )
        if created.returncode == 0:
            check = subprocess.run([tmux_bin, "has-session", "-t", session_name], check=False, capture_output=True, text=True)
            if check.returncode == 0:
                prepared_item["attach_command"] = f"tmux attach -t {session_name}"
                prepared_item["capture_mode"] = "tmux-routed"
                return True

    process = subprocess.Popen(
        ["bash", str(launcher_path), *forwarded],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        env={**os.environ, "PYTHONPATH": _package_root_str()},
    )
    time.sleep(0.1)
    started = process.poll() is None
    if started:
        prepared_item["capture_mode"] = "launcher-routed"
    else:
        prepared_item["capture_mode"] = "pending-relaunch"
    return started


def _auto_prepare_candidates(*, sessions: list[dict[str, object]]) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for item in sessions:
        if item.get("monitoring_status") == "managed":
            continue
        if not item.get("path_hint") and str(item.get("agent_id")) != "codex":
            continue
        candidates.append(item)
    return candidates


def _supervise_status_lines(*, sessions: list[dict[str, object]]) -> list[str]:
    lines: list[str] = []
    for item in sessions:
        lines.append(
            f"[clawchain] session {item['agent_id']} "
            f"status={item['monitoring_status']} "
            f"path_hint={item.get('path_hint') or '-'} "
            f"processes={item.get('process_count')}"
        )
        if item["monitoring_status"] != "managed":
            lines.append(f"[clawchain] takeover hint: {item['prepare_command']}")
            lines.append(
                "[clawchain] onboard hint: "
                f"python -m clawchain.agent_proxy_cli onboard {item['agent_id']} <account> <password>"
            )
    return lines


def _supervise_detected_lines(*, item: dict[str, object]) -> list[str]:
    lines = [
        f"[clawchain] detected {item['agent_id']} "
        f"fingerprint={item.get('session_fingerprint') or '-'} "
        f"path_hint={item.get('path_hint') or '-'} "
        f"started_at={item.get('started_at') or '-'} "
        f"processes={item.get('process_count')}"
    ]
    if item["monitoring_status"] != "managed":
        lines.append(f"[clawchain] onboard hint: python -m clawchain.agent_proxy_cli onboard {item['agent_id']} <account> <password>")
    else:
        lines.append("[clawchain] session already routed through monitoring")
    return lines


def _coalesce_supervise_sessions(*, sessions: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = list(sessions)
    rows.sort(
        key=lambda row: (
            str(row["agent_id"]),
            str(row.get("started_at") or ""),
            str(row.get("path_hint") or ""),
            str(row.get("session_fingerprint") or ""),
        )
    )
    return rows


def _supervise_session_key(item: dict[str, object]) -> tuple[str, str]:
    identity = str(item.get("session_fingerprint") or item.get("path_hint") or "-")
    return (str(item["agent_id"]), identity)


def _supervise_session_state(item: dict[str, object]) -> tuple[str, int]:
    return (str(item["monitoring_status"]), int(item.get("process_count") or 0))


def _supervise_prepared_lines(*, prepared: list[dict[str, object]]) -> list[str]:
    lines: list[str] = []
    for item in prepared:
        agent_id = str(item.get("agent_id"))
        path_hint = str(item.get("path_hint") or "-")
        if item.get("prepared_payload") is None:
            lines.append(f"[clawchain] prepared {agent_id} path_hint={path_hint} failed")
            continue
        lines.append(f"[clawchain] prepared {agent_id} path_hint={path_hint}")
        if item.get("session_id"):
            lines.append(f"[clawchain] session name: {item['session_id']}")
        if item.get("capture_mode"):
            lines.append(f"[clawchain] capture mode: {item['capture_mode']}")
        if item.get("attach_command"):
            lines.append(f"[clawchain] attach: {item['attach_command']}")
        if item.get("config_path"):
            lines.append(f"[clawchain] config: {item['config_path']}")
        if item.get("launcher_path"):
            lines.append(f"[clawchain] launcher: {item['launcher_path']}")
        git_context_mode = (item.get("prepared_payload") or {}).get("git_context_mode")
        if git_context_mode:
            lines.append(f"[clawchain] git context: {git_context_mode}")
            lines.append("[clawchain] recovery source selection: automatic")
        next_steps = item.get("next_steps") or ()
        if next_steps:
            lines.append(f"[clawchain] next: {next_steps[0]}")
        if item.get("relaunch_started"):
            lines.append("[clawchain] relaunch started: automatic dangerous-command capture is now routed through the launcher")
        elif item.get("requires_relaunch"):
            lines.append("[clawchain] note: automatic dangerous-command capture starts after relaunching this session via the launcher above")
    return lines


def _use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _ansi(code: str, text: str) -> str:
    if not _use_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def _green(text: str) -> str:
    return _ansi("32", text)


def _yellow(text: str) -> str:
    return _ansi("33", text)


def _red(text: str) -> str:
    return _ansi("31", text)


def _dim(text: str) -> str:
    return _ansi("2", text)


def _bold(text: str) -> str:
    return _ansi("1", text)


def _status_label(status: str) -> str:
    if status.startswith("monitored"):
        return _green(status)
    if status == "unmanaged":
        return _yellow(status)
    if status in ("terminated", "failed"):
        return _dim(status)
    return status


def _panel_title(title: str) -> str:
    return f"[clawchain] {title}"


def _panel_line(text: str) -> str:
    return f"  {text}"


def _clear_and_render_dashboard(dashboard: str) -> None:
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")
    print(dashboard)


def _print_monitored_sessions(*, account_id: str) -> None:
    rows = _load_session_registry(account_id)
    print(_panel_title("==================== monitored sessions ===================="))
    if not rows:
        print(_panel_line("none"))
        return
    for index, row in enumerate(rows, start=1):
        print(
            _panel_line(
                f"[{index}] "
            f"{row.get('session_name') or row.get('session_id')} "
            f"agent={row.get('agent_id')} "
                f"path_hint={row.get('path_hint') or '-'}"
            )
        )


def _registry_lookup(
    *,
    registry_rows: list[dict[str, object]],
    item: dict[str, object],
) -> dict[str, object] | None:
    agent_id = str(item.get("agent_id") or "")
    fingerprint = str(item.get("session_fingerprint") or "")
    path_hint = str(item.get("path_hint") or "")
    current_pids = {int(pid) for pid in item.get("pids", []) if pid is not None}
    if item.get("pid") is not None:
        current_pids.add(int(item["pid"]))
    fingerprint_suffix = fingerprint.split(":", 1)[-1] if ":" in fingerprint else fingerprint
    if current_pids:
        for row in registry_rows:
            if str(row.get("agent_id") or "") != agent_id:
                continue
            tracked = {int(pid) for pid in row.get("tracked_pids", []) if pid is not None}
            if tracked & current_pids:
                return row
    inferred_control_name = fingerprint.replace(":", "-") if fingerprint else ""
    for row in registry_rows:
        if str(row.get("agent_id") or "") != agent_id:
            continue
        row_fingerprint = str(row.get("session_fingerprint") or "")
        if fingerprint and row_fingerprint == fingerprint:
            return row
        row_session_id = str(row.get("session_id") or "")
        if fingerprint_suffix and row_session_id and row_session_id == fingerprint_suffix:
            return row
        row_controlled = str(row.get("controlled_session_name") or "")
        if inferred_control_name and row_controlled == inferred_control_name:
            return row
    for row in registry_rows:
        if str(row.get("agent_id") or "") != agent_id:
            continue
        row_path_hint = str(row.get("path_hint") or "")
        if not path_hint or row_path_hint != path_hint:
            continue
        row_session_id = str(row.get("session_id") or "")
        if fingerprint.startswith("path:") or not row_session_id:
            return row
    return None


def _print_running_sessions_snapshot(
    *,
    sessions: list[dict[str, object]],
    registry_rows: list[dict[str, object]],
) -> None:
    print(_panel_title("===================== running sessions ====================="))
    if not sessions:
        print(_panel_line("none"))
        return
    for index, item in enumerate(sessions, start=1):
        matched = _registry_lookup(registry_rows=registry_rows, item=item)
        status = f"monitored:{matched.get('session_name') or matched.get('session_id')}" if matched else "unmanaged"
        print(
            _panel_line(
                f"[{index}] {item['agent_id']} "
            f"status={status} "
            f"fingerprint={item.get('session_fingerprint') or '-'} "
            f"path_hint={item.get('path_hint') or '-'} "
                f"started_at={item.get('started_at') or '-'}"
            )
        )


def _print_unmanaged_candidates(*, candidates: list[dict[str, object]]) -> None:
    if not candidates:
        return
    print(_panel_title("==================== unmanaged sessions ===================="))
    for index, item in enumerate(candidates, start=1):
        print(
            _panel_line(
                f"[{index}] {item['agent_id']} "
            f"fingerprint={item.get('session_fingerprint') or '-'} "
            f"path_hint={item.get('path_hint') or '-'} "
                f"started_at={item.get('started_at') or '-'}"
            )
        )


def _print_new_session_banner(*, item: dict[str, object]) -> None:
    print(_panel_title("==================== new session detected ===================="))
    print(
        _panel_line(
            f"agent={item['agent_id']} "
            f"fingerprint={item.get('session_fingerprint') or '-'} "
            f"path_hint={item.get('path_hint') or '-'} "
            f"started_at={item.get('started_at') or '-'}"
        )
    )


def _render_supervise_dashboard(
    *,
    account_id: str,
    sessions: list[dict[str, object]],
    registry_rows: list[dict[str, object]],
) -> str:
    lines = [_panel_title("==================== monitored sessions ====================")]
    if not registry_rows:
        lines.append(_panel_line("none"))
    else:
        for index, row in enumerate(registry_rows, start=1):
            lines.append(
                _panel_line(
                    f"[{index}] {row.get('session_name') or row.get('session_id')} "
                    f"agent={row.get('agent_id')} path_hint={row.get('path_hint') or '-'}"
                )
            )
    lines.append(_panel_title("===================== running sessions ====================="))
    if not sessions:
        lines.append(_panel_line("none"))
    else:
        for index, item in enumerate(sessions, start=1):
            matched = _registry_lookup(registry_rows=registry_rows, item=item)
            status = f"monitored:{matched.get('session_name') or matched.get('session_id')}" if matched else "unmanaged"
            lines.append(
                _panel_line(
                    f"[{index}] {item['agent_id']} status={status} "
                    f"fingerprint={item.get('session_fingerprint') or '-'} "
                    f"path_hint={item.get('path_hint') or '-'} "
                    f"started_at={item.get('started_at') or '-'}"
                )
            )
        unmanaged = [
            item for item in sessions
            if _registry_lookup(registry_rows=registry_rows, item=item) is None
        ]
        if unmanaged:
            lines.append(_panel_title("==================== unmanaged sessions ===================="))
            for index, item in enumerate(unmanaged, start=1):
                lines.append(
                    _panel_line(
                        f"[{index}] {item['agent_id']} "
                        f"fingerprint={item.get('session_fingerprint') or '-'} "
                        f"path_hint={item.get('path_hint') or '-'} "
                        f"started_at={item.get('started_at') or '-'}"
                    )
                )
    return "\n".join(lines)


def _stdin_ready(timeout_sec: float) -> bool:
    try:
        ready, _, _ = select.select([sys.stdin], [], [], timeout_sec)
    except (OSError, ValueError):
        return False
    return bool(ready)


def _prompt_onboard_candidate(
    *,
    item: dict[str, object],
    account_id: str,
    password: str,
    root_dir: Path | None,
    no_start_service: bool,
) -> list[dict[str, object]]:
    print(
        f"[clawchain] detected session {item.get('session_fingerprint') or '-'} "
        f"agent={item['agent_id']} path_hint={item.get('path_hint') or '-'}"
    )
    session_name = input("[clawchain] 请输入会话名称：").strip()
    if not session_name:
        session_name = f"{item['agent_id']}-{str(item.get('session_fingerprint') or 'session').replace(':', '-')}"
    git_context_mode = _auto_select_git_context_mode(item=item)
    prepared = _prepare_detected_sessions(
        sessions=[item],
        account_id=account_id,
        password=password,
        root_dir=root_dir,
        no_start_service=no_start_service,
        git_context_mode=git_context_mode,
        session_id_override=session_name.strip().lower().replace(" ", "-"),
    )
    for result in prepared:
        result["session_name"] = session_name
        if str(item.get("agent_id")) == "codex" and result.get("prepared_payload") is not None:
            result["relaunch_started"] = _relaunch_codex_session(item=item, prepared_item=result)
            result["capture_mode"] = result.get("capture_mode") or ("launcher-routed" if result["relaunch_started"] else "pending-relaunch")
    _persist_prepared_sessions(
        account_id=account_id,
        prepared=prepared,
        root_dir=root_dir,
        fallback_items={
            str(result.get("session_id") or ""): {
                "agent_id": item.get("agent_id"),
                "session_name": session_name,
                "session_fingerprint": item.get("session_fingerprint"),
                "path_hint": item.get("path_hint"),
            }
            for result in prepared
        },
    )
    return prepared


def _collect_live_risky_event_lines(
    *,
    registry_rows: list[dict[str, object]],
    seen_event_ids: set[str],
) -> list[str]:
    lines: list[str] = []
    for row in registry_rows:
        config_path = row.get("config_path")
        session_id = str(row.get("session_id") or "")
        if not config_path or not session_id:
            continue
        config_file = Path(str(config_path))
        if not config_file.exists():
            continue
        try:
            stored = load_agent_proxy_config(config_file)
        except Exception:  # noqa: BLE001
            continue
        if not stored.base_dir:
            continue
        event_store_path = Path(stored.base_dir).expanduser() / "runtime" / "local" / "events.jsonl"
        events = _load_session_events(
            event_store_path=event_store_path,
            session_id=session_id,
        )
        last_invoke = None
        for event in events:
            event_type = str(event.get("event_type") or "")
            event_id = f"{event.get('session_id')}:{event.get('event_index')}"
            if event_type == "ToolInvocationRequested":
                last_invoke = event
            if event_type != "RecoveryPlanned" or event_id in seen_event_ids:
                continue
            seen_event_ids.add(event_id)
            command_text = _command_summary_from_invoke(last_invoke or event)
            lines.append(
                f"[{_format_ts_label(event.get('timestamp_ms'))}] "
                f"[session {session_id}] "
                f"[{row.get('session_name') or session_id}] "
                f"[{command_text}]"
            )
    return lines


def _print_live_risky_events(*, registry_rows: list[dict[str, object]], seen_event_ids: set[str]) -> None:
    for line in _collect_live_risky_event_lines(registry_rows=registry_rows, seen_event_ids=seen_event_ids):
        print(line)


def _run_onboard_interaction(
    *,
    agent_filter: str,
    account_id: str,
    password: str,
    root_dir: Path | None,
    no_start_service: bool,
) -> int:
    sessions = aggregate_running_agents(detect_running_agents(agent_filter=agent_filter))
    candidates = _auto_prepare_candidates(sessions=sessions)
    if not candidates:
        print("[clawchain] no unmanaged agent sessions are available for onboarding")
        return 0
    print(f"[clawchain] detected unmanaged sessions for {agent_filter}:")
    for index, item in enumerate(candidates, start=1):
        print(
            f"[clawchain] [{index}] {item['agent_id']} "
            f"fingerprint={item.get('session_fingerprint') or '-'} "
            f"path_hint={item.get('path_hint') or '-'} "
            f"started_at={item.get('started_at') or '-'} "
            f"processes={item.get('process_count')}"
        )
        print(f"[clawchain]     sample={item.get('sample_process_summary') or '-'}")
    choice = input("[clawchain] 是否将其中一个会话纳入监控？[1] 是 [2] 否: ").strip()
    if choice != "1":
        print("[clawchain] onboarding cancelled")
        return 0
    target_pick = input("[clawchain] 请选择想要纳入监控的会话编号：").strip()
    try:
        picked = candidates[int(target_pick) - 1]
    except (ValueError, IndexError):
        print("[clawchain] invalid onboarding selection")
        return 2
    session_name = input("[clawchain] 请输入会话名称（留空则自动生成）：").strip()
    git_context_mode = _auto_select_git_context_mode(item=picked)
    session_id = (
        session_name.strip().lower().replace(" ", "-")
        if session_name.strip()
        else f"{picked['agent_id']}-{str(picked.get('session_fingerprint') or 'session').replace(':', '-')}"
    )
    prepared = _prepare_detected_sessions(
        sessions=[picked],
        account_id=account_id,
        password=password,
        root_dir=root_dir,
        no_start_service=no_start_service,
        git_context_mode=git_context_mode,
        session_id_override=session_id,
    )
    for result in prepared:
        result["session_name"] = session_name or session_id
        if str(picked.get("agent_id")) == "codex" and result.get("prepared_payload") is not None:
            result["relaunch_started"] = _relaunch_codex_session(item=picked, prepared_item=result)
            result["capture_mode"] = result.get("capture_mode") or ("launcher-routed" if result["relaunch_started"] else "pending-relaunch")
    _persist_prepared_sessions(
        account_id=account_id,
        prepared=prepared,
        root_dir=root_dir,
        fallback_items={
            str(result.get("session_id") or session_id): {
                "agent_id": picked.get("agent_id"),
                "session_name": session_name or session_id,
                "session_fingerprint": picked.get("session_fingerprint"),
                "path_hint": picked.get("path_hint"),
            }
            for result in prepared
        },
    )
    for line in _supervise_prepared_lines(prepared=prepared):
        print(line)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if args[:1] == ["ui"]:
        from .ui_server import main as ui_main

        return ui_main(args[1:])
    if args[:1] == ["deploy"]:
        if len(args) < 3:
            print("usage: python -m clawchain.agent_proxy_cli deploy <account-id> <password> [--root-dir PATH] [--workspace PATH] [--session ID] [--run ID] [--git-context bind-existing-git|managed-session-git] [--no-start-service] [--no-auto-evm]")
            return 2
        account_id = str(args[1])
        password = str(args[2])
        root_dir = None
        workspace_root = None
        session_id = "default-session"
        run_id = "default-run"
        git_context_mode = "bind-existing-git"
        auto_evm = True
        start_service = True
        index = 3
        while index < len(args):
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--workspace" and index + 1 < len(args):
                workspace_root = Path(args[index + 1]); index += 2; continue
            if args[index] == "--session" and index + 1 < len(args):
                session_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--run" and index + 1 < len(args):
                run_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--git-context" and index + 1 < len(args):
                git_context_mode = str(args[index + 1]); index += 2; continue
            if args[index] == "--no-auto-evm":
                auto_evm = False; index += 1; continue
            if args[index] == "--no-start-service":
                start_service = False; index += 1; continue
            print(f"unknown option: {args[index]}")
            return 2
        account_root = _default_account_root(account_id, root_dir=root_dir)
        config_path = _default_account_config_path(account_id, root_dir=root_dir)
        proof_repo = _ensure_local_proof_repo(account_id, root_dir=root_dir)
        stored = AgentProxyStoredConfig(
            account_id=account_id,
            password=password,
            base_dir=str(account_root),
            path_hint=str(workspace_root) if workspace_root is not None else None,
            default_session_id=session_id,
            default_run_id=run_id,
            auto_bootstrap_evm=auto_evm,
            git_context_mode=git_context_mode,
        )
        write_agent_proxy_config(config_path, stored)
        service_payload = None
        if start_service:
            process = subprocess.run(
                [sys.executable, "-m", "clawchain.agent_proxy_cli", "service-start", str(config_path)],
                text=True,
                capture_output=True,
                check=False,
                env={**os.environ, "PYTHONPATH": _package_root_str()},
            )
            try:
                service_payload = json.loads(process.stdout) if process.stdout else {"ok": False, "reason": "empty-service-output"}
            except Exception:  # noqa: BLE001
                service_payload = {
                    "ok": False,
                    "reason": "invalid-service-output",
                    "returncode": process.returncode,
                    "stdout": process.stdout,
                    "stderr": process.stderr,
                }
        print(json.dumps({
            "ok": True,
            "account_id": account_id,
            "account_root": str(account_root),
            "config_path": str(config_path),
            "session_scope": "agent-session",
            "git_context_mode": git_context_mode,
            "git_context_label": (
                "bind existing project repository"
                if git_context_mode == "bind-existing-git"
                else "managed session repository"
            ),
            "recovery_source_selection": "automatic",
            "service": service_payload,
            "proof_repo": proof_repo,
            "next_steps": [
                f"python -m clawchain.agent_proxy_cli supervise {account_id} <password> --no-start-service",
                f"python -m clawchain.agent_proxy_cli status {account_id}",
                f"python -m clawchain.agent_proxy_cli proof --account {account_id} --limit 1 --save-manifest /tmp/clawchain-proof-manifest.json",
            ],
        }, ensure_ascii=True, indent=2))
        return 0
    if args[:1] == ["status"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli status <account-id> [agent-id|all] [--root-dir PATH]")
            return 2
        account_id = str(args[1])
        agent_filter = "all"
        root_dir = None
        index = 2
        known_agent_ids = {row.agent_id for row in list_known_agents()}
        if index < len(args) and str(args[index]) in known_agent_ids | {"all"}:
            agent_filter = str(args[index]); index += 1
        while index < len(args):
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        config_path = _default_account_config_path(account_id, root_dir=root_dir)
        registry_rows = _load_session_registry(account_id, root_dir=root_dir)
        sessions = _coalesce_supervise_sessions(
            sessions=aggregate_running_agents(detect_running_agents(agent_filter=agent_filter))
        )
        service_payload = None
        if config_path.exists():
            service_args = ["service-status", str(config_path)]
            stdout_buffer = []
            original_stdout = sys.stdout
            try:
                from io import StringIO
                capture = StringIO()
                sys.stdout = capture
                rc = main(service_args)
                stdout_buffer = capture.getvalue().strip()
            finally:
                sys.stdout = original_stdout
            if stdout_buffer:
                try:
                    service_payload = json.loads(stdout_buffer)
                except Exception:  # noqa: BLE001
                    service_payload = {"ok": False, "reason": "invalid-service-status-output", "raw": stdout_buffer, "returncode": rc}
        for line in _status_lines(
            account_id=account_id,
            registry_rows=registry_rows,
            sessions=sessions,
            config_path=config_path,
            service_payload=service_payload,
        ):
            print(line)
        return 0
    if args[:1] == ["prepare"]:
        if len(args) < 4:
            print("usage: python -m clawchain.agent_proxy_cli prepare <agent-id> <account-id> <password> [--workspace PATH] [--git-context bind-existing-git|managed-session-git] [--root-dir PATH] [--session ID] [--run ID] [--no-start-service]")
            return 2
        profile_id = _normalize_profile_id(str(args[1]))
        account_id = str(args[2])
        password = str(args[3])
        workspace_root = None
        root_dir = None
        session_id = None
        run_id = None
        start_service = True
        git_context_mode = "bind-existing-git"
        index = 4
        while index < len(args):
            if args[index] == "--workspace" and index + 1 < len(args):
                workspace_root = Path(args[index + 1]); index += 2; continue
            if args[index] == "--git-context" and index + 1 < len(args):
                git_context_mode = str(args[index + 1]); index += 2; continue
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--session" and index + 1 < len(args):
                session_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--run" and index + 1 < len(args):
                run_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--no-start-service":
                start_service = False; index += 1; continue
            print(f"unknown option: {args[index]}")
            return 2
        if workspace_root is not None:
            workspace_root = workspace_root.expanduser().resolve()
        base_dir = (root_dir or (Path.home() / ".clawchain-agent" / account_id / profile_id)).expanduser().resolve()
        if profile_id == "codex-cli":
            artifacts = bootstrap_codex_cli_integration(
                account_id=account_id,
                password=password,
                workspace_root=workspace_root,
                base_dir=base_dir,
                session_id=session_id or "codex-session",
                run_id=run_id or "codex-run",
                start_service=start_service,
                git_context_mode=git_context_mode,
            )
            print(json.dumps({
                "ok": True,
                "profile_id": profile_id,
                "session_scope": "agent-session",
                "prepared": "full-integration",
                "git_context_mode": git_context_mode,
                "git_context_label": (
                    "bind existing project repository"
                    if git_context_mode == "bind-existing-git"
                    else "managed session repository"
                ),
                "recovery_source_selection": "automatic",
                "artifacts": artifacts.to_dict(),
                "next_steps": (
                    [f"bash {artifacts.launcher_path} -C {workspace_root}"]
                    if workspace_root is not None
                    else [f"bash {artifacts.launcher_path}"]
                ) + [
                    f"env CLAWCHAIN_AGENT_PROXY_CONFIG={artifacts.config_path} PYTHONPATH={_package_root_str()} python -m clawchain.agent_proxy_cli watch codex",
                ],
            }, ensure_ascii=True, indent=2))
            return 0
        if workspace_root is None:
            print("prepare requires --workspace PATH for this agent")
            return 2
        plan = build_real_agent_harness_plan(
            profile_id,
            account_id=account_id,
            password=password,
            workspace_root=workspace_root,
            base_dir=base_dir,
            session_id=session_id,
            run_id=run_id,
        )
        stored = AgentProxyStoredConfig(
            account_id=account_id,
            password=password,
            base_dir=plan.base_dir,
            path_hint=plan.workspace_root,
            default_session_id=session_id or f"{profile_id}-session",
            default_run_id=run_id or f"{profile_id}-run",
            git_context_mode=git_context_mode,
        )
        config_path = write_agent_proxy_config(Path(plan.config_path), stored)
        service = None
        if start_service:
            process = subprocess.run(
                [sys.executable, "-m", "clawchain.agent_proxy_cli", "service-start", str(config_path)],
                text=True,
                capture_output=True,
                check=False,
                env={**os.environ, "PYTHONPATH": _package_root_str()},
            )
            service = {
                "returncode": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr,
            }
        print(json.dumps({
            "ok": True,
            "profile_id": profile_id,
            "session_scope": "agent-session",
            "prepared": "config-and-service",
            "config_path": str(config_path),
            "path_hint": plan.workspace_root,
            "base_dir": plan.base_dir,
            "git_context_mode": git_context_mode,
            "git_context_label": (
                "bind existing project repository"
                if git_context_mode == "bind-existing-git"
                else "managed session repository"
            ),
            "recovery_source_selection": "automatic",
            "command_templates": [item.to_dict() for item in plan.command_templates],
            "next_steps": [
                f"env CLAWCHAIN_AGENT_PROXY_CONFIG={config_path} PYTHONPATH={_package_root_str()} python -m clawchain.agent_proxy_cli watch {profile_id}",
            ],
            "service": service,
        }, ensure_ascii=True, indent=2))
        return 0
    if args[:1] == ["takeover"]:
        if len(args) < 3:
            print("usage: python -m clawchain.agent_proxy_cli takeover [agent-id|all] <account-id> <password> [--git-context bind-existing-git|managed-session-git] [--root-dir PATH] [--no-start-service]")
            return 2
        known_agent_ids = {row.agent_id for row in list_known_agents()}
        if str(args[1]) in known_agent_ids | {"all"}:
            agent_filter = str(args[1])
            account_id = str(args[2])
            password = str(args[3])
            index = 4
        else:
            agent_filter = "all"
            account_id = str(args[1])
            password = str(args[2])
            index = 3
        root_dir = None
        no_start_service = False
        git_context_mode = "bind-existing-git"
        while index < len(args):
            if args[index] == "--git-context" and index + 1 < len(args):
                git_context_mode = str(args[index + 1]); index += 2; continue
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--no-start-service":
                no_start_service = True; index += 1; continue
            print(f"unknown option: {args[index]}")
            return 2
        matches = detect_running_agents(agent_filter=agent_filter)
        sessions = aggregate_running_agents(matches)
        candidates = _auto_prepare_candidates(sessions=sessions)
        prepared = _prepare_detected_sessions(
            sessions=candidates,
            account_id=account_id,
            password=password,
            root_dir=root_dir,
            no_start_service=no_start_service,
            git_context_mode=git_context_mode,
        )
        print(json.dumps({
            "ok": True,
            "agent_filter": agent_filter,
            "matches": matches,
            "sessions": sessions,
            "takeover_candidates": candidates,
            "prepared": prepared,
        }, ensure_ascii=True, indent=2))
        return 0
    if args[:1] == ["supervise"]:
        if len(args) < 3:
            print("usage: python -m clawchain.agent_proxy_cli supervise [agent-id|all] <account-id> <password> [--git-context bind-existing-git|managed-session-git] [--interval SEC] [--root-dir PATH] [--no-start-service] [--auto-prepare] [--once] [--show-existing]")
            return 2
        known_agent_ids = {row.agent_id for row in list_known_agents()}
        if str(args[1]) in known_agent_ids | {"all"}:
            agent_filter = str(args[1])
            account_id = str(args[2])
            password = str(args[3])
            index = 4
        else:
            agent_filter = "all"
            account_id = str(args[1])
            password = str(args[2])
            index = 3
        interval_sec = 2.0
        root_dir = None
        no_start_service = False
        auto_prepare = False
        once = False
        show_existing = False
        git_context_mode = "bind-existing-git"
        while index < len(args):
            if args[index] == "--git-context" and index + 1 < len(args):
                git_context_mode = str(args[index + 1]); index += 2; continue
            if args[index] == "--interval" and index + 1 < len(args):
                interval_sec = float(args[index + 1]); index += 2; continue
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--no-start-service":
                no_start_service = True; index += 1; continue
            if args[index] == "--auto-prepare":
                auto_prepare = True; index += 1; continue
            if args[index] == "--once":
                once = True; index += 1; continue
            if args[index] == "--show-existing":
                show_existing = True; index += 1; continue
            print(f"unknown option: {args[index]}")
            return 2
        seen_states: dict[tuple[str, str], tuple[str, int]] = {}
        seen_items: dict[tuple[str, str], dict[str, object]] = {}
        seen_monitored_keys: set[tuple[str, str]] = set()
        seen_event_ids: set[str] = set()
        ignored_keys: set[tuple[str, str]] = set()
        interactive_tty = sys.stdin.isatty() and sys.stdout.isatty()
        last_dashboard = ""
        print(f"[clawchain] supervising agents: {agent_filter}")
        first_pass = True
        while True:
            sessions = _coalesce_supervise_sessions(
                sessions=aggregate_running_agents(detect_running_agents(agent_filter=agent_filter))
            )
            registry_rows = _load_session_registry_compat(account_id, root_dir=root_dir)
            _update_tracked_pids(
                account_id=account_id,
                sessions=sessions,
                registry_rows=registry_rows,
                root_dir=root_dir,
            )
            stale = _detect_stale_sessions(account_id=account_id, root_dir=root_dir)
            if stale:
                registry_rows = _load_session_registry_compat(account_id, root_dir=root_dir)
                for entry in stale:
                    print(f"[clawchain] session {entry.get('session_name') or entry.get('session_id')} terminated (all tracked PIDs exited)")
            dashboard = _render_supervise_dashboard(
                account_id=account_id,
                sessions=sessions,
                registry_rows=registry_rows,
            )
            if dashboard != last_dashboard:
                _clear_and_render_dashboard(dashboard)
                last_dashboard = dashboard
            if show_existing and first_pass:
                for item in sessions:
                    for line in _supervise_detected_lines(item=item):
                        print(line)
            current_states: dict[tuple[str, str], tuple[str, int]] = {}
            current_items: dict[tuple[str, str], dict[str, object]] = {}
            current_monitored_keys: set[tuple[str, str]] = set()
            newly_detected_unmanaged: list[dict[str, object]] = []
            for item in sessions:
                key = _supervise_session_key(item)
                state = _supervise_session_state(item)
                current_states[key] = state
                current_items[key] = item
                matched_registry = _registry_lookup(registry_rows=registry_rows, item=item)
                if matched_registry is not None:
                    current_monitored_keys.add(key)
                    if key not in seen_monitored_keys and not first_pass:
                        print(
                            f"[clawchain] session entered monitoring "
                            f"name={matched_registry.get('session_name') or matched_registry.get('session_id')} "
                            f"agent={item.get('agent_id')} "
                            f"fingerprint={item.get('session_fingerprint') or '-'}"
                        )
                if key not in seen_states and matched_registry is None and key not in ignored_keys:
                    newly_detected_unmanaged.append(item)
                if matched_registry is None and auto_prepare and item.get("path_hint"):
                    prepared = _prepare_detected_sessions(
                        sessions=[item],
                        account_id=account_id,
                        password=password,
                        root_dir=root_dir,
                        no_start_service=no_start_service,
                        git_context_mode=git_context_mode,
                    )
                    if prepared:
                        _persist_prepared_sessions(
                            account_id=account_id,
                            prepared=prepared,
                            root_dir=root_dir,
                            fallback_items={
                                str(result.get("session_id") or ""): {
                                    "agent_id": item.get("agent_id"),
                                    "session_fingerprint": item.get("session_fingerprint"),
                                    "path_hint": item.get("path_hint"),
                                }
                                for result in prepared
                            },
                        )
                        for line in _supervise_prepared_lines(prepared=prepared):
                            print(line)
            vanished = sorted(set(seen_states) - set(current_states))
            if show_existing:
                for key in vanished:
                    prior = seen_items.get(key, {})
                    agent_id = str(prior.get("agent_id") or key[0])
                    path_hint = str(prior.get("path_hint") or key[1])
                    print(f"[clawchain] session {agent_id} left supervision path_hint={path_hint}")
            _print_live_risky_events(registry_rows=registry_rows, seen_event_ids=seen_event_ids)
            unmanaged = [
                item for item in sessions
                if _registry_lookup(registry_rows=registry_rows, item=item) is None
            ]
            if interactive_tty and unmanaged:
                if newly_detected_unmanaged:
                    for item in newly_detected_unmanaged:
                        _print_new_session_banner(item=item)
                prompt_text = "[clawchain] 是否将其中一个当前运行的会话纳入监控？[1] 是 [2] 否: "
                print(prompt_text, end="", flush=True)
                if _stdin_ready(interval_sec):
                    choice = sys.stdin.readline().strip()
                    if choice == "1":
                        print("[clawchain] 请选择想要纳入监控的会话编号：", end="", flush=True)
                        picked_text = sys.stdin.readline().strip()
                        try:
                            picked = unmanaged[int(picked_text) - 1]
                        except (ValueError, IndexError):
                            print("[clawchain] invalid onboarding selection")
                            seen_states = current_states
                            seen_items = current_items
                            first_pass = False
                            continue
                        prepared = _prompt_onboard_candidate(
                            item=picked,
                            account_id=account_id,
                            password=password,
                            root_dir=root_dir,
                            no_start_service=no_start_service,
                        )
                        for line in _supervise_prepared_lines(prepared=prepared):
                            print(line)
                        time.sleep(1.0)
                        seen_states = {}
                        seen_items = {}
                        last_dashboard = ""
                        first_pass = False
                        continue
                    print()
            seen_states = current_states
            seen_items = current_items
            seen_monitored_keys = current_monitored_keys
            first_pass = False
            if once:
                return 0
            if not interactive_tty or not unmanaged:
                time.sleep(interval_sec)
    if args[:1] == ["onboard"]:
        if len(args) < 3:
            print("usage: python -m clawchain.agent_proxy_cli onboard [agent-id|all] <account-id> <password> [--root-dir PATH] [--no-start-service]")
            return 2
        known_agent_ids = {row.agent_id for row in list_known_agents()}
        if str(args[1]) in known_agent_ids | {"all"}:
            agent_filter = str(args[1])
            account_id = str(args[2])
            password = str(args[3])
            index = 4
        else:
            agent_filter = "all"
            account_id = str(args[1])
            password = str(args[2])
            index = 3
        root_dir = None
        no_start_service = False
        while index < len(args):
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--no-start-service":
                no_start_service = True; index += 1; continue
            print(f"unknown option: {args[index]}")
            return 2
        return _run_onboard_interaction(
            agent_filter=agent_filter,
            account_id=account_id,
            password=password,
            root_dir=root_dir,
            no_start_service=no_start_service,
        )
    if args[:1] == ["watch"]:
        if len(args) < 1:
            print("usage: python -m clawchain.agent_proxy_cli watch [agent-id|all] [--interval SEC] [--once] [--recommend] [--prepare <account-id> <password>] [--git-context bind-existing-git|managed-session-git] [--root-dir PATH] [--no-start-service]")
            return 2
        known_agent_ids = {row.agent_id for row in list_known_agents()}
        if len(args) >= 2 and str(args[1]) in known_agent_ids | {"all"}:
            agent_filter = str(args[1])
            index = 2
        else:
            agent_filter = "all"
            index = 1
        interval_sec = 2.0
        once = False
        recommend = False
        prepare_credentials = None
        root_dir = None
        no_start_service = False
        git_context_mode = "bind-existing-git"
        while index < len(args):
            if args[index] == "--interval" and index + 1 < len(args):
                interval_sec = float(args[index + 1]); index += 2; continue
            if args[index] == "--once":
                once = True; index += 1; continue
            if args[index] == "--recommend":
                recommend = True; index += 1; continue
            if args[index] == "--prepare" and index + 2 < len(args):
                prepare_credentials = (str(args[index + 1]), str(args[index + 2])); index += 3; continue
            if args[index] == "--git-context" and index + 1 < len(args):
                git_context_mode = str(args[index + 1]); index += 2; continue
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--no-start-service":
                no_start_service = True; index += 1; continue
            print(f"unknown option: {args[index]}")
            return 2
        if not once and not recommend and prepare_credentials is None:
            return main(["monitor", agent_filter, "--interval", str(interval_sec)])
        matches = detect_running_agents(agent_filter=agent_filter)
        sessions = aggregate_running_agents(matches)
        payload: dict[str, object] = {
            "ok": True,
            "monitoring_status": _summarize_monitoring_status(sessions),
            "matches": matches,
            "sessions": sessions,
        }
        if recommend:
            payload["recommendations"] = [
                {
                    "agent_id": item["agent_id"],
                    "path_hint": item.get("path_hint"),
                    "prepare_command": item.get("prepare_command"),
                    "process_count": item.get("process_count"),
                }
                for item in sessions
                if item.get("monitoring_status") != "managed"
            ]
        if prepare_credentials is not None:
            account_id, password = prepare_credentials
            payload["prepared"] = _prepare_detected_sessions(
                sessions=_auto_prepare_candidates(sessions=sessions),
                account_id=account_id,
                password=password,
                root_dir=root_dir,
                no_start_service=no_start_service,
                git_context_mode=git_context_mode,
            )
        print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 0
    if args[:1] == ["sessions"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli sessions <account-id> [agent-id|all]")
            return 2
        account_id = str(args[1])
        agent_filter = str(args[2]) if len(args) >= 3 else "all"
        registry_rows = _load_session_registry(account_id)
        sessions = _coalesce_supervise_sessions(
            sessions=aggregate_running_agents(detect_running_agents(agent_filter=agent_filter))
        )
        _print_monitored_sessions(account_id=account_id)
        _print_running_sessions_snapshot(sessions=sessions, registry_rows=registry_rows)
        unmanaged = [
            item for item in sessions
            if _registry_lookup(registry_rows=registry_rows, item=item) is None
        ]
        if unmanaged:
            _print_unmanaged_candidates(candidates=unmanaged)
        return 0
    if args[:1] == ["review"] or args[:1] == ["history"]:
        config_path = None
        session_id = None
        interactive = None
        full = False
        since_raw = None
        risk_filter = None
        limit = None
        index = 1
        while index < len(args):
            if args[index] == "--config" and index + 1 < len(args):
                config_path = args[index + 1]; index += 2; continue
            if args[index] == "--session" and index + 1 < len(args):
                session_id = args[index + 1]; index += 2; continue
            if args[index] == "--interactive":
                interactive = True; index += 1; continue
            if args[index] == "--non-interactive":
                interactive = False; index += 1; continue
            if args[index] == "--full":
                full = True; index += 1; continue
            if args[index] == "--since" and index + 1 < len(args):
                since_raw = args[index + 1]; index += 2; continue
            if args[index] == "--risk" and index + 1 < len(args):
                risk_filter = args[index + 1]; index += 2; continue
            if args[index] == "--limit" and index + 1 < len(args):
                limit = int(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        since_ms = None
        if since_raw is not None:
            try:
                since_ms = _parse_since_to_ms(str(since_raw))
            except (TypeError, ValueError) as exc:
                print(f"invalid --since value: {since_raw} ({exc})")
                return 2
        if config_path is None and session_id is None:
            account_id = os.environ.get("CLAWCHAIN_AGENT_ACCOUNT_ID")
            if not account_id:
                env_path = os.environ.get("CLAWCHAIN_AGENT_PROXY_CONFIG")
                if env_path:
                    try:
                        account_id = load_agent_proxy_config(Path(env_path)).account_id
                    except Exception:  # noqa: BLE001
                        account_id = None
            if not account_id:
                print("review without --session requires CLAWCHAIN_AGENT_ACCOUNT_ID or CLAWCHAIN_AGENT_PROXY_CONFIG")
                return 2
            entries = _filter_registry_entries(
                entries=_collect_registry_review_entries(account_id=account_id),
                risk_filter=risk_filter,
                since_ms=since_ms,
                limit=limit,
            )
            for line in _review_registry_lines(entries=entries):
                print(line)
            for line in _history_pending_capture_lines(account_id=account_id):
                print(line)
            if interactive is None:
                interactive = bool(sys.stdin.isatty() and sys.stdout.isatty())
            if interactive:
                return _run_registry_review_interaction(entries=entries)
            return 0
        try:
            resolved = _resolve_config_path(config_path)
        except RuntimeError as exc:
            print(str(exc))
            return 2
        stored = load_agent_proxy_config(resolved)
        resolved_session = _session_id_from_args_or_config(session_id, stored=stored)
        proxy = TransparentAgentProxy.create(stored.to_proxy_config())
        try:
            impact_sets = _filter_impact_sets(
                impact_sets=_collect_impact_sets(proxy=proxy, session_id=resolved_session),
                risk_filter=risk_filter,
                since_ms=since_ms,
                limit=limit,
            )
            for line in _review_lines(
                config_path=resolved,
                session_id=resolved_session,
                impact_sets=impact_sets,
                full=full,
            ):
                print(line)
            if interactive is None:
                interactive = bool(sys.stdin.isatty() and sys.stdout.isatty())
            if interactive:
                return _run_review_interaction(
                    config_path=resolved,
                    session_id=resolved_session,
                    impact_sets=impact_sets,
                )
            return 0
        finally:
            proxy.close()
    if args[:1] == ["proof-repo-status"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli proof-repo-status <account-id> [--root-dir PATH] [--repo-dir PATH]")
            return 2
        account_id = str(args[1])
        root_dir = None
        repo_dir = None
        index = 2
        while index < len(args):
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--repo-dir" and index + 1 < len(args):
                repo_dir = Path(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        print(json.dumps(_proof_repo_status(account_id=account_id, root_dir=root_dir, repo_dir=repo_dir), ensure_ascii=True, indent=2))
        return 0

    if args[:1] == ["github-connect"]:
        if len(args) < 3:
            print("usage: python -m clawchain.agent_proxy_cli github-connect <account-id> <remote-url> [--root-dir PATH] [--repo-dir PATH]")
            return 2
        account_id = str(args[1])
        remote_url = str(args[2])
        root_dir = None
        repo_dir = None
        index = 3
        while index < len(args):
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--repo-dir" and index + 1 < len(args):
                repo_dir = Path(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        print(json.dumps(_connect_github_remote(account_id=account_id, remote_url=remote_url, root_dir=root_dir, repo_dir=repo_dir), ensure_ascii=True, indent=2))
        return 0

    if args[:1] == ["integrity-check"]:
        account_id = os.environ.get("CLAWCHAIN_AGENT_ACCOUNT_ID") or "local-operator"
        session_id = None
        impact_set_id = None
        root_dir = None
        repo_dir = None
        limit = None
        index = 1
        while index < len(args):
            if args[index] == "--account" and index + 1 < len(args):
                account_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--session" and index + 1 < len(args):
                session_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--impact-set" and index + 1 < len(args):
                impact_set_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--repo-dir" and index + 1 < len(args):
                repo_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--limit" and index + 1 < len(args):
                limit = int(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        print(json.dumps(_integrity_check(account_id=account_id, session_id=session_id, impact_set_id=impact_set_id, limit=limit, root_dir=root_dir, repo_dir=repo_dir), ensure_ascii=True, indent=2))
        return 0

    if args[:1] == ["proof"]:
        account_id = os.environ.get("CLAWCHAIN_AGENT_ACCOUNT_ID") or "local-operator"
        session_id = None
        impact_set_id = None
        root_dir = None
        limit = None
        save_manifest = None
        publish_github = False
        repo_dir = None
        push = True
        index = 1
        while index < len(args):
            if args[index] == "--account" and index + 1 < len(args):
                account_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--session" and index + 1 < len(args):
                session_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--impact-set" and index + 1 < len(args):
                impact_set_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--limit" and index + 1 < len(args):
                limit = int(args[index + 1]); index += 2; continue
            if args[index] == "--save-manifest" and index + 1 < len(args):
                save_manifest = Path(args[index + 1]); index += 2; continue
            if args[index] == "--publish-github":
                publish_github = True; index += 1; continue
            if args[index] == "--repo-dir" and index + 1 < len(args):
                repo_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--no-push":
                push = False; index += 1; continue
            print(f"unknown option: {args[index]}")
            return 2
        entries = _collect_registry_review_entries(account_id=account_id, root_dir=root_dir)
        if session_id is not None:
            entries = [row for row in entries if str(row.get("session_id") or "") == session_id]
        if impact_set_id is not None:
            entries = [row for row in entries if str(row.get("impact_set_id") or "") == impact_set_id]
        if limit is not None:
            entries = entries[: max(limit, 0)]
        cards = [_build_proof_card(row) for row in entries]
        payload = {
            "ok": True,
            "account_id": account_id,
            "count": len(cards),
            "cards": cards,
        }
        manifest = None
        written = None
        if save_manifest is not None or publish_github:
            manifest = _build_proof_manifest(account_id=account_id, cards=cards)
            output_path = save_manifest or Path('/tmp') / f'clawchain-proof-{account_id}.json'
            written = _save_proof_manifest(manifest=manifest, output_path=output_path)
            payload["manifest_path"] = str(written)
            payload["manifest_format"] = manifest["format"]
        if publish_github and written is not None:
            payload["github_publish"] = _publish_manifest_to_repo(
                manifest_path=written,
                account_id=account_id,
                root_dir=root_dir,
                repo_dir=repo_dir,
                push=push,
            )
        print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 0

    if args[:1] == ["verify"]:
        manifest_path = None
        account_id = None
        root_dir = None
        index = 1
        while index < len(args):
            if args[index] == "--manifest" and index + 1 < len(args):
                manifest_path = Path(args[index + 1]); index += 2; continue
            if args[index] == "--account" and index + 1 < len(args):
                account_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        if manifest_path is None:
            print("usage: python -m clawchain.agent_proxy_cli verify --manifest <path> [--account ACCOUNT] [--root-dir PATH]")
            return 2
        payload = _verify_proof_manifest(manifest_path=manifest_path, account_id=account_id, root_dir=root_dir)
        print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 0

    if args[:1] == ["chain-connect"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli chain-connect <account-id> [--root-dir PATH] [--config PATH] [--manifest PATH | --evm-rpc URL --evm-chain-id N --evm-contract ADDR] [--bootstrap-local-evm] [--deployer-private-key HEX]")
            return 2
        account_id = str(args[1])
        root_dir = None
        config_path = None
        manifest_path = None
        evm_rpc_url = None
        evm_chain_id = None
        evm_contract_address = None
        bootstrap_local = False
        deployer_private_key = None
        index = 2
        while index < len(args):
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--config" and index + 1 < len(args):
                config_path = Path(args[index + 1]); index += 2; continue
            if args[index] == "--manifest" and index + 1 < len(args):
                manifest_path = Path(args[index + 1]); index += 2; continue
            if args[index] == "--evm-rpc" and index + 1 < len(args):
                evm_rpc_url = str(args[index + 1]); index += 2; continue
            if args[index] == "--evm-chain-id" and index + 1 < len(args):
                evm_chain_id = int(args[index + 1]); index += 2; continue
            if args[index] == "--evm-contract" and index + 1 < len(args):
                evm_contract_address = str(args[index + 1]); index += 2; continue
            if args[index] == "--bootstrap-local-evm":
                bootstrap_local = True; index += 1; continue
            if args[index] == "--deployer-private-key" and index + 1 < len(args):
                deployer_private_key = str(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        payload = _chain_connect_account(
            account_id=account_id,
            root_dir=root_dir,
            config_path=config_path,
            manifest_path=manifest_path,
            rpc_url=evm_rpc_url,
            chain_id=evm_chain_id,
            contract_address=evm_contract_address,
            bootstrap_local=bootstrap_local,
            deployer_private_key=deployer_private_key,
        )
        print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 0 if payload.get('ok') else 1

    if args[:1] == ["chain-status"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli chain-status <account-id> [--root-dir PATH] [--config PATH]")
            return 2
        account_id = str(args[1])
        root_dir = None
        config_path = None
        index = 2
        while index < len(args):
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--config" and index + 1 < len(args):
                config_path = Path(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        payload = _chain_status(account_id=account_id, root_dir=root_dir, config_path=config_path)
        print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 0 if payload.get('ok') else 1

    if args[:1] == ["chain-verify"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli chain-verify <account-id> [--root-dir PATH] [--config PATH] [--session ID] [--impact-set ID]")
            return 2
        account_id = str(args[1])
        root_dir = None
        config_path = None
        session_id = None
        impact_set_id = None
        index = 2
        while index < len(args):
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--config" and index + 1 < len(args):
                config_path = Path(args[index + 1]); index += 2; continue
            if args[index] == "--session" and index + 1 < len(args):
                session_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--impact-set" and index + 1 < len(args):
                impact_set_id = str(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        payload = _chain_verify(
            account_id=account_id,
            root_dir=root_dir,
            config_path=config_path,
            session_id=session_id,
            impact_set_id=impact_set_id,
        )
        print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 0 if payload.get('ok') else 1

    if args[:1] == ["impact"]:
        config_path = None
        session_id = None
        index = 1
        while index < len(args):
            if args[index] == "--config" and index + 1 < len(args):
                config_path = args[index + 1]; index += 2; continue
            if args[index] == "--session" and index + 1 < len(args):
                session_id = args[index + 1]; index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        try:
            resolved = _resolve_config_path(config_path)
        except RuntimeError as exc:
            print(str(exc))
            return 2
        stored = load_agent_proxy_config(resolved)
        return main(["impact-set-list", str(resolved), "--session", _session_id_from_args_or_config(session_id, stored=stored)])
    if args[:1] == ["restore"]:
        config_path = None
        session_id = None
        target_name = None
        target_pick = None
        source_kind = None
        approve = False
        index = 1
        while index < len(args):
            if args[index] == "--config" and index + 1 < len(args):
                config_path = args[index + 1]; index += 2; continue
            if args[index] == "--session" and index + 1 < len(args):
                session_id = args[index + 1]; index += 2; continue
            if args[index] == "--target" and index + 1 < len(args):
                target_name = args[index + 1]; index += 2; continue
            if args[index] == "--pick" and index + 1 < len(args):
                target_pick = int(args[index + 1]); index += 2; continue
            if args[index] == "--source" and index + 1 < len(args):
                source_kind = args[index + 1]; index += 2; continue
            if args[index] == "--approve":
                approve = True; index += 1; continue
            print(f"unknown option: {args[index]}")
            return 2
        try:
            resolved = _resolve_config_path(config_path)
        except RuntimeError as exc:
            print(str(exc))
            return 2
        stored = load_agent_proxy_config(resolved)
        resolved_session = _session_id_from_args_or_config(session_id, stored=stored)
        if target_pick is not None and target_name is not None:
            print("restore accepts either --target or --pick, not both")
            return 2
        if target_pick is not None:
            proxy = TransparentAgentProxy.create(stored.to_proxy_config())
            try:
                impact_sets = _collect_impact_sets(proxy=proxy, session_id=resolved_session)
            finally:
                proxy.close()
            try:
                picked_impact = _resolve_impact_set_from_pick(
                    impact_sets=impact_sets,
                    target_pick=target_pick,
                )
            except IndexError:
                print(f"restore pick out of range: {target_pick}")
                return 2
            forwarded = ["recover-impact-set-latest", str(resolved), resolved_session, "--impact-set-id", str(picked_impact["impact_set_id"])]
            if approve:
                forwarded.append("--approve")
            return main(forwarded)
        if target_name is not None:
            forwarded = ["recover-latest", str(resolved), target_name]
            if source_kind is not None:
                forwarded.extend(["--source", source_kind])
            if approve:
                forwarded.append("--approve")
            forwarded.extend(["--session", resolved_session])
            return main(forwarded)
        forwarded = ["recover-impact-set-latest", str(resolved), resolved_session]
        if approve:
            forwarded.append("--approve")
        return main(forwarded)
    if args[:1] == ["agents"]:
        print(
            json.dumps(
                {
                    "ok": True,
                    "agents": [
                        {
                            "agent_id": row.agent_id,
                            "display_name": row.display_name,
                            "integration_mode": row.integration_mode,
                            "process_patterns": list(row.process_patterns),
                        }
                        for row in list_known_agents()
                    ],
                },
                ensure_ascii=True,
                indent=2,
            )
        )
        return 0
    if args[:1] == ["guide"]:
        for line in _guide_lines():
            print(line)
        return 0
    if args[:1] == ["monitor"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli monitor <agent-id|all> [--interval SEC] [--once]")
            return 2
        agent_filter = str(args[1])
        interval_sec = 2.0
        once = False
        index = 2
        while index < len(args):
            if args[index] == "--interval" and index + 1 < len(args):
                interval_sec = float(args[index + 1]); index += 2; continue
            if args[index] == "--once":
                once = True; index += 1; continue
            print(f"unknown option: {args[index]}")
            return 2
        if once:
            print(json.dumps({"ok": True, "matches": detect_running_agents(agent_filter=agent_filter)}, ensure_ascii=True, indent=2))
            return 0
        return monitor_agents(agent_filter=agent_filter, interval_sec=interval_sec)
    if args[:1] == ["timeline"]:
        if len(args) < 3:
            print("usage: python -m clawchain.agent_proxy_cli timeline <config-path> <session-id>")
            return 2
        config_path = Path(args[1])
        session_id = str(args[2])
        stored = load_agent_proxy_config(config_path)
        proxy = TransparentAgentProxy.create(stored.to_proxy_config())
        try:
            events = _load_session_events(
                event_store_path=proxy.system.paths.event_store_path,
                session_id=session_id,
            )
            timeline_rows = _build_timeline_rows(events=events)
            print(json.dumps({"ok": True, "session_id": session_id, "timeline": timeline_rows}, ensure_ascii=True, indent=2))
            return 0
        finally:
            proxy.close()
    if args[:1] == ["session-report"]:
        if len(args) < 3:
            print("usage: python -m clawchain.agent_proxy_cli session-report <config-path> <session-id>")
            return 2
        config_path = Path(args[1])
        session_id = str(args[2])
        stored = load_agent_proxy_config(config_path)
        proxy = TransparentAgentProxy.create(stored.to_proxy_config())
        try:
            events = _load_session_events(
                event_store_path=proxy.system.paths.event_store_path,
                session_id=session_id,
            )
            verification = proxy.system.verify_session(session_id)
            signals = proxy.system.extract_risk_signal_records(session_id)
            recovery_rows = []
            if proxy.system.recovery_repository is not None:
                recovery_rows = [
                    row for row in proxy.system.recovery_repository.catalog_store.read_all()
                    if any(str(row.target_name_hint) in json.dumps(event.get("payload", {}), ensure_ascii=True) for event in events)
                ]
            payload = {
                "ok": True,
                "session_id": session_id,
                "event_count": len(events),
                "event_types": [str(row.get("event_type")) for row in events],
                "verify_ok": verification.ok,
                "finding_codes": [finding.code for finding in verification.findings],
                "risk_signals": [
                    {
                        "code": signal.code,
                        "signal_type": signal.signal_type,
                        "subject": signal.subject,
                        "evidence_refs": list(signal.evidence_refs),
                    }
                    for signal in signals
                ],
                "recovery_records": [
                    {
                        "recovery_id": row.recovery_id,
                        "source_kind": row.source_kind,
                        "target_name_hint": row.target_name_hint,
                        "risk_reason": row.risk_reason,
                    }
                    for row in recovery_rows
                ],
            }
            print(json.dumps(payload, ensure_ascii=True, indent=2))
            return 0
        finally:
            proxy.close()
    if args[:1] == ["recovery-list"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli recovery-list <config-path> [--target-name NAME]")
            return 2
        config_path = Path(args[1])
        target_name = None
        index = 2
        while index < len(args):
            if args[index] == "--target-name" and index + 1 < len(args):
                target_name = str(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        stored = load_agent_proxy_config(config_path)
        proxy = TransparentAgentProxy.create(stored.to_proxy_config())
        try:
            if proxy.system.recovery_repository is None:
                print(json.dumps({"ok": False, "reason": "recovery_disabled"}, ensure_ascii=True, indent=2))
                return 1
            rows = proxy.system.recovery_repository.catalog_store.read_all()
            if target_name is not None:
                rows = [row for row in rows if row.target_name_hint == target_name]
            rows.sort(key=lambda row: row.created_ts_ms, reverse=True)
            print(json.dumps({
                "ok": True,
                "count": len(rows),
                "records": [
                    {
                        "recovery_id": row.recovery_id,
                        "created_ts_ms": row.created_ts_ms,
                        "source_kind": row.source_kind,
                        "target_name_hint": row.target_name_hint,
                        "risk_reason": row.risk_reason,
                    }
                    for row in rows
                ],
            }, ensure_ascii=True, indent=2))
            return 0
        finally:
            proxy.close()
    if args[:1] == ["impact-set-list"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli impact-set-list <config-path> [--session ID]")
            return 2
        config_path = Path(args[1])
        session_filter = None
        index = 2
        while index < len(args):
            if args[index] == "--session" and index + 1 < len(args):
                session_filter = str(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        stored = load_agent_proxy_config(config_path)
        proxy = TransparentAgentProxy.create(stored.to_proxy_config())
        try:
            if proxy.system.recovery_impact_set_catalog is None:
                print(json.dumps({"ok": False, "reason": "impact_set_recovery_disabled"}, ensure_ascii=True, indent=2))
                return 1
            rows = proxy.system.recovery_impact_set_catalog.read_all()
            if session_filter is not None:
                rows = [row for row in rows if row.session_id == session_filter]
            rows.sort(key=lambda row: row.created_ts_ms, reverse=True)
            print(json.dumps({
                "ok": True,
                "count": len(rows),
                "impact_sets": [
                    {
                        "impact_set_id": row.impact_set_id,
                        "session_id": row.session_id,
                        "created_ts_ms": row.created_ts_ms,
                        "target_root": row.target_root,
                        "risk_reason": row.risk_reason,
                        "recovery_count": len(row.recovery_ids),
                    }
                    for row in rows
                ],
            }, ensure_ascii=True, indent=2))
            return 0
        finally:
            proxy.close()
    if args[:1] == ["recover-latest"]:
        if len(args) < 3:
            print("usage: python -m clawchain.agent_proxy_cli recover-latest <config-path> <target-name-hint> [--source git|snapshot] [--destination PATH] [--approve] [--session ID] [--run ID]")
            return 2
        config_path = Path(args[1])
        target_name_hint = str(args[2])
        source_kind = None
        destination_path = None
        approve = False
        session_id = None
        run_id = None
        index = 3
        while index < len(args):
            if args[index] == "--source" and index + 1 < len(args):
                source_kind = str(args[index + 1]); index += 2; continue
            if args[index] == "--destination" and index + 1 < len(args):
                destination_path = Path(args[index + 1]); index += 2; continue
            if args[index] == "--approve":
                approve = True; index += 1; continue
            if args[index] == "--session" and index + 1 < len(args):
                session_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--run" and index + 1 < len(args):
                run_id = str(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        stored = load_agent_proxy_config(config_path)
        proxy = TransparentAgentProxy.create(stored.to_proxy_config())
        try:
            protection = _load_recovery_bundle(
                proxy=proxy,
                target_name_hint=target_name_hint,
                source_kind=source_kind,
            )
            recovery_session = session_id or stored.default_session_id
            recovery_run = run_id or stored.default_run_id
            restored, started, completed = proxy.system.execute_recovery_with_audit(
                protection=protection,
                preferred_source=source_kind,
                destination_path=destination_path,
                session_id=recovery_session,
                run_id=recovery_run,
                start_event_index=proxy._session_next_index.get(recovery_session, 0),
                parent_event_hash=proxy._session_last_hash.get(recovery_session),
                require_manual_approval=(False if approve else None),
            )
            proxy._session_next_index[recovery_session] = proxy._session_next_index.get(recovery_session, 0) + 2
            proxy._session_last_hash[recovery_session] = completed.event_hash if completed is not None else started.event_hash
            if restored is None:
                print(json.dumps({"ok": False, "recovered": False, "started_event_type": started.event_type, "failed_event_type": completed.event_type if completed is not None else None}, ensure_ascii=True, indent=2))
                return 1
            verified, verify_event, receipt = proxy.system.verify_recovery_result(
                protection=protection,
                restored_path=restored,
                session_id=recovery_session,
                run_id=recovery_run,
                event_index=proxy._session_next_index[recovery_session],
                parent_event_hash=proxy._session_last_hash.get(recovery_session),
                source_kind=(source_kind or protection.plans[0].source_kind),
            )
            proxy._session_next_index[recovery_session] += 1
            proxy._session_last_hash[recovery_session] = verify_event.event_hash
            proxy.system.flush()
            proxy.system.poll_anchor_submissions()
            print(json.dumps({
                "ok": verified,
                "recovered": True,
                "target_path": str(protection.target_path),
                "restored_path": str(restored),
                "source_kinds": [plan.source_kind for plan in protection.plans],
                "recovery_id": protection.plans[0].recovery_id,
                "verified_event_type": verify_event.event_type,
                "receipt_commitment_type": (receipt.commitment_type if receipt is not None else None),
            }, ensure_ascii=True, indent=2))
            return 0 if verified else 1
        finally:
            proxy.close()
    if args[:1] == ["recover-impact-set-latest"]:
        if len(args) < 3:
            print("usage: python -m clawchain.agent_proxy_cli recover-impact-set-latest <config-path> <session-id> [--impact-set-id ID] [--approve]")
            return 2
        config_path = Path(args[1])
        session_id = str(args[2])
        impact_set_id = None
        approve = False
        index = 3
        while index < len(args):
            if args[index] == "--impact-set-id" and index + 1 < len(args):
                impact_set_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--approve":
                approve = True; index += 1; continue
            print(f"unknown option: {args[index]}")
            return 2
        stored = load_agent_proxy_config(config_path)
        proxy = TransparentAgentProxy.create(stored.to_proxy_config())
        try:
            impact_set, protections = _select_impact_set_protections_by_id(
                proxy=proxy,
                session_id=session_id,
                impact_set_id=impact_set_id,
            )
            restored_targets: list[str] = []
            verified_targets: list[str] = []
            for protection in protections:
                preferred = "snapshot" if protection.target_path.name == ".git" else protection.primary_source_kind()
                restored, started, completed = proxy.system.execute_recovery_with_audit(
                    protection=protection,
                    preferred_source=preferred,
                    session_id=session_id,
                    run_id=stored.default_run_id,
                    start_event_index=proxy._session_next_index.get(session_id, 0),
                    parent_event_hash=proxy._session_last_hash.get(session_id),
                    require_manual_approval=(False if approve else None),
                )
                proxy._session_next_index[session_id] = proxy._session_next_index.get(session_id, 0) + 2
                proxy._session_last_hash[session_id] = completed.event_hash if completed is not None else started.event_hash
                if restored is None:
                    continue
                restored_targets.append(str(restored))
                verified, verify_event, _receipt = proxy.system.verify_recovery_result(
                    protection=protection,
                    restored_path=restored,
                    session_id=session_id,
                    run_id=stored.default_run_id,
                    event_index=proxy._session_next_index[session_id],
                    parent_event_hash=proxy._session_last_hash.get(session_id),
                    source_kind=preferred,
                )
                proxy._session_next_index[session_id] += 1
                proxy._session_last_hash[session_id] = verify_event.event_hash
                if verified:
                    verified_targets.append(str(restored))
            proxy.system.flush()
            proxy.system.poll_anchor_submissions()
            operation_summary = _natural_language_operation_summary(
                risk_reason=str(impact_set.risk_reason),
                target_root=str(impact_set.target_root),
            )
            print(json.dumps({
                "ok": bool(restored_targets),
                "impact_set_id": impact_set.impact_set_id,
                "target_root": impact_set.target_root,
                "operation_summary": operation_summary,
                "restored_scope_summary": _restore_scope_summary(paths=restored_targets),
                "restored_targets": restored_targets,
                "verified_targets": verified_targets,
                "recovery_count": len(restored_targets),
            }, ensure_ascii=True, indent=2))
            return 0 if restored_targets else 1
        finally:
            proxy.close()
    if args[:1] == ["config-init"]:
        if len(args) < 3:
            print("usage: python -m clawchain.agent_proxy_cli config-init <account_id> <password> [--config PATH] [--root-dir PATH] [--workspace PATH] [--session ID] [--run ID] [--no-auto-evm] [--evm-manifest PATH] [--evm-rpc URL] [--evm-chain-id N] [--evm-contract ADDR]")
            return 2
        account_id, password = args[1:3]
        config_path = None
        root_dir = None
        workspace_root = None
        session_id = "default-session"
        run_id = "default-run"
        auto_evm = True
        evm_manifest_path = None
        evm_rpc_url = None
        evm_chain_id = None
        evm_contract_address = None
        index = 3
        while index < len(args):
            if args[index] == "--config" and index + 1 < len(args):
                config_path = Path(args[index + 1]); index += 2; continue
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1]); index += 2; continue
            if args[index] == "--workspace" and index + 1 < len(args):
                workspace_root = Path(args[index + 1]); index += 2; continue
            if args[index] == "--session" and index + 1 < len(args):
                session_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--run" and index + 1 < len(args):
                run_id = str(args[index + 1]); index += 2; continue
            if args[index] == "--no-auto-evm":
                auto_evm = False; index += 1; continue
            if args[index] == "--evm-manifest" and index + 1 < len(args):
                evm_manifest_path = str(args[index + 1]); index += 2; continue
            if args[index] == "--evm-rpc" and index + 1 < len(args):
                evm_rpc_url = str(args[index + 1]); index += 2; continue
            if args[index] == "--evm-chain-id" and index + 1 < len(args):
                evm_chain_id = int(args[index + 1]); index += 2; continue
            if args[index] == "--evm-contract" and index + 1 < len(args):
                evm_contract_address = str(args[index + 1]); index += 2; continue
            print(f"unknown option: {args[index]}")
            return 2
        stored = AgentProxyStoredConfig(
            account_id=account_id,
            password=password,
            base_dir=str(root_dir) if root_dir is not None else None,
            path_hint=str(workspace_root) if workspace_root is not None else None,
            default_session_id=session_id,
            default_run_id=run_id,
            auto_bootstrap_evm=auto_evm,
            evm_manifest_path=evm_manifest_path,
            evm_rpc_url=evm_rpc_url,
            evm_chain_id=evm_chain_id,
            evm_contract_address=evm_contract_address,
        )
        target = config_path or ((root_dir or Path.home() / ".clawchain-agent" / account_id) / "agent-proxy.config.json")
        write_agent_proxy_config(target, stored)
        print(json.dumps({"ok": True, "config_path": str(target), "config": _to_jsonable(stored)}, ensure_ascii=True, indent=2))
        return 0
    if args[:1] == ["serve"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli serve <config-path>")
            return 2
        config_path = Path(args[1])
        stored = load_agent_proxy_config(config_path)
        daemon, artifacts = AgentProxyDaemon.start(
            config=stored.to_proxy_config(),
            session_id=stored.default_session_id,
            run_id=stored.default_run_id,
        )
        state_path = stored.service_state_path()
        state = {
            "pid": os.getpid(),
            "config_path": str(config_path),
            "socket_path": artifacts.socket_path,
            "env_path": artifacts.env_path,
            "wrapper_path": artifacts.wrapper_path,
            "started_at_ms": int(time.time() * 1000),
        }
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        try:
            daemon.thread.join()
            return 0
        finally:
            daemon.close()
            if state_path.exists():
                state_path.unlink()
    if args[:1] == ["service-start"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli service-start <config-path>")
            return 2
        config_path = Path(args[1])
        stored = load_agent_proxy_config(config_path)
        base_dir = Path(stored.base_dir).expanduser() if stored.base_dir else Path.home() / ".clawchain-agent" / stored.account_id
        log_dir = base_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = log_dir / "agent-proxy.out.log"
        stderr_path = log_dir / "agent-proxy.err.log"
        python_exec = os.environ.get("PYTHON", sys.executable)
        with stdout_path.open("a", encoding="utf-8") as stdout_file, stderr_path.open("a", encoding="utf-8") as stderr_file:
            process = subprocess.Popen(
                [python_exec, "-m", "clawchain.agent_proxy_cli", "serve", str(config_path)],
                stdout=stdout_file,
                stderr=stderr_file,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
        state_path = stored.service_state_path()
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if state_path.exists():
                break
            time.sleep(0.1)
        payload = {"ok": True, "spawned_pid": process.pid, "state_path": str(state_path)}
        if state_path.exists():
            payload["service"] = json.loads(state_path.read_text(encoding="utf-8"))
        print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 0
    if args[:1] == ["service-status"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli service-status <config-path>")
            return 2
        config_path = Path(args[1])
        stored = load_agent_proxy_config(config_path)
        state_path = stored.service_state_path()
        if not state_path.exists():
            print(json.dumps({"ok": False, "running": False, "reason": "state_missing"}, ensure_ascii=True, indent=2))
            return 1
        state = json.loads(state_path.read_text(encoding="utf-8"))
        pid = int(state["pid"])
        running = True
        try:
            os.kill(pid, 0)
        except OSError:
            running = False
        ping_ok = False
        if running and state.get("socket_path"):
            try:
                ping_ok = bool(AgentProxyDaemonClient(Path(str(state["socket_path"]))).ping().get("ok"))
            except Exception:  # noqa: BLE001
                ping_ok = False
        print(json.dumps({"ok": True, "running": running, "ping_ok": ping_ok, "service": state}, ensure_ascii=True, indent=2))
        return 0 if running else 1
    if args[:1] == ["service-stop"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli service-stop <config-path>")
            return 2
        config_path = Path(args[1])
        stored = load_agent_proxy_config(config_path)
        state_path = stored.service_state_path()
        if not state_path.exists():
            print(json.dumps({"ok": False, "stopped": False, "reason": "state_missing"}, ensure_ascii=True, indent=2))
            return 1
        state = json.loads(state_path.read_text(encoding="utf-8"))
        pid = int(state["pid"])
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                break
            time.sleep(0.1)
        stopped = False
        try:
            os.kill(pid, 0)
        except OSError:
            stopped = True
        print(json.dumps({"ok": True, "stopped": stopped, "pid": pid}, ensure_ascii=True, indent=2))
        return 0 if stopped else 1
    if args[:1] == ["daemon-tool-json"]:
        if len(args) < 2:
            print("usage: python -m clawchain.agent_proxy_cli daemon-tool-json <socket-path>")
            return 2
        socket_path = Path(args[1])
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            print("stdin payload must be a JSON object")
            return 2
        client = AgentProxyDaemonClient(socket_path)
        response = client.execute_tool(
            session_id=str(payload["session_id"]),
            run_id=str(payload["run_id"]),
            tool_name=str(payload["tool_name"]),
            params=dict(payload.get("params", {})),
            actor_id=str(payload.get("actor_id", "agent")),
            cwd=Path(str(payload["cwd"])) if payload.get("cwd") is not None else None,
        )
        print(json.dumps(response, ensure_ascii=True, indent=2))
        return 0 if response.get("ok") else 1
    if args[:1] == ["daemon"]:
        if len(args) < 5:
            print("usage: python -m clawchain.agent_proxy_cli daemon <account_id> <password> <session_id> <run_id> [--root-dir PATH] [--workspace PATH] [--target PATH]... [--no-auto-evm]")
            return 2
        account_id, password, session_id, run_id = args[1:5]
        root_dir = None
        workspace_root = None
        target_paths: list[Path] = []
        auto_evm = True
        index = 5
        while index < len(args):
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1])
                index += 2
                continue
            if args[index] == "--workspace" and index + 1 < len(args):
                workspace_root = Path(args[index + 1])
                index += 2
                continue
            if args[index] == "--target" and index + 1 < len(args):
                target_paths.append(Path(args[index + 1]))
                index += 2
                continue
            if args[index] == "--no-auto-evm":
                auto_evm = False
                index += 1
                continue
            print(f"unknown option: {args[index]}")
            return 2
        daemon, artifacts = AgentProxyDaemon.start(
            config=_runtime_proxy_config(
                account_id=account_id,
                password=password,
                root_dir=root_dir,
                auto_evm=auto_evm,
            ),
            session_id=session_id,
            run_id=run_id,
        )
        try:
            setup = daemon.proxy.describe_setup_requirements(
                workspace_root=workspace_root,
                target_paths=target_paths,
            ) if workspace_root is not None else daemon.proxy.describe_setup_requirements()
            print(
                json.dumps(
                    {
                        "bootstrap": _to_jsonable(daemon.proxy.bootstrap),
                        "setup": _to_jsonable(setup),
                        "daemon": {
                            "socket_path": artifacts.socket_path,
                            "env_path": artifacts.env_path,
                            "wrapper_path": artifacts.wrapper_path,
                        },
                    },
                    ensure_ascii=True,
                    indent=2,
                )
            )
            daemon.thread.join()
            return 0
        finally:
            daemon.close()
    if args[:1] == ["tool-json"]:
        if len(args) < 5:
            print("usage: python -m clawchain.agent_proxy_cli tool-json <account_id> <password> <session_id> <run_id> [--root-dir PATH] [--no-auto-evm]")
            return 2
        account_id, password, session_id, run_id = args[1:5]
        root_dir = None
        auto_evm = True
        index = 5
        while index < len(args):
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1])
                index += 2
                continue
            if args[index] == "--no-auto-evm":
                auto_evm = False
                index += 1
                continue
            print(f"unknown option: {args[index]}")
            return 2
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            print("stdin payload must be a JSON object")
            return 2
        tool_name = str(payload.get("tool_name", ""))
        params = dict(payload.get("params", {})) if isinstance(payload.get("params", {}), dict) else {}
        actor_id = str(payload.get("actor_id", account_id))
        cwd = Path(str(payload["cwd"])) if payload.get("cwd") is not None else None
        proxy = TransparentAgentProxy.create(
            _runtime_proxy_config(
                account_id=account_id,
                password=password,
                root_dir=root_dir,
                auto_evm=auto_evm,
            )
        )
        try:
            result = proxy.execute_tool(
                session_id=session_id,
                run_id=run_id,
                actor_id=actor_id,
                tool_name=tool_name,
                params=params,
                cwd=cwd,
            )
            verification = proxy.system.verify_session(session_id)
            print(
                json.dumps(
                    {
                        "session_id": result.session_id,
                        "run_id": result.run_id,
                        "tool_call_id": result.tool_call_id,
                        "tool_name": result.tool_name,
                        "success": result.success,
                        "output": result.output,
                        "error": result.error,
                        "protection_count": len(result.protections),
                        "bootstrap": result.bootstrap.__dict__,
                        "verify_ok": verification.ok,
                        "finding_codes": [finding.code for finding in verification.findings],
                    },
                    ensure_ascii=True,
                    indent=2,
                )
            )
            return 0 if result.success else 1
        finally:
            proxy.close()
    if args[:1] == ["init"]:
        if len(args) < 3:
            print("usage: python -m clawchain.agent_proxy_cli init <account_id> <password> [--root-dir PATH] [--workspace PATH] [--target PATH]... [--no-auto-evm]")
            return 2
        account_id, password = args[1:3]
        root_dir = None
        workspace_root = None
        target_paths: list[Path] = []
        auto_evm = True
        index = 3
        while index < len(args):
            if args[index] == "--root-dir" and index + 1 < len(args):
                root_dir = Path(args[index + 1])
                index += 2
                continue
            if args[index] == "--workspace" and index + 1 < len(args):
                workspace_root = Path(args[index + 1])
                index += 2
                continue
            if args[index] == "--target" and index + 1 < len(args):
                target_paths.append(Path(args[index + 1]))
                index += 2
                continue
            if args[index] == "--no-auto-evm":
                auto_evm = False
                index += 1
                continue
            print(f"unknown option: {args[index]}")
            return 2
        proxy = TransparentAgentProxy.create(
            _runtime_proxy_config(
                account_id=account_id,
                password=password,
                root_dir=root_dir,
                auto_evm=auto_evm,
            )
        )
        try:
            artifacts = proxy.prepare_launch_artifacts(
                session_id="default-session",
                run_id="default-run",
            )
            setup = proxy.describe_setup_requirements(
                workspace_root=workspace_root,
                target_paths=target_paths,
            ) if workspace_root is not None else proxy.describe_setup_requirements()
            print(
                json.dumps(
                    {
                        "bootstrap": _to_jsonable(proxy.bootstrap),
                        "setup": _to_jsonable(setup),
                        "launch_artifacts": _to_jsonable(artifacts),
                    },
                    ensure_ascii=True,
                    indent=2,
                )
            )
            return 0
        finally:
            proxy.close()
    if "--" not in args or len(args) < 5:
        print(
            "usage: python -m clawchain.agent_proxy_cli <account_id> <password> <session_id> <run_id> [--root-dir PATH] [--auto-recover] [--no-auto-evm] [--passthrough] -- <cmd...>"
        )
        return 2
    sep = args.index("--")
    pre = args[:sep]
    cmd = args[sep + 1 :]
    account_id, password, session_id, run_id = pre[:4]
    root_dir = None
    auto_recover = False
    auto_evm = True
    passthrough = False
    index = 4
    while index < len(pre):
        if pre[index] == "--root-dir" and index + 1 < len(pre):
            root_dir = Path(pre[index + 1])
            index += 2
            continue
        if pre[index] == "--auto-recover":
            auto_recover = True
            index += 1
            continue
        if pre[index] == "--no-auto-evm":
            auto_evm = False
            index += 1
            continue
        if pre[index] == "--passthrough":
            passthrough = True
            index += 1
            continue
        print(f"unknown option: {pre[index]}")
        return 2
    proxy = TransparentAgentProxy.create(
        _runtime_proxy_config(
            account_id=account_id,
            password=password,
            root_dir=root_dir,
            auto_evm=auto_evm,
        )
    )
    try:
        result = proxy.execute_command(
            session_id=session_id,
            run_id=run_id,
            actor_id=account_id,
            cmd=cmd,
            auto_recover=auto_recover,
        )
        verification = proxy.system.verify_session(session_id)
        if passthrough:
            if result.stdout:
                sys.stdout.write(result.stdout)
            if result.stderr:
                sys.stderr.write(result.stderr)
            return 0 if result.returncode == 0 else result.returncode
        print(
            json.dumps(
                {
                    "session_id": result.session_id,
                    "run_id": result.run_id,
                    "tool_call_id": result.tool_call_id,
                    "cmd": list(result.cmd),
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "protection_count": len(result.protections),
                    "runtime_root": str(proxy.paths.runtime_root),
                    "evidence_root": str(proxy.paths.evidence_root),
                    "vault_root": str(proxy.paths.vault_root),
                    "bootstrap": proxy.bootstrap.__dict__,
                    "verify_ok": verification.ok,
                    "finding_codes": [finding.code for finding in verification.findings],
                },
                ensure_ascii=True,
                indent=2,
            )
        )
        return 0 if result.returncode == 0 else result.returncode
    finally:
        proxy.close()


if __name__ == "__main__":
    raise SystemExit(main())
