from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import shlex
import subprocess
import time
from typing import Sequence


@dataclass(frozen=True)
class MonitoredAgent:
    agent_id: str
    display_name: str
    process_patterns: tuple[str, ...]
    integration_mode: str
    negative_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class SessionFingerprint:
    agent_id: str
    pid: int | None
    ppid: int | None
    workspace_path: str | None
    resume_id: str | None
    started_at: str | None
    command_hash: str

    @property
    def stable_key(self) -> str:
        if self.resume_id:
            return f"resume:{self.resume_id}"
        if self.workspace_path:
            return f"path:{Path(self.workspace_path).name or self.workspace_path}"
        if self.started_at:
            started = re.sub(r"[^0-9]", "", self.started_at)
            if started:
                return f"proc:{started[:14]}:{self.command_hash[:8]}"
        if self.pid is not None:
            return f"proc:{self.pid}:{self.command_hash[:8]}"
        return f"cmd:{self.command_hash[:16]}"


DEFAULT_KNOWN_AGENTS: tuple[MonitoredAgent, ...] = (
    MonitoredAgent(
        "codex", "Codex CLI", ("codex", "openai codex"), "shell-wrapper",
        negative_patterns=("codex-linux-sandbox", "shell_snapshots", "cursor"),
    ),
    MonitoredAgent(
        "claude-code", "Claude Code", ("claude", "claude code", "@anthropic-ai/claude-code"), "shell-wrapper",
        negative_patterns=("claudedb", "claude-desktop", "claude-launcher"),
    ),
    MonitoredAgent(
        "cursor", "Cursor CLI", ("cursor-agent", "cursor"), "tool-proxy",
        negative_patterns=("cursor-theme", "cursors/", "xcursor", "libcursor"),
    ),
    MonitoredAgent(
        "gemini-cli", "Gemini CLI", ("gemini", "@google/gemini-cli"), "shell-wrapper",
        negative_patterns=("google-chrome",),
    ),
    MonitoredAgent("openclaw", "OpenClaw", ("openclaw",), "tool-proxy"),
    MonitoredAgent("openhands", "OpenHands", ("openhands",), "runtime-adapter"),
    MonitoredAgent("cline", "Cline", ("cline",), "tool-proxy"),
)


def list_known_agents() -> tuple[MonitoredAgent, ...]:
    config_path = Path(__file__).resolve().parent / "configs" / "supported_agents.json"
    if not config_path.exists():
        return DEFAULT_KNOWN_AGENTS
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        rows = []
        for item in payload.get("agents", []):
            rows.append(
                MonitoredAgent(
                    agent_id=str(item["agent_id"]),
                    display_name=str(item["display_name"]),
                    process_patterns=tuple(str(part) for part in item.get("process_patterns", ())),
                    integration_mode=str(item["integration_mode"]),
                    negative_patterns=tuple(str(part) for part in item.get("negative_patterns", ())),
                )
            )
        return tuple(rows) or DEFAULT_KNOWN_AGENTS
    except Exception:  # noqa: BLE001
        return DEFAULT_KNOWN_AGENTS


def _command_text(line: str) -> str:
    parts = line.strip().split(maxsplit=1)
    return parts[1] if len(parts) == 2 else line.strip()


def _is_internal_monitor_process(line: str) -> bool:
    lowered = line.lower()
    return (
        "python -m clawchain.agent_proxy_cli" in lowered
        or "codex-linux-sandbox" in lowered
        or "/.codex/shell_snapshots/" in lowered
    )


def _matches_negative(agent: MonitoredAgent, line: str) -> bool:
    lowered = line.lower()
    return any(neg in lowered for neg in agent.negative_patterns)


_AGENT_MATCH_PATTERNS: dict[str, re.Pattern[str]] = {
    "codex": re.compile(r"(^|[\s/])codex([\s-]|$)", re.IGNORECASE),
    "claude-code": re.compile(r"(^|[\s/])claude([\s-]|$)", re.IGNORECASE),
    "cursor": re.compile(r"(^|[\s/])(cursor-agent|cursor)([\s-]|$)", re.IGNORECASE),
    "gemini-cli": re.compile(r"(^|[\s/])gemini([\s-]|$)|@google/gemini-cli", re.IGNORECASE),
    "openclaw": re.compile(r"(^|[\s/])openclaw([\s]|$)", re.IGNORECASE),
    "openhands": re.compile(r"(^|[\s/])openhands([\s]|$)", re.IGNORECASE),
    "cline": re.compile(r"(^|[\s/])cline([\s]|$)", re.IGNORECASE),
}


def _matches_agent(agent: MonitoredAgent, line: str) -> bool:
    command = _command_text(line)
    if _matches_negative(agent, command):
        return False
    pattern = _AGENT_MATCH_PATTERNS.get(agent.agent_id)
    if pattern is not None:
        return pattern.search(command) is not None
    return any(p in command.lower() for p in agent.process_patterns)


def _integration_status(agent: MonitoredAgent, line: str) -> tuple[str, str]:
    lowered = line.lower()
    if "clawchain" in lowered or "codex-with-clawchain" in lowered or "codex-shims" in lowered:
        return "managed", f"already routed through {agent.integration_mode}"
    return "detected-only", f"detected but not yet confirmed through {agent.integration_mode}"


def _extract_workspace_hint(agent: MonitoredAgent, line: str) -> str | None:
    command = _command_text(line)
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if agent.agent_id in {"codex", "claude-code", "cursor"}:
        for index, token in enumerate(tokens):
            if token == "-C" and index + 1 < len(tokens):
                return tokens[index + 1]
    return None


def _extract_pid(line: str) -> int | None:
    parts = line.strip().split(maxsplit=1)
    if not parts:
        return None
    try:
        return int(parts[0])
    except ValueError:
        return None


def _read_proc_env_var(pid: int | None, key: str) -> str | None:
    if pid is None:
        return None
    environ_path = Path(f"/proc/{pid}/environ")
    try:
        raw = environ_path.read_bytes()
    except OSError:
        return None
    prefix = f"{key}=".encode("utf-8")
    for chunk in raw.split(b"\0"):
        if chunk.startswith(prefix):
            try:
                return chunk[len(prefix):].decode("utf-8") or None
            except UnicodeDecodeError:
                return None
    return None


def _parse_started_at_epoch(started_at: str | None) -> int | None:
    if not started_at:
        return None
    try:
        parsed = time.strptime(started_at, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return int(time.mktime(parsed))


def _lookup_codex_thread_id_from_state(
    pid: int | None,
    *,
    started_at: str | None,
    path_hint: str | None = None,
) -> str | None:
    if pid is None:
        return None
    cwd = path_hint or _read_proc_cwd(pid)
    if not cwd:
        return None
    started_epoch = _parse_started_at_epoch(started_at)
    db_path = Path.home() / ".codex" / "state_5.sqlite"
    if not db_path.exists():
        return None
    con = None
    try:
        con = sqlite3.connect(str(db_path))
        con.row_factory = sqlite3.Row
        rows = con.execute("select id, created_at, updated_at from threads where cwd = ? and archived = 0 order by updated_at desc limit 16", (cwd,)).fetchall()
    except sqlite3.Error:
        return None
    finally:
        if con is not None:
            con.close()
    if not rows:
        return None
    if started_epoch is None:
        return str(rows[0]["id"])
    window = 900
    scored = []
    for row in rows:
        created_at = int(row["created_at"] or 0)
        updated_at = int(row["updated_at"] or 0)
        if created_at and abs(created_at - started_epoch) <= window:
            scored.append((abs(created_at - started_epoch), str(row["id"])))
            continue
        if updated_at and abs(updated_at - started_epoch) <= window:
            scored.append((abs(updated_at - started_epoch), str(row["id"])))
    if not scored:
        if len(rows) == 1:
            return str(rows[0]["id"])
        return None
    scored.sort(key=lambda item: item[0])
    return scored[0][1]


def _extract_resume_id(
    tokens: Sequence[str],
    *,
    pid: int | None = None,
    started_at: str | None = None,
    path_hint: str | None = None,
) -> str | None:
    token_list = list(tokens)
    if "resume" in token_list:
        index = token_list.index("resume")
        if index + 1 < len(token_list):
            return token_list[index + 1]
    for index, token in enumerate(token_list):
        if token in {"-r", "--resume"} and index + 1 < len(token_list):
            return token_list[index + 1]
        if token.startswith("--resume="):
            return token.split("=", 1)[1]
    env_resume_id = _read_proc_env_var(pid, "CODEX_THREAD_ID")
    if env_resume_id:
        return env_resume_id
    state_resume_id = _lookup_codex_thread_id_from_state(pid, started_at=started_at, path_hint=path_hint)
    if state_resume_id:
        return state_resume_id
    return None


def _command_hash(line: str) -> str:
    normalized = _process_identity(line)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _build_session_fingerprint(
    agent: MonitoredAgent,
    line: str,
    *,
    path_hint: str | None,
    pid: int | None,
    ppid: int | None,
    started_at: str | None,
) -> SessionFingerprint:
    command = _command_text(line)
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    resume_id = _extract_resume_id(tokens, pid=pid, started_at=started_at, path_hint=path_hint)
    return SessionFingerprint(
        agent_id=agent.agent_id,
        pid=pid,
        ppid=ppid,
        workspace_path=path_hint,
        resume_id=resume_id,
        started_at=started_at,
        command_hash=_command_hash(line),
    )


def _extract_session_fingerprint(agent: MonitoredAgent, line: str, *, path_hint: str | None) -> str:
    command = _command_text(line)
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    resume_id = _extract_resume_id(tokens, pid=pid, started_at=started_at, path_hint=path_hint)
    if resume_id:
        return f"resume:{resume_id}"
    if path_hint:
        return f"path:{Path(path_hint).name or path_hint}"
    return f"proc:{_process_identity(line)[:48]}"


def _lookup_started_at_label(pid: int | None) -> str | None:
    if pid is None:
        return None
    probe = subprocess.run(
        ["ps", "-p", str(pid), "-o", "lstart="],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        return None
    text = probe.stdout.strip()
    return text or None


def _process_identity(line: str) -> str:
    command = _command_text(line)
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if not tokens:
        return command
    normalized = list(tokens)
    if normalized[0] in {"node", "bash", "/usr/bin/env", "env"} and len(normalized) > 1:
        normalized = normalized[1:]
    if normalized:
        normalized[0] = normalized[0].split("/")[-1]
    return " ".join(normalized)


def _prepare_command(agent: MonitoredAgent, *, path_hint: str | None) -> str:
    workspace_arg = path_hint or "<path>"
    git_context = "--git-context <bind-existing-git|managed-session-git>"
    if agent.agent_id == "codex":
        workspace_part = f"--workspace {workspace_arg} " if path_hint else ""
        return (
            "python -m clawchain.agent_proxy_cli prepare codex <account> <password> "
            f"{workspace_part}{git_context}"
        )
    if agent.agent_id == "claude-code":
        return (
            "python -m clawchain.agent_proxy_cli prepare claude-code <account> <password> "
            f"--workspace {workspace_arg} {git_context}"
        )
    if agent.agent_id == "cursor":
        return (
            "python -m clawchain.agent_proxy_cli prepare cursor-agent <account> <password> "
            f"--workspace {workspace_arg} {git_context}"
        )
    if agent.agent_id == "openclaw":
        return (
            "python -m clawchain.agent_proxy_cli prepare openclaw <account> <password> "
            f"--workspace {workspace_arg} {git_context}"
        )
    return f"prepare this agent through integration mode: {agent.integration_mode}"


def _read_proc_cmdline(pid: int) -> str | None:
    try:
        cmdline_path = Path(f"/proc/{pid}/cmdline")
        if cmdline_path.exists():
            raw = cmdline_path.read_bytes()
            return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except (OSError, PermissionError):
        pass
    return None


def _read_proc_cwd(pid: int) -> str | None:
    try:
        cwd_link = Path(f"/proc/{pid}/cwd")
        if cwd_link.exists():
            return str(cwd_link.resolve())
    except (OSError, PermissionError):
        pass
    return None


def _read_proc_ppid(pid: int) -> int | None:
    try:
        stat_path = Path(f"/proc/{pid}/stat")
        if stat_path.exists():
            stat_text = stat_path.read_text(encoding="utf-8", errors="replace")
            close_paren = stat_text.rfind(")")
            if close_paren >= 0:
                fields = stat_text[close_paren + 2:].split()
                if len(fields) >= 2:
                    return int(fields[1])
    except (OSError, PermissionError, ValueError):
        pass
    return None


def _scan_processes_via_proc() -> list[str] | None:
    proc = Path("/proc")
    if not proc.exists():
        return None
    lines: list[str] = []
    try:
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            cmdline = _read_proc_cmdline(pid)
            if cmdline:
                lines.append(f"{pid} {cmdline}")
    except (OSError, PermissionError):
        return None
    return lines if lines else None


def _scan_processes_via_pgrep() -> list[str]:
    probe = subprocess.run(
        ["pgrep", "-af", "."],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode not in (0, 1):
        return []
    return [line.strip() for line in probe.stdout.splitlines() if line.strip()]


def _scan_processes() -> list[str]:
    proc_lines = _scan_processes_via_proc()
    if proc_lines is not None:
        return proc_lines
    return _scan_processes_via_pgrep()


def detect_running_agents(*, agent_filter: str = "all") -> list[dict[str, str]]:
    lines = _scan_processes()
    matches: list[dict[str, str]] = []
    for agent in list_known_agents():
        if agent_filter != "all" and agent.agent_id != agent_filter:
            continue
        for line in lines:
            if _is_internal_monitor_process(line):
                continue
            if _matches_agent(agent, line):
                status, status_message = _integration_status(agent, line)
                path_hint = _extract_workspace_hint(agent, line)
                pid = _extract_pid(line)
                ppid = _read_proc_ppid(pid) if pid else None
                started_at = _lookup_started_at_label(pid)
                fingerprint = _build_session_fingerprint(
                    agent, line,
                    path_hint=path_hint,
                    pid=pid,
                    ppid=ppid,
                    started_at=started_at,
                )
                matches.append(
                    {
                        "agent_id": agent.agent_id,
                        "display_name": agent.display_name,
                        "process_line": line,
                        "integration_mode": agent.integration_mode,
                        "monitoring_status": status,
                        "status_message": status_message,
                        "path_hint": path_hint,
                        "pid": pid,
                        "ppid": ppid,
                        "started_at": started_at,
                        "session_fingerprint": fingerprint.stable_key,
                        "process_summary": _process_identity(line),
                        "command_text": _command_text(line),
                        "attach_hint": _prepare_command(agent, path_hint=path_hint),
                        "prepare_command": _prepare_command(agent, path_hint=path_hint),
                    }
                )
    return matches


def aggregate_running_agents(matches: list[dict[str, str]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = {}
    for item in matches:
        path_hint = str(item.get("path_hint") or "")
        process_identity = _process_identity(str(item["process_line"]))
        raw_fingerprint = item.get("session_fingerprint")
        fingerprint = str(raw_fingerprint or process_identity)
        key = (str(item["agent_id"]), fingerprint if raw_fingerprint else (path_hint or fingerprint))
        grouped.setdefault(key, []).append(item)
    sessions: list[dict[str, object]] = []
    for (_agent_id, _group_key), items in grouped.items():
        first = items[0]
        statuses = {str(item["monitoring_status"]) for item in items}
        monitoring_status = "managed" if "managed" in statuses else str(first["monitoring_status"])
        path_hint = next((str(item["path_hint"]) for item in items if item.get("path_hint")), None)
        started_at = next((str(item["started_at"]) for item in items if item.get("started_at")), None)
        session_fingerprint = next((str(item["session_fingerprint"]) for item in items if item.get("session_fingerprint")), _process_identity(str(first["process_line"])))
        sessions.append(
            {
                "agent_id": first["agent_id"],
                "display_name": first["display_name"],
                "integration_mode": first["integration_mode"],
                "monitoring_status": monitoring_status,
                "path_hint": path_hint,
                "started_at": started_at,
                "session_fingerprint": session_fingerprint,
                "prepare_command": next(
                    (str(item["prepare_command"]) for item in items if item.get("path_hint")),
                    str(first["prepare_command"]),
                ),
                "attach_hint": next(
                    (str(item["attach_hint"]) for item in items if item.get("path_hint")),
                    str(first["attach_hint"]),
                ),
                "process_count": len(items),
                "pids": [int(item["pid"]) for item in items if item.get("pid") is not None],
                "sample_processes": [str(item["process_line"]) for item in items[:3]],
                "sample_process_summary": str(first.get("process_summary") or _process_identity(str(first["process_line"]))),
                "command_text": str(first.get("command_text") or _command_text(str(first["process_line"]))),
            }
        )
    sessions.sort(key=lambda row: (row["agent_id"], row["path_hint"] or "", row["session_fingerprint"], row["monitoring_status"]))
    return sessions


def monitor_agents(
    *,
    agent_filter: str = "all",
    interval_sec: float = 2.0,
) -> int:
    seen: set[str] = set()
    print(f"[clawchain] monitoring agents: {agent_filter}")
    while True:
        current = detect_running_agents(agent_filter=agent_filter)
        current_keys = {item["process_line"] for item in current}
        for item in current:
            if item["process_line"] in seen:
                continue
            print(
                f"[clawchain] detected {item['display_name']} "
                f"({item['agent_id']}); {item['status_message']}"
            )
            if item["monitoring_status"] != "managed":
                print(f"[clawchain] attach hint: {item['attach_hint']}")
        for vanished in sorted(seen - current_keys):
            print(f"[clawchain] process left monitoring scope: {vanished}")
        seen = current_keys
        time.sleep(interval_sec)


__all__ = [
    "MonitoredAgent",
    "SessionFingerprint",
    "aggregate_running_agents",
    "detect_running_agents",
    "list_known_agents",
    "monitor_agents",
]
