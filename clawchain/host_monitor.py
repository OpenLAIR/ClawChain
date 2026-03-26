from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import shlex
import shutil
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
        negative_patterns=("codex-linux-sandbox", "codex-command-runner", "codex-windows-sandbox-setup", "shell_snapshots", "cursor"),
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


_PROCESS_SCAN_METADATA: dict[int, dict[str, object]] = {}
_CODEX_ROLLOUT_CACHE: dict[str, object] = {
    "loaded_at": 0.0,
    "items": (),
}
_CODEX_ROLLOUT_CACHE_TTL_SEC = 2.0
_CODEX_ROLLOUT_CACHE_LIMIT = 256


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


def _reset_process_scan_metadata() -> None:
    _PROCESS_SCAN_METADATA.clear()


def _remember_process_scan_metadata(
    pid: int,
    *,
    ppid: int | None = None,
    started_at: str | None = None,
    started_epoch: int | None = None,
    cwd: str | None = None,
) -> None:
    _PROCESS_SCAN_METADATA[pid] = {
        "ppid": ppid,
        "started_at": started_at,
        "started_epoch": started_epoch,
        "cwd": cwd,
    }


def _scan_metadata_value(pid: int | None, key: str) -> object | None:
    if pid is None:
        return None
    return _PROCESS_SCAN_METADATA.get(pid, {}).get(key)


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
    "codex": re.compile(r"(^|[\s/\\])codex(?:\.(?:cmd|exe|ps1|bat))?(?:[\s._-]|$)|openai codex", re.IGNORECASE),
    "claude-code": re.compile(r"(^|[\s/\\])claude(?:\.(?:cmd|exe|ps1|bat))?(?:[\s._-]|$)", re.IGNORECASE),
    "cursor": re.compile(r"(^|[\s/\\])(cursor-agent|cursor)(?:\.(?:cmd|exe|ps1|bat))?(?:[\s._-]|$)", re.IGNORECASE),
    "gemini-cli": re.compile(r"(^|[\s/\\])gemini(?:\.(?:cmd|exe|ps1|bat))?(?:[\s._-]|$)|@google/gemini-cli", re.IGNORECASE),
    "openclaw": re.compile(r"(^|[\s/\\])openclaw(?:\.(?:cmd|exe|ps1|bat))?(?:[\s._-]|$)", re.IGNORECASE),
    "openhands": re.compile(r"(^|[\s/\\])openhands(?:\.(?:cmd|exe|ps1|bat))?(?:[\s._-]|$)", re.IGNORECASE),
    "cline": re.compile(r"(^|[\s/\\])cline(?:\.(?:cmd|exe|ps1|bat))?(?:[\s._-]|$)", re.IGNORECASE),
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


def _normalize_workspace_path(path: str | None) -> str | None:
    text = str(path or "").strip()
    if not text:
        return None
    try:
        expanded = os.path.expanduser(text)
    except Exception:  # noqa: BLE001
        expanded = text
    normalized = os.path.normpath(expanded)
    if os.name == "nt":
        normalized = os.path.normcase(normalized)
    return normalized or None


def _parse_started_at_epoch(started_at: str | None) -> int | None:
    token = str(started_at or "").strip()
    if not token:
        return None
    if token.isdigit():
        try:
            return int(token)
        except ValueError:
            return None
    try:
        iso_token = token[:-1] + "+00:00" if token.endswith("Z") else token
        parsed = datetime.fromisoformat(iso_token)
    except ValueError:
        parsed = None
    if parsed is not None:
        return int(parsed.timestamp())
    for fmt in ("%Y-%m-%d %H:%M:%S", "%a %b %d %H:%M:%S %Y"):
        try:
            return int(time.mktime(time.strptime(token, fmt)))
        except ValueError:
            continue
    cjk_match = re.search(
        r"(?P<month>\d{1,2})月\s*(?P<day>\d{1,2})\s*(?P<hour>\d{1,2}):(?P<minute>\d{2}):(?P<second>\d{2})\s*(?P<year>\d{4})",
        token,
    )
    if cjk_match is None:
        return None
    try:
        parsed = datetime(
            int(cjk_match.group("year")),
            int(cjk_match.group("month")),
            int(cjk_match.group("day")),
            int(cjk_match.group("hour")),
            int(cjk_match.group("minute")),
            int(cjk_match.group("second")),
        )
    except ValueError:
        return None
    return int(parsed.timestamp())


def _lookup_started_at_epoch(pid: int | None, started_at: str | None) -> int | None:
    cached = _scan_metadata_value(pid, "started_epoch")
    if isinstance(cached, int):
        return cached
    return _parse_started_at_epoch(started_at)


@dataclass(frozen=True)
class CodexRolloutSession:
    session_id: str
    cwd: str | None
    cwd_key: str | None
    started_epoch: int | None
    file_path: str


def _read_codex_rollout_session(path: Path) -> CodexRolloutSession | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for _ in range(8):
                line = handle.readline()
                if not line:
                    break
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(payload.get("type") or "") != "session_meta":
                    continue
                meta = payload.get("payload")
                if not isinstance(meta, dict):
                    continue
                session_id = str(meta.get("id") or "").strip()
                if not session_id:
                    continue
                cwd = str(meta.get("cwd") or "").strip() or None
                started_at = str(meta.get("timestamp") or payload.get("timestamp") or "").strip() or None
                return CodexRolloutSession(
                    session_id=session_id,
                    cwd=cwd,
                    cwd_key=_normalize_workspace_path(cwd),
                    started_epoch=_parse_started_at_epoch(started_at),
                    file_path=str(path),
                )
    except OSError:
        return None
    return None


def _recent_codex_rollout_sessions() -> tuple[CodexRolloutSession, ...]:
    cached_at = float(_CODEX_ROLLOUT_CACHE.get("loaded_at") or 0.0)
    cached_items = _CODEX_ROLLOUT_CACHE.get("items")
    if isinstance(cached_items, tuple) and (time.time() - cached_at) <= _CODEX_ROLLOUT_CACHE_TTL_SEC:
        return cached_items
    sessions_root = Path.home() / ".codex" / "sessions"
    items: list[CodexRolloutSession] = []
    files: list[Path] = []
    if sessions_root.exists():
        try:
            files = sorted(
                sessions_root.rglob("rollout-*.jsonl"),
                key=lambda candidate: candidate.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            files = []
    for rollout_path in files[:_CODEX_ROLLOUT_CACHE_LIMIT]:
        session = _read_codex_rollout_session(rollout_path)
        if session is not None:
            items.append(session)
    result = tuple(items)
    _CODEX_ROLLOUT_CACHE["loaded_at"] = time.time()
    _CODEX_ROLLOUT_CACHE["items"] = result
    return result


def _lookup_codex_thread_id_from_rollouts(
    *,
    started_epoch: int | None,
    path_hint: str | None = None,
) -> str | None:
    sessions = _recent_codex_rollout_sessions()
    if not sessions:
        return None
    path_key = _normalize_workspace_path(path_hint)
    candidates = list(sessions)
    if path_key:
        path_matches = [item for item in candidates if item.cwd_key == path_key]
        if path_matches:
            candidates = path_matches
    if started_epoch is not None:
        window_sec = 1800
        scored: list[tuple[int, int, str]] = []
        for item in candidates:
            if item.started_epoch is None:
                continue
            delta = abs(item.started_epoch - started_epoch)
            if delta > window_sec:
                continue
            scored.append((0 if path_key and item.cwd_key == path_key else 1, delta, item.session_id))
        if scored:
            scored.sort(key=lambda item: (item[0], item[1], item[2]))
            return scored[0][2]
    if path_key and candidates:
        return candidates[0].session_id
    return None


def _lookup_codex_thread_id_from_state(
    pid: int | None,
    *,
    started_at: str | None,
    path_hint: str | None = None,
) -> str | None:
    cwd = path_hint or _read_proc_cwd(pid)
    started_epoch = _lookup_started_at_epoch(pid, started_at)
    db_path = Path.home() / ".codex" / "state_5.sqlite"
    if cwd and db_path.exists():
        con = None
        try:
            con = sqlite3.connect(str(db_path))
            con.row_factory = sqlite3.Row
            rows = con.execute("select id, created_at, updated_at from threads where cwd = ? and archived = 0 order by updated_at desc limit 16", (cwd,)).fetchall()
        except sqlite3.Error:
            rows = []
        finally:
            if con is not None:
                con.close()
        if rows:
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
            if scored:
                scored.sort(key=lambda item: item[0])
                return scored[0][1]
            if len(rows) == 1:
                return str(rows[0]["id"])
    return _lookup_codex_thread_id_from_rollouts(started_epoch=started_epoch, path_hint=cwd)


def _extract_resume_id(
    tokens: Sequence[str],
    *,
    agent_id: str | None = None,
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
    if agent_id not in (None, "", "codex"):
        return None
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
    resume_id = _extract_resume_id(
        tokens,
        agent_id=agent.agent_id,
        pid=pid,
        started_at=started_at,
        path_hint=path_hint,
    )
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
    resume_id = _extract_resume_id(tokens, agent_id=agent.agent_id, path_hint=path_hint)
    if resume_id:
        return f"resume:{resume_id}"
    if path_hint:
        return f"path:{Path(path_hint).name or path_hint}"
    return f"proc:{_process_identity(line)[:48]}"


def _lookup_started_at_label(pid: int | None) -> str | None:
    if pid is None:
        return None
    cached = _scan_metadata_value(pid, "started_at")
    if isinstance(cached, str) and cached:
        return cached
    if os.name == "nt":
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


def _command_candidates(*names: str) -> tuple[str, ...]:
    values: list[str] = []
    seen: set[str] = set()
    for name in names:
        resolved = shutil.which(name)
        if resolved and resolved not in seen:
            values.append(resolved)
            seen.add(resolved)
    if os.name != "nt":
        return tuple(values)
    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    static_candidates: list[Path] = []
    lowered_names = {name.lower() for name in names}
    if {"powershell", "powershell.exe"} & lowered_names:
        static_candidates.extend(
            [
                system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
                system_root / "Sysnative" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
            ]
        )
    if {"pwsh", "pwsh.exe"} & lowered_names:
        static_candidates.extend(
            [
                Path(os.environ.get("ProgramFiles") or r"C:\Program Files") / "PowerShell" / "7" / "pwsh.exe",
                Path(os.environ.get("ProgramW6432") or r"C:\Program Files") / "PowerShell" / "7" / "pwsh.exe",
            ]
        )
    if {"tasklist", "tasklist.exe"} & lowered_names:
        static_candidates.append(system_root / "System32" / "tasklist.exe")
    for candidate in static_candidates:
        text = str(candidate)
        if candidate.exists() and text not in seen:
            values.append(text)
            seen.add(text)
    return tuple(values)


def _process_identity(line: str) -> str:
    command = _command_text(line)
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if not tokens:
        return command
    normalized = list(tokens)
    wrapper_names = {"node", "node.exe", "bash", "bash.exe", "/usr/bin/env", "env", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
    wrapper_args = {"/c", "/k", "/d", "-c", "-command"}
    while normalized and Path(normalized[0]).name.lower() in wrapper_names and len(normalized) > 1:
        normalized = normalized[1:]
        while normalized and normalized[0].lower() in wrapper_args:
            normalized = normalized[1:]
    if normalized:
        normalized[0] = Path(normalized[0]).name or normalized[0]
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
    cached = _scan_metadata_value(pid, "cwd")
    if isinstance(cached, str) and cached:
        return cached
    try:
        cwd_link = Path(f"/proc/{pid}/cwd")
        if cwd_link.exists():
            return str(cwd_link.resolve())
    except (OSError, PermissionError):
        pass
    return None


def _read_proc_ppid(pid: int) -> int | None:
    cached = _scan_metadata_value(pid, "ppid")
    if isinstance(cached, int):
        return cached
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
    _reset_process_scan_metadata()
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
                started_at = _lookup_started_at_label(pid)
                _remember_process_scan_metadata(
                    pid,
                    ppid=_read_proc_ppid(pid),
                    started_at=started_at,
                    started_epoch=_parse_started_at_epoch(started_at),
                    cwd=_read_proc_cwd(pid),
                )
                lines.append(f"{pid} {cmdline}")
    except (OSError, PermissionError):
        return None
    return lines if lines else None


def _scan_processes_via_powershell() -> list[str] | None:
    _reset_process_scan_metadata()
    powershell_bins = _command_candidates("powershell", "powershell.exe", "pwsh", "pwsh.exe")
    if not powershell_bins:
        return None
    script = (
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
        "$ErrorActionPreference='Stop';"
        "try {"
        "$rows=Get-CimInstance Win32_Process | ForEach-Object {"
        "[pscustomobject]@{"
        "pid=[int]$_.ProcessId;"
        "ppid=[int]$_.ParentProcessId;"
        "created=$(if ($_.CreationDate) { ([datetime]$_.CreationDate).ToString('yyyy-MM-dd HH:mm:ss') } else { $null });"
        "created_epoch=$(if ($_.CreationDate) { [int64]([DateTimeOffset]([datetime]$_.CreationDate)).ToUnixTimeSeconds() } else { $null });"
        "cmd=$(if ($_.CommandLine) { $_.CommandLine } elseif ($_.ExecutablePath) { $_.ExecutablePath } else { $_.Name })"
        "}"
        "}"
        "} catch {"
        "$rows=Get-Process | ForEach-Object {"
        "$path=$null;"
        "$created=$null;"
        "$created_epoch=$null;"
        "try { $path=$_.Path } catch {}"
        "try { $created=$_.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch {}"
        "try { $created_epoch=[int64]([DateTimeOffset]$_.StartTime).ToUnixTimeSeconds() } catch {}"
        "[pscustomobject]@{"
        "pid=[int]$_.Id;"
        "ppid=$null;"
        "created=$created;"
        "created_epoch=$created_epoch;"
        "cmd=$(if ($path) { $path } else { $_.ProcessName })"
        "}"
        "}"
        "};"
        "$rows | ConvertTo-Json -Compress"
    )
    for powershell_bin in powershell_bins:
        try:
            probe = subprocess.run(
                [powershell_bin, "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError:
            continue
        if probe.returncode != 0 or not probe.stdout.strip():
            continue
        try:
            payload = json.loads(probe.stdout)
        except json.JSONDecodeError:
            continue
        rows = payload if isinstance(payload, list) else [payload]
        lines: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                pid = int(row.get("pid"))
            except (TypeError, ValueError):
                continue
            command_text = row.get("cmd")
            if not isinstance(command_text, str) or not command_text.strip():
                continue
            try:
                ppid = int(row.get("ppid")) if row.get("ppid") is not None else None
            except (TypeError, ValueError):
                ppid = None
            started_at = row.get("created")
            started_at_label = started_at if isinstance(started_at, str) and started_at.strip() else None
            try:
                started_epoch = int(row.get("created_epoch")) if row.get("created_epoch") is not None else None
            except (TypeError, ValueError):
                started_epoch = None
            _remember_process_scan_metadata(
                pid,
                ppid=ppid,
                started_at=started_at_label,
                started_epoch=started_epoch,
            )
            lines.append(f"{pid} {command_text.strip()}")
        if lines:
            return lines
    return None


def _scan_processes_via_tasklist() -> list[str] | None:
    if os.name != "nt":
        return None
    tasklist_bins = _command_candidates("tasklist", "tasklist.exe")
    if not tasklist_bins:
        return None
    for tasklist_bin in tasklist_bins:
        try:
            probe = subprocess.run(
                [tasklist_bin, "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError:
            continue
        if probe.returncode != 0:
            continue
        lines: list[str] = []
        for raw in probe.stdout.splitlines():
            text = raw.strip()
            if not text:
                continue
            try:
                row = next(csv.reader([text]))
            except Exception:  # noqa: BLE001
                continue
            if len(row) < 2:
                continue
            image_name = str(row[0]).strip()
            pid_token = str(row[1]).strip()
            try:
                pid = int(pid_token)
            except ValueError:
                continue
            if not image_name:
                continue
            _remember_process_scan_metadata(pid)
            lines.append(f"{pid} {image_name}")
        if lines:
            return lines
    return None


def _scan_processes_via_pgrep() -> list[str]:
    if os.name == "nt":
        return []
    try:
        probe = subprocess.run(
            ["pgrep", "-af", "."],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return []
    if probe.returncode not in (0, 1):
        return []
    return [line.strip() for line in probe.stdout.splitlines() if line.strip()]


def _scan_processes() -> list[str]:
    proc_lines = _scan_processes_via_proc()
    if proc_lines is not None:
        return proc_lines
    powershell_lines = _scan_processes_via_powershell()
    if powershell_lines is not None:
        return powershell_lines
    tasklist_lines = _scan_processes_via_tasklist()
    if tasklist_lines is not None:
        return tasklist_lines
    if os.name == "nt":
        return []
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
                if not path_hint and pid is not None:
                    path_hint = _read_proc_cwd(pid)
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
