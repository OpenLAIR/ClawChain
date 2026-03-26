from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shlex


@dataclass(frozen=True)
class CodexRolloutSessionMeta:
    session_id: str
    cwd: str | None
    file_path: str


@dataclass(frozen=True)
class CodexRolloutObservation:
    kind: str
    call_id: str
    timestamp_ms: int
    source_path: str
    tool_name: str | None = None
    params: dict[str, object] | None = None
    cwd: str | None = None
    output: str | None = None


def parse_iso_timestamp_ms(raw: str | None) -> int:
    token = str(raw or "").strip()
    if not token:
        return 0
    try:
        return int(datetime.fromisoformat(token.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return 0


def codex_rollout_paths(session_id: str) -> list[Path]:
    if not session_id:
        return []
    sessions_root = Path.home() / ".codex" / "sessions"
    if not sessions_root.exists():
        return []
    try:
        return sorted(
            sessions_root.rglob(f"*{session_id}*.jsonl"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return []


def read_rollout_session_meta(path: Path) -> CodexRolloutSessionMeta | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for _ in range(12):
                line = handle.readline()
                if not line:
                    break
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(item.get("type") or "") != "session_meta":
                    continue
                payload = item.get("payload")
                if not isinstance(payload, dict):
                    continue
                session_id = str(payload.get("id") or "").strip()
                if not session_id:
                    continue
                cwd = str(payload.get("cwd") or "").strip() or None
                return CodexRolloutSessionMeta(
                    session_id=session_id,
                    cwd=cwd,
                    file_path=str(path),
                )
    except OSError:
        return None
    return None


def _resolve_path(path_text: str, *, default_cwd: str | None) -> str:
    token = str(path_text or "").strip().strip("'\"")
    if not token:
        return token
    path = Path(token)
    if path.is_absolute() or not default_cwd:
        return str(path)
    return str((Path(default_cwd) / path).resolve())


def _command_tokens(command_text: str) -> list[str]:
    text = str(command_text or "").strip()
    if not text:
        return []
    looks_windows = bool(re.search(r"[A-Za-z]:\\", text)) or ("\\" in text and os.name != "nt")
    try:
        return [str(token) for token in shlex.split(text, posix=(False if looks_windows else (os.name != "nt")))]
    except ValueError:
        return text.split()


def _resolve_powershell_remove_item_target(*, command_text: str) -> str | None:
    tokens = _command_tokens(command_text)
    for index, token in enumerate(tokens):
        if Path(str(token)).name.lower() != "remove-item":
            continue
        probe = index + 1
        while probe < len(tokens):
            current = str(tokens[probe])
            current_lower = current.lower()
            if current_lower in {"-path", "-literalpath"} and probe + 1 < len(tokens):
                return _resolve_powershell_target(command_text=command_text, token=str(tokens[probe + 1]))
            if current.startswith("-"):
                probe += 1
                continue
            return _resolve_powershell_target(command_text=command_text, token=current)
        return None
    return None


def normalize_rollout_tool_call(
    tool_name: str,
    arguments_text: str,
    *,
    default_cwd: str | None = None,
) -> tuple[str | None, dict[str, object]]:
    normalized_name = str(tool_name or "").strip()
    payload_text = str(arguments_text or "")
    if normalized_name == "shell_command":
        try:
            payload = json.loads(payload_text) if payload_text.strip() else {}
        except json.JSONDecodeError:
            payload = {"command": payload_text}
        command = str(payload.get("command") or payload.get("cmd") or "").strip()
        if not command:
            return None, {}
        workdir = str(payload.get("workdir") or payload.get("cwd") or default_cwd or "").strip() or None
        params: dict[str, object] = {"cmd": command}
        if workdir:
            params["cwd"] = workdir
        return "system.run", params
    if normalized_name == "apply_patch":
        deleted = [
            line[len("*** Delete File: "):].strip()
            for line in payload_text.splitlines()
            if line.startswith("*** Delete File: ")
        ]
        if deleted:
            return "fs.delete", {"path": _resolve_path(deleted[0], default_cwd=default_cwd)}
    return None, {}


def _resolve_powershell_target(*, command_text: str, token: str) -> str:
    candidate = str(token or "").strip().strip("'\"")
    if not candidate.startswith("$"):
        return candidate
    var_name = re.escape(candidate[1:])
    match = re.search(
        rf"(?i)\${var_name}\s*=\s*(?P<value>'[^']+'|\"[^\"]+\"|\S+)",
        command_text,
    )
    if match is None:
        return candidate
    return str(match.group("value") or "").strip().strip("'\"")


def extract_risky_target_root(cmd_text: str) -> str:
    target_path = extract_risky_target_path(cmd_text)
    if target_path:
        return Path(target_path).name or target_path
    return "-"


def extract_risky_target_path(cmd_text: str, *, default_cwd: str | None = None) -> str:
    text = str(cmd_text or "").strip()
    if not text:
        return ""
    remove_item_target = _resolve_powershell_remove_item_target(command_text=text)
    if remove_item_target is not None:
        return _resolve_path(remove_item_target, default_cwd=default_cwd)
    delete_match = re.search(r"(?i)\b(?:del|erase)\b\s+(?P<path>'[^']+'|\"[^\"]+\"|\S+)", text)
    if delete_match is not None:
        target = _resolve_powershell_target(command_text=text, token=delete_match.group("path"))
        return _resolve_path(target, default_cwd=default_cwd)
    tokens = _command_tokens(text)
    target = ""
    for token in reversed(tokens):
        if token.startswith("-"):
            continue
        if token.lower() in {"rm", "mv", "find", "chmod", "chown", "git", "write-output", "write-host", "echo", "printf"}:
            continue
        target = token
        break
    if not target:
        return ""
    return _resolve_path(target, default_cwd=default_cwd)


def read_rollout_updates(
    path: Path,
    *,
    start_offset: int = 0,
    default_cwd: str | None = None,
) -> tuple[list[CodexRolloutObservation], int, str | None]:
    observations: list[CodexRolloutObservation] = []
    current_cwd = default_cwd
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(start_offset)
            for line in handle:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    item = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                item_type = str(item.get("type") or "")
                if item_type == "session_meta":
                    payload = item.get("payload")
                    if isinstance(payload, dict):
                        current_cwd = str(payload.get("cwd") or "").strip() or current_cwd
                    continue
                if item_type != "response_item":
                    continue
                payload = item.get("payload")
                if not isinstance(payload, dict):
                    continue
                payload_type = str(payload.get("type") or "")
                timestamp_ms = parse_iso_timestamp_ms(str(item.get("timestamp") or ""))
                call_id = str(payload.get("call_id") or "").strip()
                if payload_type == "function_call":
                    tool_name, params = normalize_rollout_tool_call(
                        str(payload.get("name") or ""),
                        str(payload.get("arguments") or ""),
                        default_cwd=current_cwd,
                    )
                    if not tool_name or not call_id:
                        continue
                    call_cwd = str((params or {}).get("cwd") or current_cwd or "").strip() or None
                    observations.append(
                        CodexRolloutObservation(
                            kind="function_call",
                            call_id=call_id,
                            timestamp_ms=timestamp_ms,
                            source_path=str(path),
                            tool_name=tool_name,
                            params=params,
                            cwd=call_cwd,
                        )
                    )
                    continue
                if payload_type == "function_call_output" and call_id:
                    observations.append(
                        CodexRolloutObservation(
                            kind="function_call_output",
                            call_id=call_id,
                            timestamp_ms=timestamp_ms,
                            source_path=str(path),
                            output=str(payload.get("output") or ""),
                            cwd=current_cwd,
                        )
                    )
            return observations, handle.tell(), current_cwd
    except OSError:
        return [], start_offset, current_cwd


__all__ = [
    "CodexRolloutObservation",
    "CodexRolloutSessionMeta",
    "codex_rollout_paths",
    "extract_risky_target_path",
    "extract_risky_target_root",
    "normalize_rollout_tool_call",
    "parse_iso_timestamp_ms",
    "read_rollout_session_meta",
    "read_rollout_updates",
]
