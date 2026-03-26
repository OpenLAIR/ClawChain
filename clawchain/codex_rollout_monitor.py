from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import threading
import time

from .agent_proxy import TransparentAgentProxy
from .codex_rollout import (
    CodexRolloutObservation,
    codex_rollout_paths,
    read_rollout_session_meta,
    read_rollout_updates,
)


def _parse_shell_command_output(raw_output: str) -> tuple[dict[str, object], str | None]:
    text = str(raw_output or "")
    lines = text.splitlines()
    exit_code: int | None = None
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    section: str | None = None
    for line in lines:
        if line.startswith("Exit code:"):
            try:
                exit_code = int(line.split(":", 1)[1].strip())
            except ValueError:
                exit_code = None
            continue
        if line == "Output:":
            section = "stdout"
            continue
        if line == "Stderr:":
            section = "stderr"
            continue
        if section == "stdout":
            stdout_lines.append(line)
        elif section == "stderr":
            stderr_lines.append(line)
    result = {
        "raw_output": text,
    }
    if exit_code is not None:
        result["exit_code"] = exit_code
    if stdout_lines:
        result["stdout"] = "\n".join(stdout_lines)
    if stderr_lines:
        result["stderr"] = "\n".join(stderr_lines)
    error = "\n".join(stderr_lines).strip() or None
    if exit_code not in (None, 0) and error is None:
        error = text.strip() or f"command exited with {exit_code}"
    return result, error


@dataclass
class CodexRolloutWatcher:
    proxy: TransparentAgentProxy
    lock: threading.Lock
    session_id: str
    run_id: str
    actor_id: str = "codex"
    workspace_root: Path | None = None
    poll_interval_sec: float = 0.05
    _offsets: dict[str, int] = field(default_factory=dict)
    _file_cwds: dict[str, str | None] = field(default_factory=dict)
    _seeded: bool = False

    def seed_existing(self) -> None:
        if self._seeded:
            return
        for path in codex_rollout_paths(self.session_id):
            try:
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(0, 2)
                    self._offsets[str(path)] = handle.tell()
            except OSError:
                continue
            meta = read_rollout_session_meta(path)
            default_cwd = str(self.workspace_root) if self.workspace_root is not None else None
            self._file_cwds[str(path)] = meta.cwd if meta is not None else default_cwd
        self._seeded = True

    def watch(self, stop_event: threading.Event) -> None:
        if not self.session_id:
            return
        self.seed_existing()
        while not stop_event.is_set():
            self.tick()
            stop_event.wait(self.poll_interval_sec)

    def tick(self) -> None:
        paths = list(reversed(codex_rollout_paths(self.session_id)))
        default_cwd = str(self.workspace_root) if self.workspace_root is not None else None
        for path in paths:
            key = str(path)
            if key not in self._offsets:
                self._offsets[key] = 0
                meta = read_rollout_session_meta(path)
                self._file_cwds[key] = meta.cwd if meta is not None else default_cwd
            observations, next_offset, next_cwd = read_rollout_updates(
                path,
                start_offset=self._offsets.get(key, 0),
                default_cwd=self._file_cwds.get(key) or default_cwd,
            )
            self._offsets[key] = next_offset
            self._file_cwds[key] = next_cwd or self._file_cwds.get(key) or default_cwd
            for item in observations:
                self._handle_observation(item)

    def _handle_observation(self, item: CodexRolloutObservation) -> None:
        with self.lock:
            if item.kind == "function_call":
                self.proxy.observe_external_tool_start(
                    session_id=self.session_id,
                    run_id=self.run_id,
                    actor_id=self.actor_id,
                    external_call_id=item.call_id,
                    tool_name=str(item.tool_name or ""),
                    params=dict(item.params or {}),
                    cwd=Path(item.cwd) if item.cwd else self.workspace_root,
                    channel="codex-rollout-monitor",
                    policy_name="codex_rollout_monitor",
                    policy_version="v1",
                )
                return
            if item.kind != "function_call_output":
                return
            state = self.proxy._observed_tool_calls.get((self.session_id, item.call_id))
            tool_name = str((state or {}).get("tool_name") or "")
            result = {
                "raw_output": str(item.output or ""),
                "external_call_id": item.call_id,
                "observation_source": "codex-rollout-monitor",
            }
            error = None
            if tool_name == "system.run":
                parsed_result, parsed_error = _parse_shell_command_output(str(item.output or ""))
                result.update(parsed_result)
                error = parsed_error
            self.proxy.observe_external_tool_completion(
                session_id=self.session_id,
                external_call_id=item.call_id,
                result=result,
                error=error,
            )


def start_codex_rollout_watcher(
    *,
    proxy: TransparentAgentProxy,
    lock: threading.Lock,
    session_id: str,
    run_id: str,
    actor_id: str = "codex",
    workspace_root: Path | None = None,
    poll_interval_sec: float = 0.05,
) -> tuple[threading.Event, threading.Thread]:
    watcher = CodexRolloutWatcher(
        proxy=proxy,
        lock=lock,
        session_id=session_id,
        run_id=run_id,
        actor_id=actor_id,
        workspace_root=workspace_root,
        poll_interval_sec=poll_interval_sec,
    )
    stop_event = threading.Event()
    thread = threading.Thread(target=watcher.watch, args=(stop_event,), daemon=True)
    thread.start()
    return stop_event, thread


__all__ = [
    "CodexRolloutWatcher",
    "start_codex_rollout_watcher",
]
