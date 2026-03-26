"""Session lifecycle state machine for ClawChain agent monitoring."""
from __future__ import annotations

from enum import Enum
import os
import time
from typing import NamedTuple, TypedDict


class SessionState(str, Enum):
    UNMANAGED = "unmanaged"
    ENROLLING = "enrolling"
    PREPARED = "prepared"
    MONITORED = "monitored"
    TERMINATED = "terminated"
    FAILED = "failed"


VALID_TRANSITIONS: dict[SessionState, frozenset[SessionState]] = {
    SessionState.UNMANAGED: frozenset({SessionState.ENROLLING}),
    SessionState.ENROLLING: frozenset({SessionState.PREPARED, SessionState.FAILED}),
    SessionState.PREPARED: frozenset({SessionState.MONITORED, SessionState.FAILED}),
    SessionState.MONITORED: frozenset({SessionState.TERMINATED, SessionState.FAILED}),
    SessionState.TERMINATED: frozenset({SessionState.UNMANAGED}),
    SessionState.FAILED: frozenset({SessionState.UNMANAGED}),
}


class StateTransition(NamedTuple):
    from_state: SessionState
    to_state: SessionState
    timestamp_ms: int
    reason: str


class SessionStateError(Exception):
    def __init__(self, from_state: SessionState, to_state: SessionState, reason: str = "") -> None:
        self.from_state = from_state
        self.to_state = to_state
        detail = f": {reason}" if reason else ""
        super().__init__(
            f"invalid session state transition {from_state.value} -> {to_state.value}{detail}"
        )


def validate_transition(from_state: SessionState, to_state: SessionState) -> bool:
    allowed = VALID_TRANSITIONS.get(from_state, frozenset())
    return to_state in allowed


def transition(
    from_state: SessionState,
    to_state: SessionState,
    *,
    reason: str = "",
) -> StateTransition:
    if not validate_transition(from_state, to_state):
        raise SessionStateError(from_state, to_state, reason)
    return StateTransition(
        from_state=from_state,
        to_state=to_state,
        timestamp_ms=int(time.time() * 1000),
        reason=reason,
    )


def resolve_state_from_registry(entry: dict[str, object]) -> SessionState:
    raw = str(entry.get("session_state") or "")
    try:
        return SessionState(raw)
    except ValueError:
        if entry.get("config_path"):
            return SessionState.PREPARED
        return SessionState.UNMANAGED


def safe_transition(
    from_state: SessionState,
    to_state: SessionState,
    *,
    reason: str = "",
) -> StateTransition | None:
    if validate_transition(from_state, to_state):
        return StateTransition(
            from_state=from_state,
            to_state=to_state,
            timestamp_ms=int(time.time() * 1000),
            reason=reason,
        )
    return None


class SessionRegistryEntry(TypedDict, total=False):
    agent_id: str
    session_id: str
    session_name: str
    session_fingerprint: str | None
    path_hint: str | None
    config_path: str | None
    session_state: str
    tracked_pids: list[int]
    last_seen_ts_ms: int
    capture_mode: str
    attach_command: str
    controlled_session_name: str
    handoff_command: str
    handoff_script_path: str


def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            access = 0x1000  # PROCESS_QUERY_LIMITED_INFORMATION
            handle = kernel32.OpenProcess(access, False, pid)
            if handle:
                try:
                    exit_code = ctypes.c_ulong()
                    if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                        return int(exit_code.value) == 259  # STILL_ACTIVE
                    return True
                finally:
                    kernel32.CloseHandle(handle)
            return ctypes.get_last_error() == 5  # ERROR_ACCESS_DENIED
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def detect_stale_pids(tracked_pids: list[int]) -> tuple[list[int], list[int]]:
    alive: list[int] = []
    stale: list[int] = []
    for pid in tracked_pids:
        if is_pid_alive(pid):
            alive.append(pid)
        else:
            stale.append(pid)
    return alive, stale


__all__ = [
    "SessionRegistryEntry",
    "SessionState",
    "SessionStateError",
    "StateTransition",
    "VALID_TRANSITIONS",
    "detect_stale_pids",
    "is_pid_alive",
    "resolve_state_from_registry",
    "safe_transition",
    "transition",
    "validate_transition",
]
