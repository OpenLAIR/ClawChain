from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys
from typing import Sequence


def is_windows() -> bool:
    return os.name == "nt"


def is_macos() -> bool:
    return sys.platform == "darwin"


def codex_env_file_name() -> str:
    return "codex-proxy-env.cmd" if is_windows() else "codex-proxy.env"


def codex_launcher_file_name() -> str:
    return "codex-with-clawchain.cmd" if is_windows() else "codex-with-clawchain"


def monitored_handoff_file_name() -> str:
    return "enter-monitored-session.cmd" if is_windows() else "enter-monitored-session.sh"


def codex_env_path(base_dir: Path) -> Path:
    return Path(base_dir) / codex_env_file_name()


def codex_launcher_path(base_dir: Path) -> Path:
    return Path(base_dir) / codex_launcher_file_name()


def monitored_handoff_path(base_dir: Path) -> Path:
    return Path(base_dir) / monitored_handoff_file_name()


def command_display(parts: Sequence[str | Path]) -> str:
    values = [str(part) for part in parts]
    if is_windows():
        return subprocess.list2cmdline(values)
    return " ".join(shlex.quote(value) for value in values)


def script_command_parts(path: str | Path, *args: str, keep_open: bool = False) -> list[str]:
    if is_windows():
        return ["cmd.exe", "/d", "/k" if keep_open else "/c", str(path), *[str(arg) for arg in args]]
    return ["bash", str(path), *[str(arg) for arg in args]]


def script_command_display(path: str | Path, *args: str, keep_open: bool = False) -> str:
    return command_display(script_command_parts(path, *args, keep_open=keep_open))


def codex_command_matches(token: str) -> bool:
    cleaned = str(token or "").strip().strip("\"'")
    if not cleaned:
        return False
    name = Path(cleaned).name.lower()
    stem = Path(name).stem.lower()
    return name in {
        "codex",
        "codex.exe",
        "codex.cmd",
        "codex.ps1",
        "codex.bat",
        "codex-with-clawchain",
        "codex-with-clawchain.cmd",
    } or stem in {"codex", "codex-with-clawchain"}


__all__ = [
    "codex_command_matches",
    "codex_env_file_name",
    "codex_env_path",
    "codex_launcher_file_name",
    "codex_launcher_path",
    "command_display",
    "is_macos",
    "is_windows",
    "monitored_handoff_file_name",
    "monitored_handoff_path",
    "script_command_display",
    "script_command_parts",
]
