from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys
from typing import Sequence

from .agent_profiles import get_shell_agent_profile


def is_windows() -> bool:
    return os.name == 'nt'


def is_macos() -> bool:
    return sys.platform == 'darwin'


def agent_env_file_name(agent_id: str) -> str:
    profile = get_shell_agent_profile(agent_id)
    if profile is None:
        raise ValueError(f'unsupported shell agent: {agent_id}')
    return profile.env_file_name(windows=is_windows())


def agent_launcher_file_name(agent_id: str) -> str:
    profile = get_shell_agent_profile(agent_id)
    if profile is None:
        raise ValueError(f'unsupported shell agent: {agent_id}')
    return profile.launcher_file_name(windows=is_windows())


def monitored_handoff_file_name() -> str:
    return 'enter-monitored-session.cmd' if is_windows() else 'enter-monitored-session.sh'


def agent_env_path(base_dir: Path, agent_id: str) -> Path:
    return Path(base_dir) / agent_env_file_name(agent_id)


def agent_launcher_path(base_dir: Path, agent_id: str) -> Path:
    return Path(base_dir) / agent_launcher_file_name(agent_id)


def monitored_handoff_path(base_dir: Path) -> Path:
    return Path(base_dir) / monitored_handoff_file_name()


def command_display(parts: Sequence[str | Path]) -> str:
    values = [str(part) for part in parts]
    if is_windows():
        return subprocess.list2cmdline(values)
    return ' '.join(shlex.quote(value) for value in values)


def script_command_parts(path: str | Path, *args: str, keep_open: bool = False) -> list[str]:
    if is_windows():
        return ['cmd.exe', '/d', '/k' if keep_open else '/c', str(path), *[str(arg) for arg in args]]
    return ['bash', str(path), *[str(arg) for arg in args]]


def script_command_display(path: str | Path, *args: str, keep_open: bool = False) -> str:
    return command_display(script_command_parts(path, *args, keep_open=keep_open))


def agent_command_matches(agent_id: str, token: str) -> bool:
    profile = get_shell_agent_profile(agent_id)
    if profile is None:
        return False
    cleaned = str(token or '').strip().strip("\"'")
    if not cleaned:
        return False
    name = Path(cleaned).name.lower()
    stem = Path(name).stem.lower()
    allowed_names = {
        profile.cli_command.lower(),
        f'{profile.cli_command.lower()}.exe',
        f'{profile.cli_command.lower()}.cmd',
        f'{profile.cli_command.lower()}.ps1',
        f'{profile.cli_command.lower()}.bat',
        profile.launcher_file_name(windows=False).lower(),
        profile.launcher_file_name(windows=True).lower(),
    }
    allowed_stems = {value.lower() for value in profile.command_stems}
    return name in allowed_names or stem in allowed_stems


def codex_env_file_name() -> str:
    return agent_env_file_name('codex')


def codex_launcher_file_name() -> str:
    return agent_launcher_file_name('codex')


def codex_env_path(base_dir: Path) -> Path:
    return agent_env_path(base_dir, 'codex')


def codex_launcher_path(base_dir: Path) -> Path:
    return agent_launcher_path(base_dir, 'codex')


def codex_command_matches(token: str) -> bool:
    return agent_command_matches('codex', token)


__all__ = [
    'agent_command_matches',
    'agent_env_file_name',
    'agent_env_path',
    'agent_launcher_file_name',
    'agent_launcher_path',
    'codex_command_matches',
    'codex_env_file_name',
    'codex_env_path',
    'codex_launcher_file_name',
    'codex_launcher_path',
    'command_display',
    'is_macos',
    'is_windows',
    'monitored_handoff_file_name',
    'monitored_handoff_path',
    'script_command_display',
    'script_command_parts',
]
