from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import shlex
import shutil
import stat
import subprocess
import sys

from .agent_profiles import get_shell_agent_profile
from .agent_proxy_config import AgentProxyStoredConfig, write_agent_proxy_config
from .platform_support import agent_env_path, agent_launcher_path, is_windows


@dataclass(frozen=True)
class ShellAgentIntegrationArtifacts:
    agent_id: str
    profile_id: str
    cli_command: str
    config_path: str
    service_state_path: str
    launcher_path: str
    env_path: str
    shim_dir: str
    wrapped_commands: tuple[str, ...]
    path_hint: str | None
    base_dir: str

    def to_dict(self) -> dict[str, object]:
        return {
            'agent_id': self.agent_id,
            'profile_id': self.profile_id,
            'cli_command': self.cli_command,
            'config_path': self.config_path,
            'service_state_path': self.service_state_path,
            'launcher_path': self.launcher_path,
            'env_path': self.env_path,
            'shim_dir': self.shim_dir,
            'wrapped_commands': list(self.wrapped_commands),
            'path_hint': self.path_hint,
            'base_dir': self.base_dir,
        }


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding='utf-8')
    if not is_windows():
        path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _shell_quote(value: str | Path) -> str:
    return shlex.quote(str(value))


def _cmd_quote(value: str | Path) -> str:
    return subprocess.list2cmdline([str(value)])


def _package_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _git_for_windows_root() -> Path | None:
    git_binary = shutil.which('git') or shutil.which('git.exe')
    if git_binary is None:
        return None
    git_path = Path(git_binary).resolve()
    root = git_path.parent.parent
    if (root / 'usr' / 'bin').exists():
        return root
    return None


def _resolve_wrapped_binary(command_name: str) -> str | None:
    if not is_windows():
        return shutil.which(command_name)
    if command_name == 'git':
        return shutil.which('git') or shutil.which('git.exe')
    git_root = _git_for_windows_root()
    if git_root is not None:
        candidate = git_root / 'usr' / 'bin' / f'{command_name}.exe'
        if candidate.exists():
            return str(candidate)
    return shutil.which(command_name) or shutil.which(f'{command_name}.exe')


def _shim_script(
    *,
    command_name: str,
    real_binary: str,
    python_executable: str,
    account_id: str,
    password: str,
    session_id: str,
    run_id: str,
    root_dir: Path,
    package_root: Path,
    passthrough_all: bool = True,
    git_risky_only: bool = False,
) -> str:
    if is_windows():
        lines = [
            '@echo off',
            'setlocal EnableExtensions',
        ]
        if git_risky_only:
            lines.extend(
                [
                    'if /I "%~1"=="reset" if /I "%~2"=="--hard" goto monitor',
                    'if /I "%~1"=="clean" goto monitor',
                    f'call {_cmd_quote(real_binary)} %*',
                    'exit /b %ERRORLEVEL%',
                    ':monitor',
                ]
            )
        if passthrough_all:
            lines.extend(
                [
                    f'set "PYTHONPATH={package_root};%PYTHONPATH%"',
                    'call '
                    + _cmd_quote(python_executable)
                    + ' -m clawchain.agent_proxy_cli '
                    + _cmd_quote(account_id)
                    + ' '
                    + _cmd_quote(password)
                    + ' '
                    + _cmd_quote(session_id)
                    + ' '
                    + _cmd_quote(run_id)
                    + ' --root-dir '
                    + _cmd_quote(root_dir)
                    + ' --passthrough -- '
                    + _cmd_quote(real_binary)
                    + ' %*',
                    'exit /b %ERRORLEVEL%',
                ]
            )
        return '\r\n'.join(lines) + '\r\n'

    lines = [
        '#!/usr/bin/env bash',
        'set -euo pipefail',
    ]
    if git_risky_only:
        lines.extend(
            [
                'if [[ "${1:-}" == "reset" && "${2:-}" == "--hard" ]]; then',
                '  :',
                'elif [[ "${1:-}" == "clean" ]]; then',
                '  :',
                'else',
                f'  exec {_shell_quote(real_binary)} "$@"',
                'fi',
            ]
        )
    if passthrough_all:
        lines.append('export PYTHONPATH=' + _shell_quote(package_root) + ':${PYTHONPATH:-}')
        lines.append(
            'exec '
            + _shell_quote(python_executable)
            + ' -m clawchain.agent_proxy_cli '
            + _shell_quote(account_id)
            + ' '
            + _shell_quote(password)
            + ' '
            + _shell_quote(session_id)
            + ' '
            + _shell_quote(run_id)
            + ' --root-dir '
            + _shell_quote(root_dir)
            + ' --passthrough -- '
            + _shell_quote(real_binary)
            + ' "$@"'
        )
    return '\n'.join(lines) + '\n'


def _windows_env_lines(
    *,
    profile_id: str,
    agent_id: str,
    cli_command: str,
    account_id: str,
    password: str,
    config_path: Path,
    session_id: str,
    run_id: str,
    base_dir: Path,
    shim_dir: Path,
    package_root: Path,
    workspace_root: Path | None,
) -> list[str]:
    lines = [
        '@echo off',
        f'set "CLAWCHAIN_AGENT_ID={agent_id}"',
        f'set "CLAWCHAIN_AGENT_PROFILE_ID={profile_id}"',
        f'set "CLAWCHAIN_AGENT_CLI_COMMAND={cli_command}"',
        f'set "CLAWCHAIN_AGENT_ACCOUNT_ID={account_id}"',
        f'set "CLAWCHAIN_AGENT_PASSWORD={password}"',
        f'set "CLAWCHAIN_AGENT_PROXY_CONFIG={config_path}"',
        f'set "CLAWCHAIN_AGENT_SESSION_ID={session_id}"',
        f'set "CLAWCHAIN_AGENT_RUN_ID={run_id}"',
        f'set "CLAWCHAIN_AGENT_ROOT_DIR={base_dir}"',
        f'set "CLAWCHAIN_AGENT_SHIM_DIR={shim_dir}"',
        f'set "PYTHONPATH={package_root};%PYTHONPATH%"',
        f'set "PATH={shim_dir};%PATH%"',
    ]
    if workspace_root is not None:
        lines.append(f'set "CLAWCHAIN_AGENT_WORKSPACE={workspace_root}"')
    if agent_id == 'codex':
        lines.append(f'set "CLAWCHAIN_CODEX_SHIM_DIR={shim_dir}"')
    return lines


def _windows_launcher_content(*, env_path: Path, cli_command: str) -> str:
    return '\r\n'.join(
        [
            '@echo off',
            'setlocal EnableExtensions',
            f'call {_cmd_quote(env_path)}',
            'if defined CLAWCHAIN_AGENT_WORKSPACE pushd "%CLAWCHAIN_AGENT_WORKSPACE%" >nul 2>nul',
            f'set "_CLAWCHAIN_AGENT_BIN={cli_command}.cmd"',
            'where /Q "%_CLAWCHAIN_AGENT_BIN%"',
            'if errorlevel 1 set "_CLAWCHAIN_AGENT_BIN=%CLAWCHAIN_AGENT_CLI_COMMAND%"',
            'call "%_CLAWCHAIN_AGENT_BIN%" %*',
            'set "_CLAWCHAIN_EXIT=%ERRORLEVEL%"',
            'if defined CLAWCHAIN_AGENT_WORKSPACE popd >nul 2>nul',
            'exit /b %_CLAWCHAIN_EXIT%',
            '',
        ]
    )


def _unix_env_lines(
    *,
    profile_id: str,
    agent_id: str,
    cli_command: str,
    account_id: str,
    password: str,
    config_path: Path,
    session_id: str,
    run_id: str,
    base_dir: Path,
    shim_dir: Path,
    package_root: Path,
    workspace_root: Path | None,
) -> list[str]:
    lines = [
        f'export CLAWCHAIN_AGENT_ID={_shell_quote(agent_id)}',
        f'export CLAWCHAIN_AGENT_PROFILE_ID={_shell_quote(profile_id)}',
        f'export CLAWCHAIN_AGENT_CLI_COMMAND={_shell_quote(cli_command)}',
        f'export CLAWCHAIN_AGENT_ACCOUNT_ID={_shell_quote(account_id)}',
        f'export CLAWCHAIN_AGENT_PASSWORD={_shell_quote(password)}',
        f'export CLAWCHAIN_AGENT_PROXY_CONFIG={_shell_quote(str(config_path))}',
        f'export CLAWCHAIN_AGENT_SESSION_ID={_shell_quote(session_id)}',
        f'export CLAWCHAIN_AGENT_RUN_ID={_shell_quote(run_id)}',
        f'export CLAWCHAIN_AGENT_ROOT_DIR={_shell_quote(base_dir)}',
        f'export CLAWCHAIN_AGENT_SHIM_DIR={_shell_quote(shim_dir)}',
        f'export PYTHONPATH={_shell_quote(str(package_root))}:${{PYTHONPATH:-}}',
        'export PATH="$CLAWCHAIN_AGENT_SHIM_DIR:$PATH"',
    ]
    if workspace_root is not None:
        lines.append(f'export CLAWCHAIN_AGENT_WORKSPACE={_shell_quote(str(workspace_root))}')
    if agent_id == 'codex':
        lines.append(f'export CLAWCHAIN_CODEX_SHIM_DIR={_shell_quote(shim_dir)}')
    return lines


def _unix_launcher_content(*, env_path: Path, cli_command: str) -> str:
    return '\n'.join(
        [
            '#!/usr/bin/env bash',
            'set -euo pipefail',
            f'source {_shell_quote(env_path)}',
            'if [[ -n "${CLAWCHAIN_AGENT_WORKSPACE:-}" ]]; then',
            '  cd "$CLAWCHAIN_AGENT_WORKSPACE"',
            'fi',
            f'exec {cli_command} "$@"',
            '',
        ]
    )


def bootstrap_shell_agent_integration(
    *,
    agent_id: str,
    account_id: str,
    password: str,
    workspace_root: Path | None,
    base_dir: Path,
    session_id: str | None = None,
    run_id: str | None = None,
    start_service: bool = True,
    git_context_mode: str = 'bind-existing-git',
) -> ShellAgentIntegrationArtifacts:
    profile = get_shell_agent_profile(agent_id)
    if profile is None:
        raise ValueError(f'unsupported shell agent: {agent_id}')
    resolved_workspace = workspace_root.expanduser().resolve() if workspace_root is not None else None
    base_dir = base_dir.expanduser().resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    session_token = str(session_id or profile.default_session_id)
    run_token = str(run_id or profile.default_run_id)
    stored = AgentProxyStoredConfig(
        account_id=account_id,
        password=password,
        agent_id=profile.agent_id,
        base_dir=str(base_dir),
        path_hint=str(resolved_workspace) if resolved_workspace is not None else None,
        default_session_id=session_token,
        default_run_id=run_token,
        git_context_mode=git_context_mode,
    )
    config_path = base_dir / 'agent-proxy.config.json'
    write_agent_proxy_config(config_path, stored)

    shim_dir = base_dir / profile.shim_dir_name
    shim_dir.mkdir(parents=True, exist_ok=True)
    python_exec = sys.executable
    package_root = _package_root()
    wrapped_commands = ('rm', 'mv', 'find', 'chmod', 'chown', 'git')
    for command_name in wrapped_commands:
        real_binary = _resolve_wrapped_binary(command_name)
        if real_binary is None:
            raise RuntimeError(f'Unable to resolve system binary for {command_name}')
        script = _shim_script(
            command_name=command_name,
            real_binary=real_binary,
            python_executable=python_exec,
            account_id=account_id,
            password=password,
            session_id=session_token,
            run_id=run_token,
            root_dir=base_dir,
            package_root=package_root,
            git_risky_only=(command_name == 'git'),
        )
        shim_name = f'{command_name}.cmd' if is_windows() else command_name
        _write_executable(shim_dir / shim_name, script)

    env_path = agent_env_path(base_dir, profile.agent_id)
    launcher_path = agent_launcher_path(base_dir, profile.agent_id)
    if is_windows():
        env_path.write_text(
            '\r\n'.join(
                _windows_env_lines(
                    profile_id=profile.profile_id,
                    agent_id=profile.agent_id,
                    cli_command=profile.cli_command,
                    account_id=account_id,
                    password=password,
                    config_path=config_path,
                    session_id=session_token,
                    run_id=run_token,
                    base_dir=base_dir,
                    shim_dir=shim_dir,
                    package_root=package_root,
                    workspace_root=resolved_workspace,
                )
                + ['']
            ),
            encoding='utf-8',
        )
        _write_executable(
            launcher_path,
            _windows_launcher_content(env_path=env_path, cli_command=profile.cli_command),
        )
    else:
        env_path.write_text(
            '\n'.join(
                _unix_env_lines(
                    profile_id=profile.profile_id,
                    agent_id=profile.agent_id,
                    cli_command=profile.cli_command,
                    account_id=account_id,
                    password=password,
                    config_path=config_path,
                    session_id=session_token,
                    run_id=run_token,
                    base_dir=base_dir,
                    shim_dir=shim_dir,
                    package_root=package_root,
                    workspace_root=resolved_workspace,
                )
            )
            + '\n',
            encoding='utf-8',
        )
        _write_executable(
            launcher_path,
            _unix_launcher_content(env_path=env_path, cli_command=profile.cli_command),
        )

    if start_service:
        subprocess.run(
            [python_exec, '-m', 'clawchain.agent_proxy_cli', 'service-start', str(config_path)],
            check=True,
            capture_output=True,
            text=True,
        )

    return ShellAgentIntegrationArtifacts(
        agent_id=profile.agent_id,
        profile_id=profile.profile_id,
        cli_command=profile.cli_command,
        config_path=str(config_path),
        service_state_path=str(stored.service_state_path()),
        launcher_path=str(launcher_path),
        env_path=str(env_path),
        shim_dir=str(shim_dir),
        wrapped_commands=wrapped_commands,
        path_hint=str(resolved_workspace) if resolved_workspace is not None else None,
        base_dir=str(base_dir),
    )


def main(
    *,
    agent_id: str,
    account_id: str,
    password: str,
    workspace_root: Path | None = None,
    base_dir: Path,
    session_id: str | None = None,
    run_id: str | None = None,
    start_service: bool = True,
    git_context_mode: str = 'bind-existing-git',
    emit: bool = True,
) -> dict[str, object]:
    artifacts = bootstrap_shell_agent_integration(
        agent_id=agent_id,
        account_id=account_id,
        password=password,
        workspace_root=workspace_root,
        base_dir=base_dir,
        session_id=session_id,
        run_id=run_id,
        start_service=start_service,
        git_context_mode=git_context_mode,
    )
    payload = artifacts.to_dict()
    if emit:
        print(json.dumps(payload, ensure_ascii=True, indent=2))
    return payload


__all__ = [
    'ShellAgentIntegrationArtifacts',
    'bootstrap_shell_agent_integration',
    'main',
]
