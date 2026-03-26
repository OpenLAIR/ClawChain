from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys

from .agent_proxy_config import AgentProxyStoredConfig, write_agent_proxy_config
from .platform_support import codex_env_path, codex_launcher_path, is_windows


@dataclass(frozen=True)
class CodexIntegrationArtifacts:
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
            "config_path": self.config_path,
            "service_state_path": self.service_state_path,
            "launcher_path": self.launcher_path,
            "env_path": self.env_path,
            "shim_dir": self.shim_dir,
            "wrapped_commands": list(self.wrapped_commands),
            "path_hint": self.path_hint,
            "base_dir": self.base_dir,
        }


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    if not is_windows():
        path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _shell_quote(value: str | Path) -> str:
    return shlex.quote(str(value))


def _cmd_quote(value: str | Path) -> str:
    return subprocess.list2cmdline([str(value)])


def _package_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _git_for_windows_root() -> Path | None:
    git_binary = shutil.which("git") or shutil.which("git.exe")
    if git_binary is None:
        return None
    git_path = Path(git_binary).resolve()
    root = git_path.parent.parent
    if (root / "usr" / "bin").exists():
        return root
    return None


def _resolve_wrapped_binary(command_name: str) -> str | None:
    if not is_windows():
        return shutil.which(command_name)
    if command_name == "git":
        return shutil.which("git") or shutil.which("git.exe")
    git_root = _git_for_windows_root()
    if git_root is not None:
        candidate = git_root / "usr" / "bin" / f"{command_name}.exe"
        if candidate.exists():
            return str(candidate)
    return shutil.which(command_name) or shutil.which(f"{command_name}.exe")


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
            "@echo off",
            "setlocal EnableExtensions",
        ]
        if git_risky_only:
            lines.extend(
                [
                    'if /I "%~1"=="reset" if /I "%~2"=="--hard" goto monitor',
                    'if /I "%~1"=="clean" goto monitor',
                    f"call {_cmd_quote(real_binary)} %*",
                    "exit /b %ERRORLEVEL%",
                    ":monitor",
                ]
            )
        if passthrough_all:
            lines.extend(
                [
                    f'set "PYTHONPATH={package_root};%PYTHONPATH%"',
                    "call "
                    + _cmd_quote(python_executable)
                    + " -m clawchain.agent_proxy_cli "
                    + _cmd_quote(account_id)
                    + " "
                    + _cmd_quote(password)
                    + " "
                    + _cmd_quote(session_id)
                    + " "
                    + _cmd_quote(run_id)
                    + " --root-dir "
                    + _cmd_quote(root_dir)
                    + " --passthrough -- "
                    + _cmd_quote(real_binary)
                    + " %*",
                    "exit /b %ERRORLEVEL%",
                ]
            )
        return "\r\n".join(lines) + "\r\n"

    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
    ]
    if git_risky_only:
        lines.extend(
            [
                'if [[ "${1:-}" == "reset" && "${2:-}" == "--hard" ]]; then',
                "  :",
                'elif [[ "${1:-}" == "clean" ]]; then',
                "  :",
                "else",
                f"  exec {_shell_quote(real_binary)} \"$@\"",
                "fi",
            ]
        )
    if passthrough_all:
        lines.append(
            "export PYTHONPATH="
            + _shell_quote(package_root)
            + ':${PYTHONPATH:-}'
        )
        lines.append(
            "exec "
            + _shell_quote(python_executable)
            + " -m clawchain.agent_proxy_cli "
            + _shell_quote(account_id)
            + " "
            + _shell_quote(password)
            + " "
            + _shell_quote(session_id)
            + " "
            + _shell_quote(run_id)
            + " --root-dir "
            + _shell_quote(root_dir)
            + " --passthrough -- "
            + _shell_quote(real_binary)
            + " \"$@\""
        )
    return "\n".join(lines) + "\n"


def bootstrap_codex_cli_integration(
    *,
    account_id: str,
    password: str,
    workspace_root: Path | None,
    base_dir: Path,
    session_id: str = "codex-session",
    run_id: str = "codex-run",
    start_service: bool = True,
    git_context_mode: str = "bind-existing-git",
) -> CodexIntegrationArtifacts:
    resolved_workspace = workspace_root.expanduser().resolve() if workspace_root is not None else None
    base_dir = base_dir.expanduser().resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    stored = AgentProxyStoredConfig(
        account_id=account_id,
        password=password,
        base_dir=str(base_dir),
        path_hint=str(resolved_workspace) if resolved_workspace is not None else None,
        default_session_id=session_id,
        default_run_id=run_id,
        git_context_mode=git_context_mode,
    )
    config_path = base_dir / "agent-proxy.config.json"
    write_agent_proxy_config(config_path, stored)

    shim_dir = base_dir / "codex-shims"
    shim_dir.mkdir(parents=True, exist_ok=True)
    python_exec = sys.executable
    package_root = _package_root()
    wrapped_commands = ("rm", "mv", "find", "chmod", "chown", "git")
    for command_name in wrapped_commands:
        real_binary = _resolve_wrapped_binary(command_name)
        if real_binary is None:
            raise RuntimeError(f"Unable to resolve system binary for {command_name}")
        script = _shim_script(
            command_name=command_name,
            real_binary=real_binary,
            python_executable=python_exec,
            account_id=account_id,
            password=password,
            session_id=session_id,
            run_id=run_id,
            root_dir=base_dir,
            package_root=package_root,
            git_risky_only=(command_name == "git"),
        )
        shim_name = f"{command_name}.cmd" if is_windows() else command_name
        _write_executable(shim_dir / shim_name, script)

    env_path = codex_env_path(base_dir)
    launcher_path = codex_launcher_path(base_dir)
    if is_windows():
        env_path.write_text(
            "\r\n".join(
                [
                    "@echo off",
                    f'set "CLAWCHAIN_AGENT_ACCOUNT_ID={account_id}"',
                    f'set "CLAWCHAIN_AGENT_PASSWORD={password}"',
                    f'set "CLAWCHAIN_AGENT_PROXY_CONFIG={config_path}"',
                    f'set "CLAWCHAIN_AGENT_SESSION_ID={session_id}"',
                    f'set "CLAWCHAIN_AGENT_RUN_ID={run_id}"',
                    f'set "CLAWCHAIN_AGENT_ROOT_DIR={base_dir}"',
                    f'set "CLAWCHAIN_CODEX_SHIM_DIR={shim_dir}"',
                    f'set "PYTHONPATH={package_root};%PYTHONPATH%"',
                    f'set "PATH={shim_dir};%PATH%"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        _write_executable(
            launcher_path,
            "\r\n".join(
                [
                    "@echo off",
                    "setlocal EnableExtensions",
                    f"call {_cmd_quote(env_path)}",
                    "call codex.cmd %*",
                    "exit /b %ERRORLEVEL%",
                    "",
                ]
            ),
        )
    else:
        env_path.write_text(
            "\n".join(
                [
                    f'export CLAWCHAIN_AGENT_ACCOUNT_ID={_shell_quote(account_id)}',
                    f'export CLAWCHAIN_AGENT_PASSWORD={_shell_quote(password)}',
                    f'export CLAWCHAIN_AGENT_PROXY_CONFIG={_shell_quote(str(config_path))}',
                    f'export CLAWCHAIN_AGENT_SESSION_ID={_shell_quote(session_id)}',
                    f'export CLAWCHAIN_AGENT_RUN_ID={_shell_quote(run_id)}',
                    f'export CLAWCHAIN_AGENT_ROOT_DIR={_shell_quote(base_dir)}',
                    f'export CLAWCHAIN_CODEX_SHIM_DIR={_shell_quote(shim_dir)}',
                    f'export PYTHONPATH={_shell_quote(str(package_root))}:${{PYTHONPATH:-}}',
                    'export PATH="$CLAWCHAIN_CODEX_SHIM_DIR:$PATH"',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        _write_executable(
            launcher_path,
            "\n".join(
                [
                    "#!/usr/bin/env bash",
                    "set -euo pipefail",
                    f"source {_shell_quote(env_path)}",
                    "exec codex \"$@\"",
                    "",
                ]
            ),
        )

    if start_service:
        subprocess.run(
            [python_exec, "-m", "clawchain.agent_proxy_cli", "service-start", str(config_path)],
            check=True,
            capture_output=True,
            text=True,
        )

    return CodexIntegrationArtifacts(
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
    account_id: str,
    password: str,
    workspace_root: Path | None = None,
    base_dir: Path,
    session_id: str = "codex-session",
    run_id: str = "codex-run",
    start_service: bool = True,
    git_context_mode: str = "bind-existing-git",
    emit: bool = True,
) -> dict[str, object]:
    artifacts = bootstrap_codex_cli_integration(
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
    "CodexIntegrationArtifacts",
    "bootstrap_codex_cli_integration",
    "main",
]
