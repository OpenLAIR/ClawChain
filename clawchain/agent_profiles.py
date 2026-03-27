from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ShellAgentProfile:
    agent_id: str
    profile_id: str
    cli_command: str
    directory_name: str
    env_file_stem: str
    launcher_stem: str
    shim_dir_name: str
    default_session_id: str
    default_run_id: str
    watcher_kind: str | None = None
    resume_style: str = "flag"
    resume_token: str = "-r"
    workspace_flag: str | None = None
    display_name: str = ""
    command_stems: tuple[str, ...] = ()

    def env_file_name(self, *, windows: bool) -> str:
        suffix = '.cmd' if windows else '.env'
        return f'{self.env_file_stem}{suffix}'

    def launcher_file_name(self, *, windows: bool) -> str:
        return f'{self.launcher_stem}.cmd' if windows else self.launcher_stem

    def directory_candidates(self) -> tuple[str, ...]:
        values = []
        for value in (self.agent_id, self.profile_id, self.directory_name):
            token = str(value or '').strip()
            if token and token not in values:
                values.append(token)
        return tuple(values)

    def initial_launch_args(self, workspace_root: str | Path | None) -> tuple[str, ...]:
        if workspace_root is None or not self.workspace_flag:
            return ()
        return (self.workspace_flag, str(workspace_root))

    def resume_args(self, session_id: str) -> tuple[str, ...]:
        token = str(session_id or '').strip()
        if self.resume_style == 'continue':
            return (self.resume_token,) if self.resume_token else ()
        if not token:
            return ()
        if self.resume_style == 'subcommand':
            return (self.resume_token, token)
        return (self.resume_token, token)


_SHELL_AGENT_PROFILES: tuple[ShellAgentProfile, ...] = (
    ShellAgentProfile(
        agent_id='codex',
        profile_id='codex-cli',
        cli_command='codex',
        directory_name='codex',
        env_file_stem='codex-proxy-env',
        launcher_stem='codex-with-clawchain',
        shim_dir_name='codex-shims',
        default_session_id='codex-session',
        default_run_id='codex-run',
        watcher_kind='codex-rollout',
        resume_style='subcommand',
        resume_token='resume',
        workspace_flag='-C',
        display_name='Codex CLI',
        command_stems=('codex', 'codex-with-clawchain'),
    ),
    ShellAgentProfile(
        agent_id='claude-code',
        profile_id='claude-code',
        cli_command='claude',
        directory_name='claude-code',
        env_file_stem='claude-proxy-env',
        launcher_stem='claude-with-clawchain',
        shim_dir_name='claude-shims',
        default_session_id='claude-session',
        default_run_id='claude-run',
        watcher_kind=None,
        resume_style='continue',
        resume_token='--continue',
        workspace_flag=None,
        display_name='Claude Code',
        command_stems=('claude', 'claude-with-clawchain'),
    ),
)

_PROFILE_BY_AGENT = {profile.agent_id: profile for profile in _SHELL_AGENT_PROFILES}
_PROFILE_ALIASES: dict[str, str] = {}
for profile in _SHELL_AGENT_PROFILES:
    for alias in {
        profile.agent_id,
        profile.profile_id,
        profile.directory_name,
        profile.cli_command,
    }:
        token = str(alias or '').strip().lower()
        if token:
            _PROFILE_ALIASES[token] = profile.agent_id


def get_shell_agent_profile(raw: str | None) -> ShellAgentProfile | None:
    token = str(raw or '').strip().lower()
    if not token:
        return None
    canonical = _PROFILE_ALIASES.get(token)
    if canonical is None:
        return None
    return _PROFILE_BY_AGENT.get(canonical)


def normalize_shell_agent_id(raw: str | None) -> str | None:
    profile = get_shell_agent_profile(raw)
    return profile.agent_id if profile is not None else None


def iter_shell_agent_profiles() -> tuple[ShellAgentProfile, ...]:
    return _SHELL_AGENT_PROFILES


def shell_agent_supports_prepare(raw: str | None) -> bool:
    return get_shell_agent_profile(raw) is not None


def shell_agent_default_capture_mode(raw: str | None) -> str:
    profile = get_shell_agent_profile(raw)
    if profile is None:
        return 'pending'
    return 'rollout-observed' if profile.watcher_kind == 'codex-rollout' else 'launcher-routed'


__all__ = [
    'ShellAgentProfile',
    'get_shell_agent_profile',
    'iter_shell_agent_profiles',
    'normalize_shell_agent_id',
    'shell_agent_default_capture_mode',
    'shell_agent_supports_prepare',
]
