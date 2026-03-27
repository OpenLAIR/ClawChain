from __future__ import annotations

import json
from pathlib import Path

from .shell_agent_integration import ShellAgentIntegrationArtifacts, bootstrap_shell_agent_integration

CodexIntegrationArtifacts = ShellAgentIntegrationArtifacts


def bootstrap_codex_cli_integration(
    *,
    account_id: str,
    password: str,
    workspace_root: Path | None,
    base_dir: Path,
    session_id: str = 'codex-session',
    run_id: str = 'codex-run',
    start_service: bool = True,
    git_context_mode: str = 'bind-existing-git',
) -> CodexIntegrationArtifacts:
    return bootstrap_shell_agent_integration(
        agent_id='codex',
        account_id=account_id,
        password=password,
        workspace_root=workspace_root,
        base_dir=base_dir,
        session_id=session_id,
        run_id=run_id,
        start_service=start_service,
        git_context_mode=git_context_mode,
    )


def main(
    *,
    account_id: str,
    password: str,
    workspace_root: Path | None = None,
    base_dir: Path,
    session_id: str = 'codex-session',
    run_id: str = 'codex-run',
    start_service: bool = True,
    git_context_mode: str = 'bind-existing-git',
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
    'CodexIntegrationArtifacts',
    'bootstrap_codex_cli_integration',
    'main',
]
