from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from pprint import pprint
import sys

from .agent_proxy_config import AgentProxyStoredConfig

try:
    from .benchmark.real_agents import build_real_agent_integration_plan
except ModuleNotFoundError:
    from dataclasses import dataclass as _fallback_dataclass

    @_fallback_dataclass(frozen=True)
    class _FallbackIntegrationPlan:
        primary_scenarios: tuple[str, ...]
        success_checks: tuple[str, ...]

    def build_real_agent_integration_plan(profile_id: str) -> _FallbackIntegrationPlan:
        return _FallbackIntegrationPlan(
            primary_scenarios=(f"Prepare {profile_id} through the ClawChain proxy",),
            success_checks=(
                "proxy config written",
                "service start command available",
                "service status command available",
            ),
        )


@dataclass(frozen=True)
class RealAgentCommandTemplate:
    name: str
    description: str
    command: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "description": self.description,
            "command": self.command,
        }


@dataclass(frozen=True)
class RealAgentHarnessPlan:
    profile_id: str
    workspace_root: str
    base_dir: str
    config_path: str
    service_state_path: str
    command_templates: tuple[RealAgentCommandTemplate, ...]
    primary_scenarios: tuple[str, ...]
    success_checks: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "workspace_root": self.workspace_root,
            "base_dir": self.base_dir,
            "config_path": self.config_path,
            "service_state_path": self.service_state_path,
            "command_templates": [item.to_dict() for item in self.command_templates],
            "primary_scenarios": list(self.primary_scenarios),
            "success_checks": list(self.success_checks),
        }


def _quote(value: str | Path) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def _build_common_harness_plan(
    *,
    profile_id: str,
    account_id: str,
    password: str,
    workspace_root: Path,
    base_dir: Path | None = None,
    session_id: str,
    run_id: str,
) -> RealAgentHarnessPlan:
    integration_plan = build_real_agent_integration_plan(profile_id)
    resolved_base_dir = (base_dir or (Path.home() / ".clawchain-agent" / account_id)).expanduser()
    stored = AgentProxyStoredConfig(
        account_id=account_id,
        password=password,
        base_dir=str(resolved_base_dir),
        path_hint=str(workspace_root.expanduser().resolve()),
        default_session_id=session_id,
        default_run_id=run_id,
    )
    config_path = resolved_base_dir / "agent-proxy.config.json"
    state_path = stored.service_state_path()
    commands = (
        RealAgentCommandTemplate(
            name="config-init",
            description="Initialize the local ClawChain proxy config for this agent workspace.",
            command=(
                "python -m clawchain.agent_proxy_cli config-init "
                f"{_quote(account_id)} {_quote(password)} "
                f"--config {_quote(config_path)} "
                f"--root-dir {_quote(resolved_base_dir)} "
                f"--workspace {_quote(stored.workspace_root)} "
                f"--session {_quote(session_id)} "
                f"--run {_quote(run_id)}"
            ),
        ),
        RealAgentCommandTemplate(
            name="service-start",
            description="Start the long-running local ClawChain proxy service.",
            command=(
                "python -m clawchain.agent_proxy_cli service-start "
                f"{_quote(config_path)}"
            ),
        ),
        RealAgentCommandTemplate(
            name="service-status",
            description="Verify that the proxy service is running and responsive.",
            command=(
                "python -m clawchain.agent_proxy_cli service-status "
                f"{_quote(config_path)}"
            ),
        ),
    )
    return RealAgentHarnessPlan(
        profile_id=profile_id,
        workspace_root=str(workspace_root.expanduser().resolve()),
        base_dir=str(resolved_base_dir),
        config_path=str(config_path),
        service_state_path=str(state_path),
        command_templates=commands,
        primary_scenarios=integration_plan.primary_scenarios,
        success_checks=integration_plan.success_checks,
    )


def build_codex_cli_harness_plan(
    *,
    account_id: str,
    password: str,
    workspace_root: Path,
    base_dir: Path | None = None,
    session_id: str = "codex-session",
    run_id: str = "codex-run",
) -> RealAgentHarnessPlan:
    base = _build_common_harness_plan(
        profile_id="codex-cli",
        account_id=account_id,
        password=password,
        workspace_root=workspace_root,
        base_dir=base_dir,
        session_id=session_id,
        run_id=run_id,
    )
    state_path = Path(base.service_state_path)
    commands = base.command_templates + (
        RealAgentCommandTemplate(
            name="codex-wrapper-example",
            description="Example shell-style Codex action routed through the proxy wrapper path.",
            command=(
                "python -m clawchain.agent_proxy_cli "
                f"{_quote(account_id)} {_quote(password)} {_quote(session_id)} {_quote(run_id)} "
                f"--root-dir {_quote(base.base_dir)} -- "
                "bash -lc "
                + _quote("printf 'Codex proxy ready\\n'")
            ),
        ),
        RealAgentCommandTemplate(
            name="codex-tool-json-example",
            description="Example structured tool action routed through the long-running daemon for Codex-style tool mediation.",
            command=(
                "python -m clawchain.agent_proxy_cli daemon-tool-json "
                f"$(python - <<'PY'\n"
                "import json, pathlib\n"
                f"state = json.loads(pathlib.Path({_quote(state_path)}).read_text())\n"
                "print(state['socket_path'])\n"
                "PY\n"
                ") <<'JSON'\n"
                + json.dumps(
                    {
                        "session_id": session_id,
                        "run_id": run_id,
                        "tool_name": "fs.delete",
                        "params": {"path": str(Path(workspace_root).resolve() / "danger.txt")},
                        "actor_id": account_id,
                        "cwd": str(Path(workspace_root).resolve()),
                    },
                    ensure_ascii=True,
                    indent=2,
                )
                + "\nJSON"
            ),
        ),
    )
    return RealAgentHarnessPlan(
        profile_id=base.profile_id,
        workspace_root=base.workspace_root,
        base_dir=base.base_dir,
        config_path=base.config_path,
        service_state_path=base.service_state_path,
        command_templates=commands,
        primary_scenarios=base.primary_scenarios,
        success_checks=base.success_checks,
    )


def build_real_agent_harness_plan(
    profile_id: str,
    *,
    account_id: str,
    password: str,
    workspace_root: Path,
    base_dir: Path | None = None,
    session_id: str | None = None,
    run_id: str | None = None,
) -> RealAgentHarnessPlan:
    if profile_id == "codex-cli":
        return build_codex_cli_harness_plan(
            account_id=account_id,
            password=password,
            workspace_root=workspace_root,
            base_dir=base_dir,
            session_id=session_id or "codex-session",
            run_id=run_id or "codex-run",
        )
    return _build_common_harness_plan(
        profile_id=profile_id,
        account_id=account_id,
        password=password,
        workspace_root=workspace_root,
        base_dir=base_dir,
        session_id=session_id or f"{profile_id}-session",
        run_id=run_id or f"{profile_id}-run",
    )


def main(
    *,
    profile_id: str = "codex-cli",
    account_id: str = "demo-user",
    password: str = "demo-password",
    workspace_root: Path | None = None,
    base_dir: Path | None = None,
    emit: bool = True,
) -> dict[str, object]:
    plan = build_real_agent_harness_plan(
        profile_id,
        account_id=account_id,
        password=password,
        workspace_root=workspace_root or Path.cwd(),
        base_dir=base_dir,
    )
    payload = plan.to_dict()
    if emit:
        pprint(payload)
    return payload


if __name__ == "__main__":
    argv = sys.argv[1:]
    arg_profile = argv[0] if argv else "codex-cli"
    arg_account = argv[1] if len(argv) > 1 else "demo-user"
    arg_password = argv[2] if len(argv) > 2 else "demo-password"
    arg_workspace = Path(argv[3]) if len(argv) > 3 else Path.cwd()
    main(
        profile_id=arg_profile,
        account_id=arg_account,
        password=arg_password,
        workspace_root=arg_workspace,
    )


__all__ = [
    "RealAgentCommandTemplate",
    "RealAgentHarnessPlan",
    "build_codex_cli_harness_plan",
    "build_real_agent_harness_plan",
    "main",
]
