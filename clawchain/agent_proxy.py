from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
import hashlib
import hmac
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile
import threading
import time
import uuid

from .canonical.events import CanonicalEvent, EventType
from .runtime.anchor import (
    EvmAnchorBackend,
    EvmAnchorConfig,
    LocalAnchorBackend,
    RpcEvmBroadcaster,
    load_evm_deployment_manifest,
    verify_evm_deployment_manifest,
)
from .runtime.remote import LocalAppendOnlyEvidenceSink, RemoteEvidenceSink, UnixSocketEvidenceSink
from .runtime.sidecar_service import SidecarServiceConfig, build_sidecar_unix_server
from .system import ClawChainConfig, ClawChainSystem


def _default_base_dir(account_id: str) -> Path:
    return Path.home() / ".clawchain-agent" / account_id


def _socket_path_for(root: Path) -> Path:
    candidate = root / "sidecar.sock"
    if len(str(candidate)) <= 96:
        return candidate
    return Path(tempfile.gettempdir()) / f"occp-{uuid.uuid4().hex[:12]}.sock"


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _derive_secret(*, account_id: str, password: str, label: str) -> str:
    material = f"{account_id}:{label}".encode("utf-8")
    return hmac.new(password.encode("utf-8"), material, hashlib.sha256).hexdigest()


def _default_deployer_private_key() -> str:
    return (
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )


def _run_git_probe(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def _bootstrap_local_evm_manifest(base_dir: Path) -> tuple[Path | None, subprocess.Popen[str] | None]:
    if os.name == "nt":
        return None, None
    manifest_path = base_dir / "deployment.json"
    if manifest_path.exists():
        try:
            existing = load_evm_deployment_manifest(manifest_path)
            if verify_evm_deployment_manifest(existing).ok:
                return manifest_path, None
        except Exception:  # noqa: BLE001
            pass
    root = _project_root()
    start_script = root / "scripts" / "start_local_devnet.sh"
    deploy_script = root / "scripts" / "deploy_commitment_anchor.sh"
    if not start_script.exists() or not deploy_script.exists():
        return None, None
    env = os.environ.copy()
    env.setdefault("CLAWCHAIN_EVM_MANIFEST_PATH", str(manifest_path))
    env.setdefault("CLAWCHAIN_DEPLOYER_PRIVATE_KEY", _default_deployer_private_key())
    process = subprocess.Popen(
        [str(start_script)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        env=env,
    )
    broadcaster = RpcEvmBroadcaster(env.get("CLAWCHAIN_EVM_RPC_URL", "http://127.0.0.1:8545"))
    deadline = time.time() + 8.0
    while time.time() < deadline:
        if process.poll() is not None:
            break
        try:
            broadcaster.probe_chain(configured_chain_id=int(env.get("CLAWCHAIN_EVM_CHAIN_ID", "31337")))
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    else:
        process.terminate()
        return None, None
    deploy = subprocess.run(
        [str(deploy_script)],
        capture_output=True,
        text=True,
        env=env,
        cwd=root,
        check=False,
    )
    if deploy.returncode != 0 or not manifest_path.exists():
        process.terminate()
        return None, None
    return manifest_path, process


def _bootstrap_local_evm_manifest_with_config(config: "AgentProxyConfig", base_dir: Path) -> tuple[Path | None, subprocess.Popen[str] | None]:
    if os.name == "nt":
        return None, None
    manifest_path = Path(config.evm_manifest_path).expanduser() if config.evm_manifest_path else (base_dir / "deployment.json")
    if manifest_path.exists():
        try:
            existing = load_evm_deployment_manifest(manifest_path)
            if verify_evm_deployment_manifest(existing).ok:
                return manifest_path, None
        except Exception:  # noqa: BLE001
            pass
    root = _project_root()
    start_script = root / "scripts" / "start_local_devnet.sh"
    deploy_script = root / "scripts" / "deploy_commitment_anchor.sh"
    if not start_script.exists() or not deploy_script.exists():
        return None, None
    env = os.environ.copy()
    env["CLAWCHAIN_EVM_MANIFEST_PATH"] = str(manifest_path)
    if config.evm_rpc_url:
        env["CLAWCHAIN_EVM_RPC_URL"] = config.evm_rpc_url
    if config.evm_chain_id is not None:
        env["CLAWCHAIN_EVM_CHAIN_ID"] = str(config.evm_chain_id)
    env["CLAWCHAIN_DEPLOYER_PRIVATE_KEY"] = config.evm_deployer_private_key or _default_deployer_private_key()
    process = subprocess.Popen(
        [str(start_script)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        env=env,
    )
    broadcaster = RpcEvmBroadcaster(env.get("CLAWCHAIN_EVM_RPC_URL", "http://127.0.0.1:8545"))
    configured_chain_id = int(env.get("CLAWCHAIN_EVM_CHAIN_ID", "31337"))
    deadline = time.time() + 8.0
    while time.time() < deadline:
        if process.poll() is not None:
            break
        try:
            broadcaster.probe_chain(configured_chain_id=configured_chain_id)
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    else:
        process.terminate()
        return None, None
    deploy = subprocess.run(
        [str(deploy_script)],
        capture_output=True,
        text=True,
        env=env,
        cwd=root,
        check=False,
    )
    if deploy.returncode != 0 or not manifest_path.exists():
        process.terminate()
        return None, None
    return manifest_path, process


def _wait_for_unix_sidecar(sink: UnixSocketEvidenceSink, socket_path: Path, *, timeout_sec: float = 2.0) -> None:
    deadline = time.time() + timeout_sec
    last_error: Exception | None = None
    while time.time() < deadline:
        if socket_path.exists():
            try:
                sink.snapshot()
                return
            except Exception as exc:  # noqa: BLE001
                last_error = exc
        time.sleep(0.05)
    if last_error is not None:
        raise RuntimeError("unix sidecar did not become ready") from last_error
    raise RuntimeError("unix sidecar socket was not created")


def _auto_anchor_backend(base_dir: Path, config: "AgentProxyConfig"):
    manifest_candidates = [
        Path(config.evm_manifest_path).expanduser()
        for _ in [0]
        if config.evm_manifest_path
    ]
    manifest_candidates.extend(
        [
            Path(os.environ["CLAWCHAIN_EVM_MANIFEST_PATH"])
            for _ in [0]
            if os.environ.get("CLAWCHAIN_EVM_MANIFEST_PATH")
        ]
    )
    manifest_candidates.append(base_dir / "deployment.json")
    for path in manifest_candidates:
        if not path.exists():
            continue
        manifest = load_evm_deployment_manifest(path)
        return EvmAnchorBackend(
            EvmAnchorConfig(
                chain_id=manifest.chain_id,
                rpc_url=manifest.rpc_url,
                contract_address=manifest.contract_address,
            ),
            broadcaster=RpcEvmBroadcaster(manifest.rpc_url),
        )
    if config.evm_rpc_url and config.evm_contract_address:
        return EvmAnchorBackend(
            EvmAnchorConfig(
                chain_id=config.evm_chain_id or 31337,
                rpc_url=config.evm_rpc_url,
                contract_address=config.evm_contract_address,
            ),
            broadcaster=RpcEvmBroadcaster(config.evm_rpc_url),
        )
    return LocalAnchorBackend()


def _canonical_execution_started(
    *,
    session_id: str,
    run_id: str,
    event_index: int,
    timestamp_ms: int,
    actor_id: str,
    tool_name: str,
    tool_call_id: str,
    params: dict[str, object],
    parent_event_hash: str | None,
) -> CanonicalEvent:
    return CanonicalEvent(
        session_id=session_id,
        run_id=run_id,
        event_index=event_index,
        event_type=EventType.TOOL_EXECUTION_STARTED,
        timestamp_ms=timestamp_ms,
        actor_id=actor_id,
        source="clawchain.agent-proxy",
        payload={
            "tool_name": tool_name,
            "tool_call_id": tool_call_id,
            "params": params,
        },
        parent_event_hash=parent_event_hash,
    )


def _canonical_execution_completed(
    *,
    session_id: str,
    run_id: str,
    event_index: int,
    timestamp_ms: int,
    actor_id: str,
    tool_name: str,
    tool_call_id: str,
    result: dict[str, object] | None,
    error: str | None,
    parent_event_hash: str | None,
) -> CanonicalEvent:
    return CanonicalEvent(
        session_id=session_id,
        run_id=run_id,
        event_index=event_index,
        event_type=EventType.TOOL_EXECUTION_COMPLETED,
        timestamp_ms=timestamp_ms,
        actor_id=actor_id,
        source="clawchain.agent-proxy",
        payload={
            "tool_name": tool_name,
            "tool_call_id": tool_call_id,
            "result": result,
            "error": error,
        },
        parent_event_hash=parent_event_hash,
    )


def _expand_existing_targets(expanded: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    result: list[Path] = []
    for path in expanded:
        if not path.exists():
            continue
        candidates = [path]
        if path.is_dir():
            file_children = [child for child in sorted(path.rglob("*")) if child.is_file()]
            candidates = file_children or [path]
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            result.append(candidate)
    return result


def _command_tokens_and_text(cmd: list[str] | tuple[str, ...] | str | object) -> tuple[list[str], str]:
    if isinstance(cmd, (list, tuple)):
        tokens = [str(part) for part in cmd]
        return tokens, " ".join(tokens)
    text = str(cmd or "").strip()
    if not text:
        return [], ""
    try:
        tokens = shlex.split(text, posix=(os.name != "nt"))
    except ValueError:
        tokens = text.split()
    return [str(part) for part in tokens], text


def _resolve_candidate_path(token: str, *, cwd: Path) -> Path:
    candidate = Path(str(token or "").strip().strip("'\""))
    if candidate.is_absolute():
        return candidate
    return (cwd / candidate).resolve()


def _resolve_powershell_variable(*, command_text: str, token: str) -> str:
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


def _infer_target_paths_from_text(command_text: str, *, cwd: Path | None) -> list[Path]:
    text = str(command_text or "").strip()
    if not text:
        return []
    cwd = cwd or Path.cwd()
    remove_item_match = re.search(
        r"(?i)\bRemove-Item\b.*?-(?:LiteralPath|Path)\s+(?P<path>'[^']+'|\"[^\"]+\"|\S+)",
        text,
    )
    if remove_item_match is not None:
        target = _resolve_powershell_variable(command_text=text, token=remove_item_match.group("path"))
        return _expand_existing_targets([_resolve_candidate_path(target, cwd=cwd)])
    delete_match = re.search(r"(?i)\b(?:del|erase)\b\s+(?P<path>'[^']+'|\"[^\"]+\"|\S+)", text)
    if delete_match is not None:
        target = _resolve_powershell_variable(command_text=text, token=delete_match.group("path"))
        return _expand_existing_targets([_resolve_candidate_path(target, cwd=cwd)])
    tokens, _ = _command_tokens_and_text(text)
    lowered_tokens = [token.lower() for token in tokens]
    if tokens:
        launcher = Path(tokens[0]).name.lower()
        if launcher in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
            for flag in ("-command", "-c"):
                if flag in lowered_tokens:
                    index = lowered_tokens.index(flag)
                    return _infer_target_paths_from_text(" ".join(tokens[index + 1:]), cwd=cwd)
        if launcher in {"cmd", "cmd.exe"} and len(tokens) >= 3 and tokens[1].lower() in {"/c", "/k"}:
            return _infer_target_paths_from_text(" ".join(tokens[2:]), cwd=cwd)
    return _infer_target_paths(tokens, cwd=cwd)


def _infer_target_paths(cmd: list[str] | tuple[str, ...] | str | object, *, cwd: Path | None) -> list[Path]:
    tokens, text = _command_tokens_and_text(cmd)
    if not tokens and not text:
        return []
    if text and not isinstance(cmd, (list, tuple)):
        return _infer_target_paths_from_text(text, cwd=cwd)
    cwd = cwd or Path.cwd()
    command_name = Path(tokens[0]).name
    lowered = [part.lower() for part in tokens]
    expanded: list[Path] = []
    if command_name == "rm":
        for part in tokens[1:]:
            if part.startswith("-"):
                continue
            if any(ch in part for ch in "*?[]"):
                expanded.extend(path for path in cwd.glob(part) if path.exists())
            else:
                path = (cwd / part).resolve() if not Path(part).is_absolute() else Path(part)
                if path.exists():
                    expanded.append(path)
    elif command_name == "git" and (tokens[1:3] == ["reset", "--hard"] or tokens[1:2] == ["clean"]):
        expanded.append(cwd.resolve())
    elif command_name == "find" and "-delete" in lowered:
        for part in tokens[1:]:
            if part.startswith("-"):
                break
            path = (cwd / part).resolve() if not Path(part).is_absolute() else Path(part)
            if path.exists():
                expanded.append(path)
    return _expand_existing_targets(expanded)


def _infer_referenced_paths_from_text(command_text: str, *, cwd: Path | None) -> list[Path]:
    text = str(command_text or "").strip()
    if not text:
        return []
    cwd = cwd or Path.cwd()
    refs: list[Path] = list(_infer_target_paths_from_text(text, cwd=cwd))
    seen = set(refs)
    tokens, _ = _command_tokens_and_text(text)
    for token in tokens[1:]:
        cleaned = str(token or "").strip().strip("'\"")
        if not cleaned or cleaned.startswith("-") or any(ch in cleaned for ch in "*?[]"):
            continue
        if cleaned.startswith("$"):
            cleaned = _resolve_powershell_variable(command_text=text, token=cleaned)
        path = _resolve_candidate_path(cleaned, cwd=cwd)
        if path.exists() and path not in seen:
            seen.add(path)
            refs.append(path)
    return refs


def _infer_referenced_paths(cmd: list[str] | tuple[str, ...] | str | object, *, cwd: Path | None) -> list[Path]:
    tokens, text = _command_tokens_and_text(cmd)
    if not tokens and not text:
        return []
    if text and not isinstance(cmd, (list, tuple)):
        return _infer_referenced_paths_from_text(text, cwd=cwd)
    cwd = cwd or Path.cwd()
    refs: list[Path] = []
    seen: set[Path] = set()
    for token in tokens[1:]:
        if token.startswith("-") or any(ch in token for ch in "*?[]"):
            continue
        candidate = Path(token)
        path = candidate if candidate.is_absolute() else (cwd / candidate).resolve()
        if path.exists() and path not in seen:
            seen.add(path)
            refs.append(path)
    return refs


def _infer_tool_target_paths(*, tool_name: str, params: dict[str, object], cwd: Path | None) -> list[Path]:
    if tool_name == "system.run":
        return _infer_target_paths(params.get("cmd"), cwd=cwd)
    if tool_name in {"fs.delete", "fs.write_text"}:
        path = params.get("path")
        if isinstance(path, str):
            candidate = Path(path)
            return [candidate if candidate.is_absolute() else ((cwd or Path.cwd()) / candidate).resolve()]
        return []
    if tool_name == "fs.move":
        targets: list[Path] = []
        for key in ("src", "dst"):
            value = params.get(key)
            if isinstance(value, str):
                candidate = Path(value)
                targets.append(candidate if candidate.is_absolute() else ((cwd or Path.cwd()) / candidate).resolve())
        return targets
    return []


def _path_is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _path_matches_policy(path: Path, policy: AgentProxyPolicy) -> bool:
    resolved = path.resolve()
    if resolved.name in policy.protected_file_names:
        return True
    return any(_path_is_under(resolved, prefix) for prefix in policy.expanded_prefixes())


def _expand_recovery_targets(target_paths: list[Path]) -> list[Path]:
    expanded: list[Path] = []
    seen: set[Path] = set()
    sibling_names = {
        ".env",
        ".env.local",
        ".env.production",
        "config.yaml",
        "config.yml",
        "settings.json",
        ".bashrc",
        ".zshrc",
    }
    for path in target_paths:
        candidates = [path]
        if path.is_file() and any(token in path.name.lower() for token in (".env", "config", "settings", ".bashrc", ".zshrc")):
            for sibling in sorted(path.parent.iterdir()):
                if sibling.is_file() and sibling.name in sibling_names:
                    candidates.append(sibling)
        for candidate in candidates:
            if candidate.exists() and candidate not in seen:
                seen.add(candidate)
                expanded.append(candidate)
    return expanded


def _common_target_root(target_paths: list[Path]) -> Path | None:
    if not target_paths:
        return None
    try:
        common = os.path.commonpath([str(path.resolve()) for path in target_paths])
    except ValueError:
        return None
    return Path(common)


@dataclass(frozen=True)
class AgentProxyPaths:
    base_dir: Path
    runtime_root: Path
    evidence_root: Path
    vault_root: Path
    wrapper_root: Path
    sidecar_socket: Path

    @classmethod
    def from_base_dir(cls, base_dir: Path) -> "AgentProxyPaths":
        return cls(
            base_dir=base_dir,
            runtime_root=base_dir / "runtime",
            evidence_root=base_dir / "evidence-remote",
            vault_root=base_dir / "recovery-vault",
            wrapper_root=base_dir / "bin",
            sidecar_socket=_socket_path_for(base_dir / "sidecar"),
        )


@dataclass(frozen=True)
class AgentProxyPolicy:
    protected_path_prefixes: tuple[str, ...] = (
        "~/.ssh",
        "~/.gnupg",
        "~/.aws",
        "~/.kube",
    )
    protected_file_names: tuple[str, ...] = (
        "id_rsa",
        "id_ed25519",
        ".env",
        ".env.local",
        ".env.production",
    )
    forbidden_tool_names: tuple[str, ...] = ()
    allowed_env_names: tuple[str, ...] = ()
    allowed_secret_file_paths: tuple[str, ...] = ()
    deny_secret_reads: bool = True
    deny_writes_to_protected_paths: bool = True
    deny_deletes_on_protected_paths: bool = True

    def expanded_prefixes(self) -> tuple[Path, ...]:
        return tuple(Path(prefix).expanduser().resolve() for prefix in self.protected_path_prefixes)

    def expanded_allowed_secret_paths(self) -> tuple[Path, ...]:
        return tuple(Path(path).expanduser().resolve() for path in self.allowed_secret_file_paths)


@dataclass(frozen=True)
class AgentProxyPolicyDecision:
    allowed: bool
    reason_code: str
    message: str
    matched_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class AgentProxyConfig:
    account_id: str
    password: str
    base_dir: Path | None = None
    auto_start_sidecar: bool = True
    anchor_strategy: str = "auto"
    auto_bootstrap_evm: bool = True
    evm_manifest_path: str | None = None
    evm_rpc_url: str | None = None
    evm_chain_id: int | None = None
    evm_contract_address: str | None = None
    evm_deployer_private_key: str | None = None
    system_config: ClawChainConfig = field(default_factory=ClawChainConfig.hardened)
    policy: AgentProxyPolicy = field(default_factory=AgentProxyPolicy)


@dataclass(frozen=True)
class AgentProxyBootstrapReport:
    sidecar_enabled: bool
    anchor_backend: str
    evm_manifest_path: str | None
    evm_bootstrapped: bool
    runtime_root: str
    evidence_root: str
    vault_root: str
    wrapper_root: str
    service_state_path: str | None = None


@dataclass(frozen=True)
class AgentProxyRequirement:
    component: str
    code: str
    message: str
    manual: bool = True


@dataclass(frozen=True)
class AgentProxyEvmSetupStatus:
    enabled: bool
    backend: str
    auto_bootstrap_requested: bool
    auto_bootstrap_succeeded: bool
    manifest_path: str | None
    requirements: tuple[AgentProxyRequirement, ...] = ()


@dataclass(frozen=True)
class AgentProxyGitSetupStatus:
    path_hint: str
    repo_root: str | None
    repo_detected: bool
    head_available: bool
    user_name_configured: bool
    user_email_configured: bool
    target_count: int
    tracked_target_count: int
    untracked_targets: tuple[str, ...] = ()
    missing_targets: tuple[str, ...] = ()
    requirements: tuple[AgentProxyRequirement, ...] = ()


@dataclass(frozen=True)
class AgentProxySetupStatus:
    bootstrap: AgentProxyBootstrapReport
    evm: AgentProxyEvmSetupStatus
    git: AgentProxyGitSetupStatus | None = None


@dataclass(frozen=True)
class AgentProxyLaunchArtifacts:
    wrapper_path: str
    env_path: str
    account_id: str
    session_id: str
    run_id: str


@dataclass(frozen=True)
class AgentProxyCommandResult:
    session_id: str
    run_id: str
    tool_call_id: str
    cmd: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    protections: tuple[object, ...]
    bootstrap: AgentProxyBootstrapReport


@dataclass(frozen=True)
class AgentProxyToolResult:
    session_id: str
    run_id: str
    tool_call_id: str
    tool_name: str
    success: bool
    output: dict[str, object]
    error: str | None
    protections: tuple[object, ...]
    bootstrap: AgentProxyBootstrapReport


@dataclass
class TransparentAgentProxy:
    config: AgentProxyConfig
    paths: AgentProxyPaths
    system: ClawChainSystem
    remote_sink: RemoteEvidenceSink
    bootstrap: AgentProxyBootstrapReport
    server: object | None = None
    server_thread: threading.Thread | None = None
    evm_process: subprocess.Popen[str] | None = None
    _session_next_index: dict[str, int] = field(default_factory=dict)
    _session_last_hash: dict[str, str | None] = field(default_factory=dict)
    _observed_tool_calls: dict[tuple[str, str], dict[str, object]] = field(default_factory=dict)

    def describe_evm_setup(self) -> AgentProxyEvmSetupStatus:
        requirements: list[AgentProxyRequirement] = []
        backend = self.bootstrap.anchor_backend
        manifest_path = self.bootstrap.evm_manifest_path
        if backend != "EvmAnchorBackend":
            if not self.config.auto_bootstrap_evm:
                requirements.append(
                    AgentProxyRequirement(
                        component="evm",
                        code="evm_auto_bootstrap_disabled",
                        message=(
                            "Real EVM is not enabled automatically. "
                            "Enable auto_bootstrap_evm or provide an existing deployment manifest."
                        ),
                    )
                )
            elif manifest_path is None:
                requirements.append(
                    AgentProxyRequirement(
                        component="evm",
                        code="evm_manifest_missing",
                        message=(
                            "Automatic local EVM bootstrap did not produce a deployment manifest. "
                            "You may need to install/start the local devnet toolchain or provide "
                            "CLAWCHAIN_EVM_MANIFEST_PATH."
                        ),
                    )
                )
            requirements.append(
                AgentProxyRequirement(
                    component="evm",
                    code="evm_custom_chain_requires_manual_values",
                    message=(
                        "If you want a non-local or non-default EVM chain, you must provide "
                        "RPC URL, contract deployment manifest, and deployer credentials manually."
                    ),
                )
            )
        return AgentProxyEvmSetupStatus(
            enabled=backend == "EvmAnchorBackend",
            backend=backend,
            auto_bootstrap_requested=self.config.auto_bootstrap_evm,
            auto_bootstrap_succeeded=self.bootstrap.evm_bootstrapped,
            manifest_path=manifest_path,
            requirements=tuple(requirements),
        )

    def describe_git_setup(
        self,
        *,
        workspace_root: Path,
        target_paths: list[Path] | None = None,
    ) -> AgentProxyGitSetupStatus:
        workspace_root = workspace_root.resolve()
        targets = [path.resolve() for path in (target_paths or [])]
        probe = _run_git_probe(["rev-parse", "--show-toplevel"], cwd=workspace_root)
        repo_detected = probe.returncode == 0
        repo_root = Path(probe.stdout.strip()).resolve() if repo_detected else None
        head_available = False
        user_name_configured = False
        user_email_configured = False
        tracked_target_count = 0
        untracked_targets: list[str] = []
        missing_targets: list[str] = []
        requirements: list[AgentProxyRequirement] = []

        if repo_detected and repo_root is not None:
            head_available = _run_git_probe(["rev-parse", "--verify", "HEAD"], cwd=repo_root).returncode == 0
            user_name_configured = (
                _run_git_probe(["config", "--get", "user.name"], cwd=repo_root).returncode == 0
            )
            user_email_configured = (
                _run_git_probe(["config", "--get", "user.email"], cwd=repo_root).returncode == 0
            )
            for target in targets:
                if not target.exists():
                    missing_targets.append(str(target))
                    continue
                try:
                    relative = str(target.relative_to(repo_root))
                except ValueError:
                    untracked_targets.append(str(target))
                    continue
                tracked = _run_git_probe(["ls-files", "--error-unmatch", relative], cwd=repo_root)
                if tracked.returncode == 0:
                    tracked_target_count += 1
                else:
                    untracked_targets.append(str(target))
        else:
            requirements.append(
                AgentProxyRequirement(
                    component="git",
                    code="git_repo_missing",
                    message=(
                        "Git recovery requires the workspace to be inside an initialized Git repository."
                    ),
                )
            )

        if repo_detected and not head_available:
            requirements.append(
                AgentProxyRequirement(
                    component="git",
                    code="git_head_missing",
                    message=(
                        "Git recovery requires at least one commit so that tracked files can be restored from HEAD."
                    ),
                )
            )
        if repo_detected and not user_name_configured:
            requirements.append(
                AgentProxyRequirement(
                    component="git",
                    code="git_user_name_missing",
                    message="Git user.name is not configured for this workspace.",
                )
            )
        if repo_detected and not user_email_configured:
            requirements.append(
                AgentProxyRequirement(
                    component="git",
                    code="git_user_email_missing",
                    message="Git user.email is not configured for this workspace.",
                )
            )
        if untracked_targets:
            requirements.append(
                AgentProxyRequirement(
                    component="git",
                    code="git_targets_untracked",
                    message=(
                        "Some target paths are not tracked by Git and cannot use Git recovery until committed."
                    ),
                )
            )
        if missing_targets:
            requirements.append(
                AgentProxyRequirement(
                    component="git",
                    code="git_targets_missing",
                    message="Some requested target paths do not currently exist and cannot be pre-protected via Git.",
                )
            )

        return AgentProxyGitSetupStatus(
            path_hint=str(workspace_root),
            repo_root=str(repo_root) if repo_root is not None else None,
            repo_detected=repo_detected,
            head_available=head_available,
            user_name_configured=user_name_configured,
            user_email_configured=user_email_configured,
            target_count=len(targets),
            tracked_target_count=tracked_target_count,
            untracked_targets=tuple(untracked_targets),
            missing_targets=tuple(missing_targets),
            requirements=tuple(requirements),
        )

    def describe_setup_requirements(
        self,
        *,
        workspace_root: Path | None = None,
        target_paths: list[Path] | None = None,
    ) -> AgentProxySetupStatus:
        git_status = None
        if workspace_root is not None:
            git_status = self.describe_git_setup(
                workspace_root=workspace_root,
                target_paths=target_paths,
            )
        return AgentProxySetupStatus(
            bootstrap=self.bootstrap,
            evm=self.describe_evm_setup(),
            git=git_status,
        )

    @classmethod
    def create(cls, config: AgentProxyConfig) -> "TransparentAgentProxy":
        base_dir = config.base_dir or _default_base_dir(config.account_id)
        paths = AgentProxyPaths.from_base_dir(base_dir)
        paths.base_dir.mkdir(parents=True, exist_ok=True)
        paths.runtime_root.mkdir(parents=True, exist_ok=True)
        paths.evidence_root.mkdir(parents=True, exist_ok=True)
        paths.vault_root.mkdir(parents=True, exist_ok=True)
        paths.wrapper_root.mkdir(parents=True, exist_ok=True)
        for protected_dir in (
            paths.base_dir,
            paths.runtime_root,
            paths.evidence_root,
            paths.vault_root,
            paths.wrapper_root,
        ):
            try:
                protected_dir.chmod(0o700)
            except PermissionError:
                pass

        server = None
        thread = None
        evm_process = None
        write_secret = _derive_secret(
            account_id=config.account_id,
            password=config.password,
            label="sidecar-write",
        )
        read_secret = _derive_secret(
            account_id=config.account_id,
            password=config.password,
            label="sidecar-read",
        )
        if config.auto_start_sidecar and os.name != "nt":
            sidecar_config = SidecarServiceConfig(
                root_dir=paths.evidence_root,
                socket_path=paths.sidecar_socket,
                write_auth_secret=write_secret,
                read_auth_secret=read_secret,
            )
            try:
                server = build_sidecar_unix_server(sidecar_config)
            except PermissionError:
                fallback_socket = _socket_path_for(Path(tempfile.gettempdir()) / f"occp-{config.account_id}")
                sidecar_config = SidecarServiceConfig(
                    root_dir=paths.evidence_root,
                    socket_path=fallback_socket,
                    write_auth_secret=write_secret,
                    read_auth_secret=read_secret,
                )
                paths = replace(paths, sidecar_socket=fallback_socket)
                try:
                    server = build_sidecar_unix_server(sidecar_config)
                except PermissionError:
                    server = None
            if server is not None:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                remote_sink = UnixSocketEvidenceSink(
                    paths.sidecar_socket,
                    write_auth_secret=write_secret,
                    read_auth_secret=read_secret,
                )
                try:
                    _wait_for_unix_sidecar(remote_sink, paths.sidecar_socket)
                    remote_sink.snapshot()
                except Exception:  # noqa: BLE001
                    server.shutdown()
                    server.server_close()
                    if thread is not None:
                        thread.join(timeout=2)
                    server = None
                    thread = None
                    remote_sink = LocalAppendOnlyEvidenceSink(paths.evidence_root)
            else:
                remote_sink = LocalAppendOnlyEvidenceSink(paths.evidence_root)
        else:
            remote_sink = LocalAppendOnlyEvidenceSink(paths.evidence_root)
        evm_manifest_path: Path | None = None
        if config.anchor_strategy == "auto":
            if config.auto_bootstrap_evm:
                if any(
                    value is not None
                    for value in (
                        config.evm_manifest_path,
                        config.evm_rpc_url,
                        config.evm_chain_id,
                        config.evm_contract_address,
                        config.evm_deployer_private_key,
                    )
                ):
                    evm_manifest_path, evm_process = _bootstrap_local_evm_manifest_with_config(config, paths.base_dir)
                else:
                    evm_manifest_path, evm_process = _bootstrap_local_evm_manifest(paths.base_dir)
            anchor_backend = _auto_anchor_backend(paths.base_dir, config)
        else:
            anchor_backend = LocalAnchorBackend()
        system = ClawChainSystem.create(
            root_dir=paths.runtime_root,
            config=config.system_config,
            anchor_backend=anchor_backend,
            remote_sink=remote_sink,
            remote_root=paths.evidence_root,
            vault_root=paths.vault_root,
        )
        bootstrap = AgentProxyBootstrapReport(
            sidecar_enabled=server is not None,
            anchor_backend=type(anchor_backend).__name__,
            evm_manifest_path=str(evm_manifest_path) if evm_manifest_path is not None else None,
            evm_bootstrapped=evm_manifest_path is not None,
            runtime_root=str(paths.runtime_root),
            evidence_root=str(paths.evidence_root),
            vault_root=str(paths.vault_root),
            wrapper_root=str(paths.wrapper_root),
            service_state_path=str(paths.base_dir / "agent-proxy-service.json"),
        )
        return cls(
            config=config,
            paths=paths,
            system=system,
            remote_sink=remote_sink,
            bootstrap=bootstrap,
            server=server,
            server_thread=thread,
            evm_process=evm_process,
        )

    def close(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.server_thread is not None:
            self.server_thread.join(timeout=2)
        if self.paths.sidecar_socket.exists():
            self.paths.sidecar_socket.unlink()
        if self.evm_process is not None and self.evm_process.poll() is None:
            self.evm_process.terminate()
            try:
                self.evm_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.evm_process.kill()

    def prepare_launch_artifacts(
        self,
        *,
        session_id: str,
        run_id: str,
    ) -> AgentProxyLaunchArtifacts:
        env_path = self.paths.base_dir / "agent-proxy.env"
        wrapper_path = self.paths.wrapper_root / "clawchain-agent-run"
        python_exec = os.environ.get("PYTHON", os.sys.executable)
        env_lines = [
            f"CLAWCHAIN_AGENT_ACCOUNT_ID={self.config.account_id}",
            f"CLAWCHAIN_AGENT_PASSWORD={self.config.password}",
            f"CLAWCHAIN_AGENT_SESSION_ID={session_id}",
            f"CLAWCHAIN_AGENT_RUN_ID={run_id}",
            f"CLAWCHAIN_AGENT_ROOT_DIR={self.paths.base_dir}",
            f"CLAWCHAIN_AGENT_NO_AUTO_EVM={'0' if self.config.auto_bootstrap_evm else '1'}",
        ]
        env_path.write_text("\n".join(env_lines) + "\n", encoding="utf-8")
        wrapper = "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                'ACCOUNT_ID="${CLAWCHAIN_AGENT_ACCOUNT_ID:?missing CLAWCHAIN_AGENT_ACCOUNT_ID}"',
                'PASSWORD="${CLAWCHAIN_AGENT_PASSWORD:?missing CLAWCHAIN_AGENT_PASSWORD}"',
                'SESSION_ID="${CLAWCHAIN_AGENT_SESSION_ID:?missing CLAWCHAIN_AGENT_SESSION_ID}"',
                'RUN_ID="${CLAWCHAIN_AGENT_RUN_ID:?missing CLAWCHAIN_AGENT_RUN_ID}"',
                'ROOT_DIR="${CLAWCHAIN_AGENT_ROOT_DIR:?missing CLAWCHAIN_AGENT_ROOT_DIR}"',
                'AUTO_EVM_FLAG=""',
                'if [[ "${CLAWCHAIN_AGENT_NO_AUTO_EVM:-0}" == "1" ]]; then AUTO_EVM_FLAG="--no-auto-evm"; fi',
                f'exec "{python_exec}" -m clawchain.agent_proxy_cli "$ACCOUNT_ID" "$PASSWORD" "$SESSION_ID" "$RUN_ID" --root-dir "$ROOT_DIR" $AUTO_EVM_FLAG -- "$@"',
                "",
            ]
        )
        wrapper_path.write_text(wrapper, encoding="utf-8")
        wrapper_path.chmod(wrapper_path.stat().st_mode | stat.S_IXUSR)
        return AgentProxyLaunchArtifacts(
            wrapper_path=str(wrapper_path),
            env_path=str(env_path),
            account_id=self.config.account_id,
            session_id=session_id,
            run_id=run_id,
        )

    def _ensure_session_started(self, *, session_id: str, run_id: str, channel: str) -> None:
        if session_id in self._session_next_index:
            return
        req = self.system.adapter.request_accepted(
            session_id=session_id,
            run_id=run_id,
            event_index=0,
            timestamp_ms=int(time.time() * 1000),
            channel=channel,
        )
        self.system.publish(req)
        self._session_next_index[session_id] = 1
        self._session_last_hash[session_id] = req.event_hash

    def _evaluate_action_policy(
        self,
        *,
        tool_name: str,
        params: dict[str, object],
        cwd: Path | None,
    ) -> AgentProxyPolicyDecision:
        policy = self.config.policy
        if tool_name in policy.forbidden_tool_names:
            return AgentProxyPolicyDecision(
                allowed=False,
                reason_code="forbidden_tool",
                message=f"tool {tool_name} is forbidden by proxy policy",
            )
        if tool_name == "secret.read_env":
            name = str(params.get("name", ""))
            if not name or name not in policy.allowed_env_names:
                return AgentProxyPolicyDecision(
                    allowed=False,
                    reason_code="protected_env_access_denied",
                    message=f"proxy policy denied access to environment variable {name or '<empty>'}",
                )
            return AgentProxyPolicyDecision(
                allowed=True,
                reason_code="allowed",
                message="proxy policy allowed env access",
            )
        if tool_name == "secret.read_file":
            raw_path = params.get("path")
            if not isinstance(raw_path, str):
                return AgentProxyPolicyDecision(
                    allowed=False,
                    reason_code="protected_file_access_denied",
                    message="proxy policy denied secret file access because no valid path was provided",
                )
            candidate = Path(raw_path)
            resolved = candidate if candidate.is_absolute() else ((cwd or Path.cwd()) / candidate).resolve()
            if resolved not in policy.expanded_allowed_secret_paths():
                return AgentProxyPolicyDecision(
                    allowed=False,
                    reason_code="protected_file_access_denied",
                    message="proxy policy denied secret file access",
                    matched_paths=(str(resolved),),
                )
            return AgentProxyPolicyDecision(
                allowed=True,
                reason_code="allowed",
                message="proxy policy allowed secret file access",
                matched_paths=(str(resolved),),
            )
        matched_paths: list[str] = []
        referenced_paths: list[Path] = []
        if tool_name == "system.run":
            referenced_paths = _infer_referenced_paths(params.get("cmd"), cwd=cwd)
        elif tool_name in {"fs.delete", "fs.write_text", "fs.move"}:
            referenced_paths = _infer_tool_target_paths(tool_name=tool_name, params=params, cwd=cwd)
        secret_read_command = False
        if tool_name == "system.run":
            _cmd_tokens, cmd_text = _command_tokens_and_text(params.get("cmd"))
            cmd_text = cmd_text.lower()
            secret_read_command = any(keyword in cmd_text for keyword in ("cat ", "sed ", "head ", "tail ", "less ", "more "))
        for path in referenced_paths:
            if _path_matches_policy(path, policy):
                matched_paths.append(str(path))
        if matched_paths and policy.deny_secret_reads and secret_read_command:
            return AgentProxyPolicyDecision(
                allowed=False,
                reason_code="protected_secret_read_denied",
                message="proxy policy denied reading a protected path or secret file",
                matched_paths=tuple(dict.fromkeys(matched_paths)),
            )
        if matched_paths and policy.deny_writes_to_protected_paths and tool_name in {"fs.write_text", "fs.move"}:
            return AgentProxyPolicyDecision(
                allowed=False,
                reason_code="protected_path_mutation_denied",
                message="proxy policy denied mutating a protected path",
                matched_paths=tuple(dict.fromkeys(matched_paths)),
            )
        if matched_paths and policy.deny_deletes_on_protected_paths and tool_name == "fs.delete":
            return AgentProxyPolicyDecision(
                allowed=False,
                reason_code="protected_path_delete_denied",
                message="proxy policy denied deleting a protected path",
                matched_paths=tuple(dict.fromkeys(matched_paths)),
            )
        if matched_paths and policy.deny_deletes_on_protected_paths and tool_name == "system.run":
            _cmd_tokens, cmd_text = _command_tokens_and_text(params.get("cmd"))
            cmd_text = cmd_text.lower()
            destructive = any(token in cmd_text for token in ("rm ", "find ", "-delete", "git reset --hard", "git clean"))
            if destructive:
                return AgentProxyPolicyDecision(
                    allowed=False,
                    reason_code="protected_path_delete_denied",
                    message="proxy policy denied a destructive command targeting a protected path",
                    matched_paths=tuple(dict.fromkeys(matched_paths)),
                )
        return AgentProxyPolicyDecision(
            allowed=True,
            reason_code="allowed",
            message="proxy policy allowed action",
        )

    def _publish_tool_boundary(
        self,
        *,
        session_id: str,
        run_id: str,
        actor_id: str,
        tool_name: str,
        params: dict[str, object],
        policy_name: str,
        policy_version: str,
        decision: str,
    ) -> tuple[str, CanonicalEvent]:
        tool_call_id = f"tool-{uuid.uuid4().hex[:12]}"
        invoke = self.system.adapter.tool_invocation_requested(
            session_id=session_id,
            run_id=run_id,
            event_index=self._session_next_index[session_id],
            timestamp_ms=int(time.time() * 1000),
            actor_id=actor_id,
            tool_name=tool_name,
            params=params,
            tool_call_id=tool_call_id,
            parent_event_hash=self._session_last_hash[session_id],
        )
        self.system.publish(invoke)
        self._session_next_index[session_id] += 1
        self._session_last_hash[session_id] = invoke.event_hash
        policy = self.system.adapter.policy_decision(
            session_id=session_id,
            run_id=run_id,
            event_index=self._session_next_index[session_id],
            timestamp_ms=int(time.time() * 1000),
            actor_id="policy-engine",
            tool_name=tool_name,
            params=params,
            policy_name=policy_name,
            policy_version=policy_version,
            decision=decision,
            reason="proxy-policy-allow" if decision == "allow" else "proxy-policy-deny",
            requires_ask=False,
            approved_by_ask=False,
            parent_event_hash=self._session_last_hash[session_id],
        )
        self.system.publish(policy)
        self._session_next_index[session_id] += 1
        self._session_last_hash[session_id] = policy.event_hash
        return tool_call_id, policy

    def _plan_protections(
        self,
        *,
        session_id: str,
        run_id: str,
        actor_id: str,
        tool_name: str,
        params: dict[str, object],
        target_paths: list[Path],
    ) -> list[object]:
        protections = []
        for target in target_paths:
            protection = self.system.plan_recovery(
                session_id=session_id,
                run_id=run_id,
                event_index=self._session_next_index[session_id],
                timestamp_ms=int(time.time() * 1000),
                actor_id=actor_id,
                target_path=target,
                tool_name=tool_name,
                params=params,
                parent_event_hash=self._session_last_hash[session_id],
            )
            if protection[0] is not None:
                protections.append(protection[0])
                self._session_next_index[session_id] += 1
                planned_event = protection[1]
                if planned_event is not None:
                    self._session_last_hash[session_id] = planned_event.event_hash
        if protections:
            common_root = _common_target_root(target_paths)
            if common_root is not None:
                self.system.record_recovery_impact_set(
                    session_id=session_id,
                    target_root=common_root,
                    risk_reason=protections[0].plans[0].risk_reason,
                    protections=tuple(protections),
                )
        return protections

    def _start_tool_execution(
        self,
        *,
        session_id: str,
        run_id: str,
        actor_id: str,
        tool_name: str,
        tool_call_id: str,
        params: dict[str, object],
    ) -> CanonicalEvent:
        started = _canonical_execution_started(
            session_id=session_id,
            run_id=run_id,
            event_index=self._session_next_index[session_id],
            timestamp_ms=int(time.time() * 1000),
            actor_id=actor_id,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            params=params,
            parent_event_hash=self._session_last_hash[session_id],
        )
        self.system.publish(started)
        self._session_next_index[session_id] += 1
        self._session_last_hash[session_id] = started.event_hash
        return started

    def _complete_tool_execution(
        self,
        *,
        session_id: str,
        run_id: str,
        actor_id: str,
        tool_name: str,
        tool_call_id: str,
        result: dict[str, object] | None,
        error: str | None,
    ) -> CanonicalEvent:
        completed = _canonical_execution_completed(
            session_id=session_id,
            run_id=run_id,
            event_index=self._session_next_index[session_id],
            timestamp_ms=int(time.time() * 1000),
            actor_id=actor_id,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            result=result,
            error=error,
            parent_event_hash=self._session_last_hash[session_id],
        )
        self.system.publish(completed)
        self._session_next_index[session_id] += 1
        self._session_last_hash[session_id] = completed.event_hash
        return completed

    def execute_command(
        self,
        *,
        session_id: str,
        run_id: str,
        actor_id: str,
        cmd: list[str],
        cwd: Path | None = None,
        channel: str = "agent-shell",
        tool_name: str = "system.run",
        policy_name: str = "default_exec_policy",
        policy_version: str = "v1",
        decision: str = "allow",
        auto_recover: bool = False,
    ) -> AgentProxyCommandResult:
        cwd = cwd or Path.cwd()
        self._ensure_session_started(session_id=session_id, run_id=run_id, channel=channel)
        params = {"cmd": cmd}
        policy_decision = self._evaluate_action_policy(tool_name=tool_name, params=params, cwd=cwd)
        tool_call_id, _policy = self._publish_tool_boundary(
            session_id=session_id,
            run_id=run_id,
            actor_id=actor_id,
            tool_name=tool_name,
            params=params,
            policy_name=policy_name,
            policy_version=policy_version,
            decision=decision if policy_decision.allowed else "deny",
        )
        if not policy_decision.allowed:
            self.system.flush()
            self.system.poll_anchor_submissions()
            return AgentProxyCommandResult(
                session_id=session_id,
                run_id=run_id,
                tool_call_id=tool_call_id,
                cmd=tuple(cmd),
                returncode=126,
                stdout="",
                stderr=policy_decision.message,
                protections=(),
                bootstrap=self.bootstrap,
            )

        protections = self._plan_protections(
            session_id=session_id,
            run_id=run_id,
            actor_id=actor_id,
            tool_name=tool_name,
            params=params,
            target_paths=_expand_recovery_targets(_infer_target_paths(cmd, cwd=cwd)),
        )

        self._start_tool_execution(
            session_id=session_id,
            run_id=run_id,
            actor_id=actor_id,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            params=params,
        )

        completed_process = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
        self._complete_tool_execution(
            session_id=session_id,
            run_id=run_id,
            actor_id=actor_id,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            result={"exit_code": completed_process.returncode, "stdout": completed_process.stdout},
            error=(completed_process.stderr or None),
        )

        if auto_recover and completed_process.returncode == 0:
            for protection in protections:
                restored, _started, recovery_done = self.system.execute_recovery_with_audit(
                    protection=protection,
                    preferred_source=protection.primary_source_kind(),
                    session_id=session_id,
                    run_id=run_id,
                    start_event_index=self._session_next_index[session_id],
                    parent_event_hash=self._session_last_hash[session_id],
                    require_manual_approval=False,
                )
                self._session_next_index[session_id] += 2
                if recovery_done is not None:
                    self._session_last_hash[session_id] = recovery_done.event_hash
                if restored is not None:
                    _verified, verified_event, _receipt = self.system.verify_recovery_result(
                        protection=protection,
                        restored_path=restored,
                        session_id=session_id,
                        run_id=run_id,
                        event_index=self._session_next_index[session_id],
                        parent_event_hash=self._session_last_hash[session_id],
                        source_kind=protection.primary_source_kind(),
                    )
                    self._session_next_index[session_id] += 1
                    self._session_last_hash[session_id] = verified_event.event_hash

        self.system.flush()
        self.system.poll_anchor_submissions()
        return AgentProxyCommandResult(
            session_id=session_id,
            run_id=run_id,
            tool_call_id=tool_call_id,
            cmd=tuple(cmd),
            returncode=completed_process.returncode,
            stdout=completed_process.stdout,
            stderr=completed_process.stderr,
            protections=tuple(protections),
            bootstrap=self.bootstrap,
        )

    def execute_tool(
        self,
        *,
        session_id: str,
        run_id: str,
        actor_id: str,
        tool_name: str,
        params: dict[str, object],
        cwd: Path | None = None,
        channel: str = "agent-tool",
        policy_name: str = "default_exec_policy",
        policy_version: str = "v1",
        decision: str = "allow",
    ) -> AgentProxyToolResult:
        cwd = cwd or Path.cwd()
        self._ensure_session_started(session_id=session_id, run_id=run_id, channel=channel)
        policy_gate = self._evaluate_action_policy(tool_name=tool_name, params=params, cwd=cwd)
        tool_call_id, _policy = self._publish_tool_boundary(
            session_id=session_id,
            run_id=run_id,
            actor_id=actor_id,
            tool_name=tool_name,
            params=params,
            policy_name=policy_name,
            policy_version=policy_version,
            decision=decision if policy_gate.allowed else "deny",
        )
        if not policy_gate.allowed:
            self.system.flush()
            self.system.poll_anchor_submissions()
            return AgentProxyToolResult(
                session_id=session_id,
                run_id=run_id,
                tool_call_id=tool_call_id,
                tool_name=tool_name,
                success=False,
                output={"denied": True, "policy_reason": policy_gate.reason_code},
                error=policy_gate.message,
                protections=(),
                bootstrap=self.bootstrap,
            )
        target_paths = _infer_tool_target_paths(tool_name=tool_name, params=params, cwd=cwd)
        protections = self._plan_protections(
            session_id=session_id,
            run_id=run_id,
            actor_id=actor_id,
            tool_name=tool_name,
            params=params,
            target_paths=_expand_recovery_targets([path for path in target_paths if path.exists()]),
        )
        self._start_tool_execution(
            session_id=session_id,
            run_id=run_id,
            actor_id=actor_id,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            params=params,
        )
        success = False
        output: dict[str, object] = {}
        error: str | None = None
        try:
            if tool_name == "system.run":
                cmd, _cmd_text = _command_tokens_and_text(params.get("cmd"))
                if not cmd:
                    raise RuntimeError("system.run requires a non-empty cmd")
                completed_process = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
                success = completed_process.returncode == 0
                output = {
                    "exit_code": completed_process.returncode,
                    "stdout": completed_process.stdout,
                    "stderr": completed_process.stderr,
                }
                error = completed_process.stderr or None
            elif tool_name == "fs.delete":
                path = Path(str(params["path"]))
                target = path if path.is_absolute() else (cwd / path).resolve()
                recursive = bool(params.get("recursive", False))
                if target.is_dir():
                    if not recursive:
                        raise RuntimeError("fs.delete requires recursive=true for directories")
                    for child in sorted(target.rglob("*"), reverse=True):
                        if child.is_file():
                            child.unlink()
                        elif child.is_dir():
                            child.rmdir()
                    target.rmdir()
                elif target.exists():
                    target.unlink()
                success = True
                output = {"deleted_path": str(target)}
            elif tool_name == "fs.write_text":
                path = Path(str(params["path"]))
                target = path if path.is_absolute() else (cwd / path).resolve()
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(str(params.get("content", "")), encoding="utf-8")
                success = True
                output = {"written_path": str(target), "bytes": target.stat().st_size}
            elif tool_name == "fs.move":
                src = Path(str(params["src"]))
                dst = Path(str(params["dst"]))
                source = src if src.is_absolute() else (cwd / src).resolve()
                target = dst if dst.is_absolute() else (cwd / dst).resolve()
                target.parent.mkdir(parents=True, exist_ok=True)
                source.rename(target)
                success = True
                output = {"src": str(source), "dst": str(target)}
            elif tool_name == "secret.read_env":
                name = str(params["name"])
                success = True
                output = {"name": name, "value": os.environ.get(name, "")}
            elif tool_name == "secret.read_file":
                path = Path(str(params["path"]))
                target = path if path.is_absolute() else (cwd / path).resolve()
                success = True
                output = {"path": str(target), "value": target.read_text(encoding="utf-8")}
            else:
                raise RuntimeError(f"unsupported proxy tool: {tool_name}")
        except Exception as exc:  # noqa: BLE001
            success = False
            error = str(exc)
            output = {"error_type": type(exc).__name__}
        self._complete_tool_execution(
            session_id=session_id,
            run_id=run_id,
            actor_id=actor_id,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            result=output,
            error=error,
        )
        self.system.flush()
        self.system.poll_anchor_submissions()
        return AgentProxyToolResult(
            session_id=session_id,
            run_id=run_id,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            success=success,
            output=output,
            error=error,
            protections=tuple(protections),
            bootstrap=self.bootstrap,
        )

    def observe_external_tool_start(
        self,
        *,
        session_id: str,
        run_id: str,
        actor_id: str,
        external_call_id: str,
        tool_name: str,
        params: dict[str, object],
        cwd: Path | None = None,
        channel: str = "external-tool",
        policy_name: str = "external_observation_policy",
        policy_version: str = "v1",
    ) -> dict[str, object]:
        key = (session_id, external_call_id)
        existing = self._observed_tool_calls.get(key)
        if existing is not None:
            return existing
        cwd = cwd or Path.cwd()
        observed_params = dict(params)
        observed_params.setdefault("external_call_id", external_call_id)
        observed_params.setdefault("observation_mode", "external-rollout")
        self._ensure_session_started(session_id=session_id, run_id=run_id, channel=channel)
        policy_gate = self._evaluate_action_policy(tool_name=tool_name, params=observed_params, cwd=cwd)
        tool_call_id, _policy = self._publish_tool_boundary(
            session_id=session_id,
            run_id=run_id,
            actor_id=actor_id,
            tool_name=tool_name,
            params=observed_params,
            policy_name=policy_name,
            policy_version=policy_version,
            decision="allow" if policy_gate.allowed else "deny",
        )
        target_paths = _infer_tool_target_paths(tool_name=tool_name, params=observed_params, cwd=cwd)
        protections = self._plan_protections(
            session_id=session_id,
            run_id=run_id,
            actor_id=actor_id,
            tool_name=tool_name,
            params=observed_params,
            target_paths=_expand_recovery_targets([path for path in target_paths if path.exists()]),
        )
        self._start_tool_execution(
            session_id=session_id,
            run_id=run_id,
            actor_id=actor_id,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            params=observed_params,
        )
        self.system.flush()
        self.system.poll_anchor_submissions()
        state = {
            "session_id": session_id,
            "run_id": run_id,
            "actor_id": actor_id,
            "external_call_id": external_call_id,
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "params": observed_params,
            "cwd": str(cwd),
            "protections": tuple(protections),
            "policy_allowed": policy_gate.allowed,
            "policy_reason": policy_gate.reason_code,
        }
        self._observed_tool_calls[key] = state
        return state

    def observe_external_tool_completion(
        self,
        *,
        session_id: str,
        external_call_id: str,
        result: dict[str, object] | None = None,
        error: str | None = None,
    ) -> bool:
        key = (session_id, external_call_id)
        state = self._observed_tool_calls.pop(key, None)
        if state is None:
            return False
        self._complete_tool_execution(
            session_id=session_id,
            run_id=str(state.get("run_id") or ""),
            actor_id=str(state.get("actor_id") or "external-tool"),
            tool_name=str(state.get("tool_name") or ""),
            tool_call_id=str(state.get("tool_call_id") or ""),
            result=result,
            error=error,
        )
        self.system.flush()
        self.system.poll_anchor_submissions()
        return True


__all__ = [
    "AgentProxyConfig",
    "AgentProxyPaths",
    "AgentProxyPolicy",
    "AgentProxyPolicyDecision",
    "AgentProxyBootstrapReport",
    "AgentProxyRequirement",
    "AgentProxyEvmSetupStatus",
    "AgentProxyGitSetupStatus",
    "AgentProxySetupStatus",
    "AgentProxyLaunchArtifacts",
    "AgentProxyCommandResult",
    "AgentProxyToolResult",
    "TransparentAgentProxy",
]
