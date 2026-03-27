from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path

from .agent_proxy import AgentProxyConfig, AgentProxyPolicy
from .system import ClawChainConfig


@dataclass(frozen=True)
class AgentProxyStoredConfig:
    account_id: str
    password: str
    agent_id: str | None = None
    base_dir: str | None = None
    path_hint: str | None = None
    default_session_id: str = 'default-session'
    default_run_id: str = 'default-run'
    auto_start_sidecar: bool = True
    anchor_strategy: str = 'auto'
    auto_bootstrap_evm: bool = True
    auto_install_foundry: bool = True
    anvil_path: str | None = None
    forge_path: str | None = None
    evm_manifest_path: str | None = None
    evm_rpc_url: str | None = None
    evm_chain_id: int | None = None
    evm_contract_address: str | None = None
    evm_deployer_private_key: str | None = None
    protected_path_prefixes: tuple[str, ...] = (
        '~/.ssh',
        '~/.gnupg',
        '~/.aws',
        '~/.kube',
    )
    protected_file_names: tuple[str, ...] = (
        'id_rsa',
        'id_ed25519',
        '.env',
        '.env.local',
        '.env.production',
    )
    allowed_env_names: tuple[str, ...] = ()
    allowed_secret_file_paths: tuple[str, ...] = ()
    git_context_mode: str = 'bind-existing-git'
    git_max_file_count_per_target: int = 512
    git_max_total_bytes_per_target: int = 32 * 1024 * 1024

    def to_proxy_config(self) -> AgentProxyConfig:
        return AgentProxyConfig(
            account_id=self.account_id,
            password=self.password,
            base_dir=Path(self.base_dir) if self.base_dir else None,
            auto_start_sidecar=self.auto_start_sidecar,
            anchor_strategy=self.anchor_strategy,
            auto_bootstrap_evm=self.auto_bootstrap_evm,
            auto_install_foundry=self.auto_install_foundry,
            anvil_path=self.anvil_path,
            forge_path=self.forge_path,
            evm_manifest_path=self.evm_manifest_path,
            evm_rpc_url=self.evm_rpc_url,
            evm_chain_id=self.evm_chain_id,
            evm_contract_address=self.evm_contract_address,
            evm_deployer_private_key=self.evm_deployer_private_key,
            policy=AgentProxyPolicy(
                protected_path_prefixes=self.protected_path_prefixes,
                protected_file_names=self.protected_file_names,
                allowed_env_names=self.allowed_env_names,
                allowed_secret_file_paths=self.allowed_secret_file_paths,
            ),
            system_config=ClawChainConfig.hardened().__class__(
                **{
                    **ClawChainConfig.hardened().__dict__,
                    'git_context_mode': self.git_context_mode,
                    'git_max_file_count_per_target': self.git_max_file_count_per_target,
                    'git_max_total_bytes_per_target': self.git_max_total_bytes_per_target,
                }
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def workspace_root(self) -> str | None:
        return self.path_hint

    def service_state_path(self) -> Path:
        base = Path(self.base_dir).expanduser() if self.base_dir else Path.home() / '.clawchain-agent' / self.account_id
        return base / 'agent-proxy-service.json'

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> 'AgentProxyStoredConfig':
        return cls(
            account_id=str(data['account_id']),
            password=str(data['password']),
            agent_id=str(data['agent_id']) if data.get('agent_id') is not None else None,
            base_dir=str(data['base_dir']) if data.get('base_dir') is not None else None,
            path_hint=(
                str(data['path_hint'])
                if data.get('path_hint') is not None
                else (str(data['workspace_root']) if data.get('workspace_root') is not None else None)
            ),
            default_session_id=str(data.get('default_session_id', 'default-session')),
            default_run_id=str(data.get('default_run_id', 'default-run')),
            auto_start_sidecar=bool(data.get('auto_start_sidecar', True)),
            anchor_strategy=str(data.get('anchor_strategy', 'auto')),
            auto_bootstrap_evm=bool(data.get('auto_bootstrap_evm', True)),
            auto_install_foundry=bool(data.get('auto_install_foundry', True)),
            anvil_path=str(data['anvil_path']) if data.get('anvil_path') is not None else None,
            forge_path=str(data['forge_path']) if data.get('forge_path') is not None else None,
            evm_manifest_path=str(data['evm_manifest_path']) if data.get('evm_manifest_path') is not None else None,
            evm_rpc_url=str(data['evm_rpc_url']) if data.get('evm_rpc_url') is not None else None,
            evm_chain_id=int(data['evm_chain_id']) if data.get('evm_chain_id') is not None else None,
            evm_contract_address=str(data['evm_contract_address']) if data.get('evm_contract_address') is not None else None,
            evm_deployer_private_key=str(data['evm_deployer_private_key']) if data.get('evm_deployer_private_key') is not None else None,
            protected_path_prefixes=tuple(str(item) for item in data.get('protected_path_prefixes', ()) or ()),
            protected_file_names=tuple(str(item) for item in data.get('protected_file_names', ()) or ()),
            allowed_env_names=tuple(str(item) for item in data.get('allowed_env_names', ()) or ()),
            allowed_secret_file_paths=tuple(str(item) for item in data.get('allowed_secret_file_paths', ()) or ()),
            git_context_mode=str(data.get('git_context_mode', data.get('git_recovery_mode', 'bind-existing-git'))),
            git_max_file_count_per_target=int(data.get('git_max_file_count_per_target', 512)),
            git_max_total_bytes_per_target=int(data.get('git_max_total_bytes_per_target', 32 * 1024 * 1024)),
        )


def load_agent_proxy_config(path: Path) -> AgentProxyStoredConfig:
    return AgentProxyStoredConfig.from_dict(json.loads(path.read_text(encoding='utf-8')))


def write_agent_proxy_config(path: Path, config: AgentProxyStoredConfig) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config.to_dict(), ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    return path


__all__ = [
    'AgentProxyStoredConfig',
    'load_agent_proxy_config',
    'write_agent_proxy_config',
]
