from __future__ import annotations

from dataclasses import dataclass, field

from .ids import digest_text, stable_json


@dataclass(frozen=True)
class PolicyAttestation:
    session_id: str
    run_id: str
    event_id: str
    tool_name: str
    normalized_args_hash: str
    actor_id: str
    policy_name: str
    policy_version: str
    policy_hash: str
    decision: str
    reason: str
    requires_ask: bool
    approved_by_ask: bool
    timestamp_ms: int
    signer: str
    signature: str

    def payload_hash(self) -> str:
        return digest_text(
            stable_json(
                {
                    "actor_id": self.actor_id,
                    "approved_by_ask": self.approved_by_ask,
                    "decision": self.decision,
                    "event_id": self.event_id,
                    "normalized_args_hash": self.normalized_args_hash,
                    "policy_hash": self.policy_hash,
                    "policy_name": self.policy_name,
                    "policy_version": self.policy_version,
                    "reason": self.reason,
                    "requires_ask": self.requires_ask,
                    "run_id": self.run_id,
                    "session_id": self.session_id,
                    "timestamp_ms": self.timestamp_ms,
                    "tool_name": self.tool_name,
                }
            )
        )


@dataclass(frozen=True)
class DelegationScope:
    allowed_tools: tuple[str, ...] = ("*",)
    denied_tools: tuple[str, ...] = ()
    sandbox_mode: str = "inherit"
    sub_delegation: bool = False
    allowed_agents: tuple[str, ...] = ()
    max_depth: int = 0
    expiry_ts: int | None = None


@dataclass(frozen=True)
class DelegationCertificate:
    parent_session_id: str
    child_session_id: str
    parent_agent_id: str
    child_agent_id: str
    run_id: str
    issued_ts: int
    scope: DelegationScope = field(default_factory=DelegationScope)
    signer: str = "delegation-signer"
    signature: str = ""

    @property
    def cert_id(self) -> str:
        return digest_text(
            stable_json(
                {
                    "child_agent_id": self.child_agent_id,
                    "child_session_id": self.child_session_id,
                    "issued_ts": self.issued_ts,
                    "parent_agent_id": self.parent_agent_id,
                    "parent_session_id": self.parent_session_id,
                    "run_id": self.run_id,
                    "scope": {
                        "allowed_agents": self.scope.allowed_agents,
                        "allowed_tools": self.scope.allowed_tools,
                        "denied_tools": self.scope.denied_tools,
                        "expiry_ts": self.scope.expiry_ts,
                        "max_depth": self.scope.max_depth,
                        "sandbox_mode": self.scope.sandbox_mode,
                        "sub_delegation": self.scope.sub_delegation,
                    },
                }
            )
        )
