from __future__ import annotations

from dataclasses import dataclass

from ..canonical.attestations import PolicyAttestation
from ..canonical.ids import digest_text


@dataclass(frozen=True)
class PolicyDecisionRecord:
    session_id: str
    run_id: str
    event_id: str
    tool_name: str
    normalized_args_hash: str
    actor_id: str
    policy_name: str
    policy_version: str
    decision: str
    reason: str
    requires_ask: bool
    approved_by_ask: bool
    timestamp_ms: int


@dataclass(frozen=True)
class PolicyAttestor:
    signer: str = "policy-engine-key"

    def attest(self, decision: PolicyDecisionRecord) -> PolicyAttestation:
        policy_hash = digest_text(f"{decision.policy_name}:{decision.policy_version}")
        signature = digest_text(
            f"{self.signer}:{decision.session_id}:{decision.event_id}:{decision.timestamp_ms}"
        )
        return PolicyAttestation(
            session_id=decision.session_id,
            run_id=decision.run_id,
            event_id=decision.event_id,
            tool_name=decision.tool_name,
            normalized_args_hash=decision.normalized_args_hash,
            actor_id=decision.actor_id,
            policy_name=decision.policy_name,
            policy_version=decision.policy_version,
            policy_hash=policy_hash,
            decision=decision.decision,
            reason=decision.reason,
            requires_ask=decision.requires_ask,
            approved_by_ask=decision.approved_by_ask,
            timestamp_ms=decision.timestamp_ms,
            signer=self.signer,
            signature=signature,
        )
