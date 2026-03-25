from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from .attestations import DelegationCertificate, PolicyAttestation
from .ids import digest_text, new_event_id, stable_json


class EventType(StrEnum):
    REQUEST_ACCEPTED = "RequestAccepted"
    PLAN_CREATED = "PlanCreated"
    TOOL_INVOCATION_REQUESTED = "ToolInvocationRequested"
    POLICY_DECISION = "PolicyDecision"
    TOOL_EXECUTION_STARTED = "ToolExecutionStarted"
    TOOL_EXECUTION_COMPLETED = "ToolExecutionCompleted"
    DELEGATION_INITIATED = "DelegationInitiated"
    DELEGATION_COMPLETED = "DelegationCompleted"
    FINAL_OUTPUT_PRODUCED = "FinalOutputProduced"
    RECOVERY_PLANNED = "RecoveryPlanned"
    RECOVERY_STARTED = "RecoveryStarted"
    RECOVERY_COMPLETED = "RecoveryCompleted"
    RECOVERY_FAILED = "RecoveryFailed"
    RECOVERY_VERIFIED = "RecoveryVerified"


@dataclass(frozen=True)
class CanonicalEvent:
    session_id: str
    run_id: str
    event_index: int
    event_type: EventType
    timestamp_ms: int
    actor_id: str
    source: str
    payload: dict[str, Any]
    parent_event_hash: str | None = None
    authority_root: str | None = None
    policy_attestation: PolicyAttestation | None = None
    delegation_certificate: DelegationCertificate | None = None
    signature: str | None = None

    @property
    def event_id(self) -> str:
        return new_event_id(session_id=self.session_id, event_index=self.event_index)

    @property
    def payload_hash(self) -> str:
        return digest_text(stable_json(self.payload))

    @property
    def event_hash(self) -> str:
        return digest_text(
            stable_json(
                {
                    "actor_id": self.actor_id,
                    "authority_root": self.authority_root,
                    "event_id": self.event_id,
                    "event_type": self.event_type.value,
                    "parent_event_hash": self.parent_event_hash,
                    "payload_hash": self.payload_hash,
                    "run_id": self.run_id,
                    "source": self.source,
                    "timestamp_ms": self.timestamp_ms,
                }
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "run_id": self.run_id,
            "event_index": self.event_index,
            "event_type": self.event_type.value,
            "timestamp_ms": self.timestamp_ms,
            "actor_id": self.actor_id,
            "source": self.source,
            "parent_event_hash": self.parent_event_hash,
            "authority_root": self.authority_root,
            "payload_hash": self.payload_hash,
            "payload": self.payload,
            "policy_attestation": (
                asdict(self.policy_attestation) if self.policy_attestation is not None else None
            ),
            "delegation_certificate": (
                {
                    **asdict(self.delegation_certificate),
                    "cert_id": self.delegation_certificate.cert_id,
                }
                if self.delegation_certificate is not None
                else None
            ),
            "signature": self.signature,
            "event_hash": self.event_hash,
        }
