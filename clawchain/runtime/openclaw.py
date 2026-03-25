from __future__ import annotations

from dataclasses import dataclass

from ..capture import extract_claims_from_output
from ..canonical.attestations import DelegationCertificate, DelegationScope
from ..canonical.events import CanonicalEvent, EventType
from ..canonical.ids import digest_text
from .policy import PolicyAttestor, PolicyDecisionRecord


@dataclass(frozen=True)
class OpenClawRuntimeAdapter:
    source: str = "openclaw.runtime"
    policy_attestor: PolicyAttestor = PolicyAttestor()

    def request_accepted(
        self,
        *,
        session_id: str,
        run_id: str,
        event_index: int,
        timestamp_ms: int,
        channel: str,
        actor_id: str = "gateway",
        parent_event_hash: str | None = None,
        authority_root: str | None = None,
    ) -> CanonicalEvent:
        return CanonicalEvent(
            session_id=session_id,
            run_id=run_id,
            event_index=event_index,
            event_type=EventType.REQUEST_ACCEPTED,
            timestamp_ms=timestamp_ms,
            actor_id=actor_id,
            source=self.source,
            payload={"channel": channel},
            parent_event_hash=parent_event_hash,
            authority_root=authority_root,
        )

    def tool_invocation_requested(
        self,
        *,
        session_id: str,
        run_id: str,
        event_index: int,
        timestamp_ms: int,
        actor_id: str,
        tool_name: str,
        params: dict,
        tool_call_id: str | None,
        parent_event_hash: str | None,
    ) -> CanonicalEvent:
        return CanonicalEvent(
            session_id=session_id,
            run_id=run_id,
            event_index=event_index,
            event_type=EventType.TOOL_INVOCATION_REQUESTED,
            timestamp_ms=timestamp_ms,
            actor_id=actor_id,
            source=self.source,
            payload={
                "tool_name": tool_name,
                "params": params,
                "tool_call_id": tool_call_id,
                "normalized_args_hash": digest_text(str(params)),
            },
            parent_event_hash=parent_event_hash,
        )

    def policy_decision(
        self,
        *,
        session_id: str,
        run_id: str,
        event_index: int,
        timestamp_ms: int,
        actor_id: str,
        tool_name: str,
        params: dict,
        policy_name: str,
        policy_version: str,
        decision: str,
        reason: str,
        requires_ask: bool,
        approved_by_ask: bool,
        parent_event_hash: str | None,
    ) -> CanonicalEvent:
        event_id = f"{session_id}:{event_index}"
        normalized_args_hash = digest_text(str(params))
        attestation = self.policy_attestor.attest(
            PolicyDecisionRecord(
                session_id=session_id,
                run_id=run_id,
                event_id=event_id,
                tool_name=tool_name,
                normalized_args_hash=normalized_args_hash,
                actor_id=actor_id,
                policy_name=policy_name,
                policy_version=policy_version,
                decision=decision,
                reason=reason,
                requires_ask=requires_ask,
                approved_by_ask=approved_by_ask,
                timestamp_ms=timestamp_ms,
            )
        )
        return CanonicalEvent(
            session_id=session_id,
            run_id=run_id,
            event_index=event_index,
            event_type=EventType.POLICY_DECISION,
            timestamp_ms=timestamp_ms,
            actor_id=actor_id,
            source=self.source,
            payload={
                "tool_name": tool_name,
                "normalized_args_hash": normalized_args_hash,
                "policy_name": policy_name,
                "policy_version": policy_version,
                "policy_hash": attestation.policy_hash,
                "decision": decision,
                "reason": reason,
                "requires_ask": requires_ask,
                "approved_by_ask": approved_by_ask,
            },
            parent_event_hash=parent_event_hash,
            policy_attestation=attestation,
        )

    def delegation_initiated(
        self,
        *,
        parent_session_id: str,
        child_session_id: str,
        run_id: str,
        event_index: int,
        timestamp_ms: int,
        parent_agent_id: str,
        child_agent_id: str,
        mode: str,
        sandbox_mode: str,
        thread_requested: bool,
        allowed_agents: tuple[str, ...] = (),
        allowed_tools: tuple[str, ...] = ("*",),
        denied_tools: tuple[str, ...] = (),
        max_depth: int = 1,
        expiry_ts: int | None = None,
        parent_event_hash: str | None = None,
    ) -> CanonicalEvent:
        certificate = DelegationCertificate(
            parent_session_id=parent_session_id,
            child_session_id=child_session_id,
            parent_agent_id=parent_agent_id,
            child_agent_id=child_agent_id,
            run_id=run_id,
            issued_ts=timestamp_ms,
            scope=DelegationScope(
                allowed_tools=allowed_tools,
                denied_tools=denied_tools,
                sandbox_mode=sandbox_mode,
                sub_delegation=max_depth > 1,
                allowed_agents=allowed_agents,
                max_depth=max_depth,
                expiry_ts=expiry_ts,
            ),
            signature=digest_text(
                f"{parent_session_id}:{child_session_id}:{child_agent_id}:{timestamp_ms}"
            ),
        )
        return CanonicalEvent(
            session_id=parent_session_id,
            run_id=run_id,
            event_index=event_index,
            event_type=EventType.DELEGATION_INITIATED,
            timestamp_ms=timestamp_ms,
            actor_id=parent_agent_id,
            source=self.source,
            payload={
                "child_session_id": child_session_id,
                "child_agent_id": child_agent_id,
                "mode": mode,
                "sandbox_mode": sandbox_mode,
                "thread_requested": thread_requested,
                "allowed_agents": allowed_agents,
                "allowed_tools": allowed_tools,
                "denied_tools": denied_tools,
                "max_depth": max_depth,
                "expiry_ts": expiry_ts,
            },
            parent_event_hash=parent_event_hash,
            delegation_certificate=certificate,
        )

    def final_output_produced(
        self,
        *,
        session_id: str,
        run_id: str,
        event_index: int,
        timestamp_ms: int,
        actor_id: str,
        output_text: str,
        delivery_phase: str,
        channel: str,
        target: dict[str, str | int | None],
        parent_event_hash: str | None,
    ) -> CanonicalEvent:
        claims = [claim.to_dict() for claim in extract_claims_from_output(output_text)]
        return CanonicalEvent(
            session_id=session_id,
            run_id=run_id,
            event_index=event_index,
            event_type=EventType.FINAL_OUTPUT_PRODUCED,
            timestamp_ms=timestamp_ms,
            actor_id=actor_id,
            source=self.source,
            payload={
                "channel": channel,
                "delivery_phase": delivery_phase,
                "output_text_hash": digest_text(output_text),
                "claims": claims,
                "target": target,
            },
            parent_event_hash=parent_event_hash,
        )

    def recovery_planned(
        self,
        *,
        session_id: str,
        run_id: str,
        event_index: int,
        timestamp_ms: int,
        actor_id: str,
        recovery_id: str,
        target_path: str,
        source_kinds: tuple[str, ...],
        risk_reason: str,
        parent_event_hash: str | None,
    ) -> CanonicalEvent:
        return CanonicalEvent(
            session_id=session_id,
            run_id=run_id,
            event_index=event_index,
            event_type=EventType.RECOVERY_PLANNED,
            timestamp_ms=timestamp_ms,
            actor_id=actor_id,
            source=self.source,
            payload={
                "recovery_id": recovery_id,
                "target_path": target_path,
                "source_kinds": source_kinds,
                "risk_reason": risk_reason,
            },
            parent_event_hash=parent_event_hash,
        )

    def recovery_started(
        self,
        *,
        session_id: str,
        run_id: str,
        event_index: int,
        timestamp_ms: int,
        actor_id: str,
        recovery_id: str,
        target_path: str,
        source_kind: str,
        parent_event_hash: str | None,
    ) -> CanonicalEvent:
        return CanonicalEvent(
            session_id=session_id,
            run_id=run_id,
            event_index=event_index,
            event_type=EventType.RECOVERY_STARTED,
            timestamp_ms=timestamp_ms,
            actor_id=actor_id,
            source=self.source,
            payload={
                "recovery_id": recovery_id,
                "target_path": target_path,
                "source_kind": source_kind,
            },
            parent_event_hash=parent_event_hash,
        )

    def recovery_completed(
        self,
        *,
        session_id: str,
        run_id: str,
        event_index: int,
        timestamp_ms: int,
        actor_id: str,
        recovery_id: str,
        target_path: str,
        source_kind: str,
        restored_path: str,
        parent_event_hash: str | None,
    ) -> CanonicalEvent:
        return CanonicalEvent(
            session_id=session_id,
            run_id=run_id,
            event_index=event_index,
            event_type=EventType.RECOVERY_COMPLETED,
            timestamp_ms=timestamp_ms,
            actor_id=actor_id,
            source=self.source,
            payload={
                "recovery_id": recovery_id,
                "target_path": target_path,
                "source_kind": source_kind,
                "restored_path": restored_path,
            },
            parent_event_hash=parent_event_hash,
        )

    def recovery_failed(
        self,
        *,
        session_id: str,
        run_id: str,
        event_index: int,
        timestamp_ms: int,
        actor_id: str,
        recovery_id: str,
        target_path: str,
        source_kind: str,
        error_type: str,
        error_message: str,
        parent_event_hash: str | None,
    ) -> CanonicalEvent:
        return CanonicalEvent(
            session_id=session_id,
            run_id=run_id,
            event_index=event_index,
            event_type=EventType.RECOVERY_FAILED,
            timestamp_ms=timestamp_ms,
            actor_id=actor_id,
            source=self.source,
            payload={
                "recovery_id": recovery_id,
                "target_path": target_path,
                "source_kind": source_kind,
                "error_type": error_type,
                "error_message": error_message,
            },
            parent_event_hash=parent_event_hash,
        )

    def recovery_verified(
        self,
        *,
        session_id: str,
        run_id: str,
        event_index: int,
        timestamp_ms: int,
        actor_id: str,
        recovery_id: str,
        target_path: str,
        source_kind: str,
        verified: bool,
        expected_digest: str,
        observed_digest: str,
        parent_event_hash: str | None,
    ) -> CanonicalEvent:
        return CanonicalEvent(
            session_id=session_id,
            run_id=run_id,
            event_index=event_index,
            event_type=EventType.RECOVERY_VERIFIED,
            timestamp_ms=timestamp_ms,
            actor_id=actor_id,
            source=self.source,
            payload={
                "recovery_id": recovery_id,
                "target_path": target_path,
                "source_kind": source_kind,
                "verified": verified,
                "expected_digest": expected_digest,
                "observed_digest": observed_digest,
            },
            parent_event_hash=parent_event_hash,
        )
