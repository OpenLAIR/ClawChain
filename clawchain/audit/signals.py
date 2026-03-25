from __future__ import annotations

from dataclasses import asdict, dataclass

from ..runtime.batching import AnchorReceipt


@dataclass(frozen=True)
class RiskSignal:
    code: str
    message: str
    session_id: str
    signal_type: str
    object_kind: str
    severity: str
    subject: str
    evidence_refs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def risk_signal_from_parts(*, code: str, message: str, session_id: str) -> RiskSignal:
    if "secret_access" in code:
        signal_type = "sensitive_access"
        object_kind = "secret"
        severity = "high"
    elif "config_" in code:
        signal_type = "configuration_integrity"
        object_kind = "configuration"
        severity = "high"
    elif "persistent_state" in code:
        signal_type = "persistent_state"
        object_kind = "persistent_state"
        severity = "high"
    elif "availability" in code:
        signal_type = "availability"
        object_kind = "service"
        severity = "high"
    elif "intent_drift" in code:
        signal_type = "intent_drift"
        object_kind = "action_sequence"
        severity = "medium"
    elif "initialization" in code or "supply_chain" in code:
        signal_type = "trust_bootstrap"
        object_kind = "tooling_registration"
        severity = "high"
    elif "claim_" in code:
        signal_type = "claim_truthfulness"
        object_kind = "claim"
        severity = "medium"
    elif "recovery_" in code:
        signal_type = "recovery"
        object_kind = "recovery_artifact"
        severity = "medium"
    else:
        signal_type = "audit_risk"
        object_kind = "session"
        severity = "medium"
    return RiskSignal(
        code=code,
        message=message,
        session_id=session_id,
        signal_type=signal_type,
        object_kind=object_kind,
        severity=severity,
        subject=session_id,
        evidence_refs=(session_id, code),
    )


def derive_signal_subject(
    *,
    code: str,
    session_id: str,
    rows: list[dict],
    receipts: list[AnchorReceipt],
) -> str:
    if "recovery_" in code:
        for row in rows:
            if not str(row.get("event_type", "")).startswith("Recovery"):
                continue
            payload = row.get("payload", {})
            if isinstance(payload, dict) and isinstance(payload.get("recovery_id"), str) and payload.get("recovery_id"):
                return str(payload["recovery_id"])
        for receipt in receipts:
            if receipt.session_id != session_id or receipt.commitment_type != "recovery":
                continue
            if receipt.subject_id:
                return receipt.subject_id
    return session_id


def derive_signal_evidence_refs(
    *,
    code: str,
    session_id: str,
    rows: list[dict],
    receipts: list[AnchorReceipt],
) -> tuple[str, ...]:
    event_refs: list[str] = []
    receipt_refs: list[str] = []
    for row in rows:
        event_type = str(row.get("event_type", ""))
        payload = row.get("payload", {})
        if not isinstance(payload, dict):
            continue
        event_id = str(row.get("event_id", ""))
        tool_name = str(payload.get("tool_name", ""))
        cmd_parts = _extract_cmd(payload)
        joined = " ".join(cmd_parts).lower() if cmd_parts else ""
        structured_secret_access = tool_name in {"secret.read_env", "secret.read_file"}
        if "secret_access" in code and (
            structured_secret_access
            or _looks_like_secret_access(joined)
            or event_type in {"ToolInvocationRequested", "PolicyDecision"} and tool_name == "system.run"
        ):
            if event_id:
                event_refs.append(f"event:{event_id}")
        elif "config_" in code and _looks_like_config_mutation(joined):
            if event_id:
                event_refs.append(f"event:{event_id}")
        elif "persistent_state" in code and _looks_like_persistent_state_mutation(joined):
            if event_id:
                event_refs.append(f"event:{event_id}")
        elif "availability" in code and _looks_like_availability_risk(joined):
            if event_id:
                event_refs.append(f"event:{event_id}")
        elif "intent_drift" in code and event_type in {"ToolInvocationRequested", "PolicyDecision"}:
            if event_id:
                event_refs.append(f"event:{event_id}")
        elif ("initialization" in code or "supply_chain" in code) and _looks_like_initialization_trust_grant(joined):
            if event_id:
                event_refs.append(f"event:{event_id}")
        elif "recovery_" in code and event_type.startswith("Recovery"):
            if event_id:
                event_refs.append(f"event:{event_id}")
        elif "claim_" in code and event_type == "FinalOutputProduced":
            if event_id:
                event_refs.append(f"event:{event_id}")
    for receipt in receipts:
        if receipt.session_id != session_id:
            continue
        ref = receipt.anchor_reference or f"{receipt.commitment_type}:{receipt.batch_seq_no}"
        if "config_recovery_artifact_missing" == code:
            if receipt.commitment_type == "backup_locator":
                receipt_refs.append(f"receipt:{ref}")
        elif "recovery_" in code:
            if receipt.commitment_type == "recovery":
                receipt_refs.append(f"receipt:{ref}")
        elif "initialization" in code or "supply_chain" in code or "persistent_state" in code or "availability" in code or "secret_access" in code or "config_" in code:
            if receipt.commitment_type == "event_batch":
                receipt_refs.append(f"receipt:{ref}")
        elif "claim_" in code:
            if receipt.commitment_type == "event_batch":
                receipt_refs.append(f"receipt:{ref}")
    refs = tuple(dict.fromkeys(event_refs + receipt_refs))
    if refs:
        return refs
    return (f"session:{session_id}", code)


def risk_signals_from_findings(findings: list[object]) -> list[RiskSignal]:
    return [
        risk_signal_from_parts(
            code=str(getattr(finding, "code")),
            message=str(getattr(finding, "message")),
            session_id=str(getattr(finding, "session_id")),
        )
        for finding in findings
    ]


def _extract_cmd(payload: dict) -> list[str] | None:
    params = payload.get("params")
    if isinstance(params, dict):
        cmd = params.get("cmd")
        if isinstance(cmd, list):
            return [str(part) for part in cmd]
    cmd = payload.get("cmd")
    if isinstance(cmd, list):
        return [str(part) for part in cmd]
    return None


def _looks_like_secret_access(joined: str) -> bool:
    return any(token in joined for token in ("id_rsa", ".env", "secrets", "token", "apikey", "credential"))


def _looks_like_config_mutation(joined: str) -> bool:
    return any(token in joined for token in (".bashrc", ".zshrc", ".config", "/etc/", "settings.json", "config"))


def _looks_like_persistent_state_mutation(joined: str) -> bool:
    return any(
        token in joined
        for token in ("memory", "plugin", "skill", "register", "install", "mcp", "state", "approval")
    )


def _looks_like_availability_risk(joined: str) -> bool:
    return any(
        token in joined
        for token in ("kill -9", "pkill", "restart", "systemctl", "reboot", "rm -rf /", "forkbomb", ":(){")
    )


def _looks_like_initialization_trust_grant(joined: str) -> bool:
    return any(
        token in joined
        for token in ("install plugin", "install skill", "register tool", "register mcp", "enable mcp", "grant trust")
    )


__all__ = [
    "RiskSignal",
    "derive_signal_evidence_refs",
    "derive_signal_subject",
    "risk_signal_from_parts",
    "risk_signals_from_findings",
]
