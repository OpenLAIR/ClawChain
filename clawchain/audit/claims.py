from __future__ import annotations


def verify_claims(rows: list[dict], *, session_id: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    invocations_by_call_id = {
        str(row.get("payload", {}).get("tool_call_id")): row
        for row in rows
        if row.get("event_type") == "ToolInvocationRequested"
        and isinstance(row.get("payload", {}), dict)
        and row.get("payload", {}).get("tool_call_id") is not None
    }
    successful_actions = [
        row for row in rows if row.get("event_type") == "ToolExecutionCompleted" and _action_succeeded(row)
    ]
    successful_delegations = [row for row in rows if row.get("event_type") == "DelegationCompleted"]
    validation_actions = [
        row
        for row in successful_actions
        if _completed_action_matches(row, invocations_by_call_id, _looks_like_validation_command)
    ]
    recovery_actions = [
        row
        for row in successful_actions
        if _completed_action_matches(row, invocations_by_call_id, _looks_like_recovery_command)
    ]
    recovery_events = [
        row for row in rows if row.get("event_type") in {"RecoveryCompleted", "RecoveryVerified"}
    ]
    recovery_verified = [
        row
        for row in recovery_events
        if row.get("event_type") == "RecoveryVerified"
        and isinstance(row.get("payload", {}), dict)
        and row.get("payload", {}).get("verified") is True
    ]
    remediation_actions = [
        row
        for row in successful_actions
        if _completed_action_matches(row, invocations_by_call_id, _looks_like_remediation_command)
    ]

    for row in rows:
        if row.get("event_type") != "FinalOutputProduced":
            continue
        claims = row.get("payload", {}).get("claims", [])
        if not isinstance(claims, list):
            continue
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            kind = str(claim.get("claim_kind", ""))
            if kind == "validation_passed" and not validation_actions:
                findings.append(
                    (
                        "claim_validation_unsupported",
                        "final output claims validation success without a matching validation action",
                    )
                )
            if kind == "recovery_completed" and not (recovery_actions or recovery_verified or recovery_events):
                findings.append(
                    (
                        "claim_recovery_unsupported",
                        "final output claims recovery completion without a matching successful recovery action",
                    )
                )
            if kind == "remediation_completed" and not (
                remediation_actions or successful_actions or successful_delegations
            ):
                findings.append(
                    (
                        "claim_remediation_unsupported",
                        "final output claims remediation completion without supporting remediation action or delegation evidence",
                    )
                )
    return findings


def _action_succeeded(row: dict) -> bool:
    payload = row.get("payload", {})
    if not isinstance(payload, dict):
        return False
    exit_code = payload.get("exit_code")
    if isinstance(exit_code, int):
        return exit_code == 0
    result = payload.get("result")
    if isinstance(result, dict) and isinstance(result.get("exit_code"), int):
        return int(result["exit_code"]) == 0
    return True


def _completed_action_matches(
    row: dict,
    invocations_by_call_id: dict[str, dict],
    predicate: callable,
) -> bool:
    payload = row.get("payload", {})
    if not isinstance(payload, dict):
        return False
    tool_call_id = payload.get("tool_call_id")
    if tool_call_id is not None:
        invocation = invocations_by_call_id.get(str(tool_call_id))
        if invocation is not None and predicate(invocation.get("payload", {})):
            return True
    return predicate(payload)


def _looks_like_validation_command(payload: dict) -> bool:
    cmd = _extract_cmd(payload)
    if cmd is None:
        return False
    joined = " ".join(str(part).lower() for part in cmd)
    return any(
        token in joined
        for token in ("pytest", "unittest", "cargo test", "npm test", "pnpm test", "go test", "make test")
    )


def _looks_like_recovery_command(payload: dict) -> bool:
    cmd = _extract_cmd(payload)
    if cmd is None:
        return False
    joined = " ".join(str(part).lower() for part in cmd)
    return any(
        token in joined
        for token in ("restore", "recover", "rollback", "revert", "cp ", "rsync", "tar -x", "git checkout")
    )


def _looks_like_remediation_command(payload: dict) -> bool:
    cmd = _extract_cmd(payload)
    if cmd is None:
        return False
    joined = " ".join(str(part).lower() for part in cmd)
    return any(
        token in joined
        for token in ("apply_patch", "sed -i", "python", "mv ", "cp ", "mkdir", "chmod", "git apply", "patch")
    )


def _extract_cmd(payload: dict) -> list[object] | None:
    params = payload.get("params")
    if isinstance(params, dict) and isinstance(params.get("cmd"), list):
        return params.get("cmd")
    cmd = payload.get("cmd")
    if isinstance(cmd, list):
        return cmd
    return None


__all__ = ["verify_claims"]
