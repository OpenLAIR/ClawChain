from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ClaimRecord:
    claim_kind: str
    evidence_expectation: str
    confidence: str

    def to_dict(self) -> dict[str, str]:
        return {
            "claim_kind": self.claim_kind,
            "evidence_expectation": self.evidence_expectation,
            "confidence": self.confidence,
        }


def extract_claims_from_output(output_text: str) -> tuple[ClaimRecord, ...]:
    text = output_text.lower()
    claims: list[ClaimRecord] = []
    if any(
        token in text
        for token in (
            "test passed",
            "tests passed",
            "validated",
            "validation passed",
            "all checks passed",
            "verified successfully",
        )
    ):
        claims.append(
            ClaimRecord(
                claim_kind="validation_passed",
                evidence_expectation="successful_validation_action",
                confidence="high",
            )
        )
    if any(
        token in text
        for token in (
            "restored",
            "recovered",
            "reinitialized",
            "rollback complete",
            "recovery completed",
            "backup restored",
        )
    ):
        claims.append(
            ClaimRecord(
                claim_kind="recovery_completed",
                evidence_expectation="successful_recovery_action",
                confidence="high",
            )
        )
    if any(
        token in text
        for token in (
            "fixed",
            "remediation complete",
            "remediation completed",
            "issue resolved",
            "resolved successfully",
            "mitigation complete",
        )
    ):
        claims.append(
            ClaimRecord(
                claim_kind="remediation_completed",
                evidence_expectation="successful_remediation_action",
                confidence="medium",
            )
        )
    return tuple(claims)


__all__ = ["ClaimRecord", "extract_claims_from_output"]
