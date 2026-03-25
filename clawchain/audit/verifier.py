from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path

from .claims import verify_claims
from ..canonical.commitments import EncryptionScheme, manifest_digest_from_summary
from ..canonical.ids import digest_text
from ..runtime.anchor import AnchorSubmission
from ..runtime.batching import AnchorReceipt, merkle_root
from ..runtime.evidence_bundle import decrypt_bundle_payload

KNOWN_SUBMISSION_STATUSES = {"submitted", "pending", "confirmed", "timeout", "exported", "reverted"}


@dataclass(frozen=True)
class VerificationFinding:
    code: str
    message: str
    session_id: str


@dataclass
class VerificationReport:
    ok: bool = True
    findings: list[VerificationFinding] = field(default_factory=list)

    def add(self, code: str, message: str, session_id: str) -> None:
        self.ok = False
        self.findings.append(VerificationFinding(code=code, message=message, session_id=session_id))


@dataclass
class Verifier:
    def new_report(self) -> VerificationReport:
        return VerificationReport()

    def verify_session(
        self,
        *,
        rows: list[dict],
        receipts: list[AnchorReceipt],
        submissions: list[AnchorSubmission] | None = None,
        remote_rows: list[dict] | None = None,
        remote_receipts: list[AnchorReceipt] | None = None,
        remote_submissions: list[AnchorSubmission] | None = None,
        local_bundle_dirs: list[Path] | None = None,
        remote_bundles: dict[str, dict] | None = None,
        remote_metadata: dict[str, object] | None = None,
        bundle_private_keys: dict[str, str] | None = None,
    ) -> VerificationReport:
        report = VerificationReport()
        if not rows:
            return report
        rows = sorted(rows, key=lambda row: int(row["event_index"]))
        for index, row in enumerate(rows):
            if int(row["event_index"]) != index:
                report.add(
                    "event_index_gap",
                    f"expected event_index {index}, saw {row['event_index']}",
                    str(row["session_id"]),
                )
            if index > 0 and row.get("parent_event_hash") != rows[index - 1].get("event_hash"):
                report.add(
                    "hash_chain_break",
                    "parent_event_hash does not match previous event_hash",
                    str(row["session_id"]),
                )
        for code, message in verify_claims(rows, session_id=str(rows[0]["session_id"])):
            report.add(code, message, str(rows[0]["session_id"]))
        receipt_by_seq = {receipt.batch_seq_no: receipt for receipt in receipts}
        for expected_seq in range(len(receipt_by_seq)):
            if expected_seq not in receipt_by_seq:
                report.add(
                    "missing_batch_sequence",
                    f"missing batch sequence {expected_seq}",
                    str(rows[0]["session_id"]),
                )
        if receipts:
            receipt = receipt_by_seq.get(0)
            if receipt is not None:
                self._verify_receipts(
                    report=report,
                    session_id=str(rows[0]["session_id"]),
                    rows=rows,
                    receipts=receipts,
                    local_bundle_dirs=local_bundle_dirs or [],
                    bundle_private_keys=bundle_private_keys or {},
                )
        if submissions is not None:
            self._verify_submissions(
                report=report,
                session_id=str(rows[0]["session_id"]),
                receipts=receipts,
                submissions=submissions,
            )
        if remote_rows is not None or remote_receipts is not None or remote_submissions is not None:
            self._verify_remote_consistency(
                report=report,
                session_id=str(rows[0]["session_id"]),
                rows=rows,
                receipts=receipts,
                submissions=submissions or [],
                remote_rows=remote_rows or [],
                remote_receipts=remote_receipts or [],
                remote_submissions=remote_submissions or [],
                local_bundle_dirs=local_bundle_dirs or [],
                remote_bundles=remote_bundles or {},
                remote_metadata=remote_metadata or {},
            )
        return report

    def verify_remote_recovery(
        self,
        *,
        session_id: str,
        remote_rows: list[dict],
        remote_receipts: list[AnchorReceipt],
        remote_submissions: list[AnchorSubmission],
    ) -> VerificationReport:
        report = VerificationReport()
        if not remote_rows and not remote_receipts and not remote_submissions:
            report.add(
                "evidence_absent_both_local_and_remote",
                "no local evidence and no remote evidence available for recovery",
                session_id,
            )
            return report
        report.add(
            "local_evidence_missing_remote_recovery_available",
            "local evidence is missing but remote append-only evidence is still available",
            session_id,
        )
        remote_report = self.verify_session(
            rows=remote_rows,
            receipts=remote_receipts,
            submissions=remote_submissions,
        )
        report.ok = report.ok and remote_report.ok
        report.findings.extend(remote_report.findings)
        return report

    def analyze_session_risks(
        self,
        *,
        rows: list[dict],
        receipts: list[AnchorReceipt],
    ) -> list[VerificationFinding]:
        if not rows:
            return []
        session_id = str(rows[0]["session_id"])
        findings: list[VerificationFinding] = []
        invocation_rows = [
            row for row in rows if row.get("event_type") == "ToolInvocationRequested"
        ]
        policy_by_hash = {
            (str(row.get("payload", {}).get("tool_name", "")), str(row.get("payload", {}).get("normalized_args_hash", ""))): row
            for row in rows
            if row.get("event_type") == "PolicyDecision" and isinstance(row.get("payload", {}), dict)
        }
        has_backup_locator = any(receipt.commitment_type == "backup_locator" for receipt in receipts)
        has_recovery_receipt = any(receipt.commitment_type == "recovery" for receipt in receipts)
        recovery_events = [row for row in rows if str(row.get("event_type", "")).startswith("Recovery")]
        recovery_verified = [
            row
            for row in recovery_events
            if row.get("event_type") == "RecoveryVerified"
            and isinstance(row.get("payload", {}), dict)
            and row.get("payload", {}).get("verified") is True
        ]
        diagnostic_seen = False
        initialization_trust_grant_seen = False
        if recovery_events:
            findings.append(
                VerificationFinding(
                    code="recovery_flow_detected",
                    message="the session contains explicit recovery planning, execution, or verification events",
                    session_id=session_id,
                )
            )
        if recovery_verified:
            findings.append(
                VerificationFinding(
                    code="recovery_verification_detected",
                    message="the session contains a verified recovery result",
                    session_id=session_id,
                )
            )
        for row in invocation_rows:
            payload = row.get("payload", {})
            if not isinstance(payload, dict):
                continue
            tool_name = str(payload.get("tool_name", ""))
            args_hash = str(payload.get("normalized_args_hash", ""))
            policy = policy_by_hash.get((tool_name, args_hash))
            cmd = self._extract_cmd(payload)
            secret_access = tool_name in {"secret.read_env", "secret.read_file"} or self._looks_like_secret_access(cmd)
            if not cmd and not secret_access:
                continue
            if self._looks_like_diagnostic_action(cmd):
                diagnostic_seen = True
            if self._looks_like_initialization_trust_grant(cmd):
                initialization_trust_grant_seen = True
                findings.append(
                    VerificationFinding(
                        code="initialization_trust_grant_detected",
                        message="a startup, plugin, skill, or MCP registration action established new trusted agent capabilities",
                        session_id=session_id,
                    )
                )
                if policy is None:
                    findings.append(
                        VerificationFinding(
                            code="policy_initialization_trust_grant_unjustified",
                            message="initialization or registration trust grant has no matching policy decision record",
                            session_id=session_id,
                        )
                    )
                elif str(policy.get("payload", {}).get("decision")) == "allow":
                    findings.append(
                        VerificationFinding(
                            code="policy_initialization_trust_grant_allowed",
                            message="policy allowed a startup, plugin, skill, or MCP trust grant action",
                            session_id=session_id,
                        )
                    )
            if secret_access:
                if initialization_trust_grant_seen:
                    findings.append(
                        VerificationFinding(
                            code="supply_chain_follow_on_secret_access_detected",
                            message="secret access followed an initialization or registration trust grant in the same session",
                            session_id=session_id,
                        )
                    )
                if policy is None:
                    findings.append(
                        VerificationFinding(
                            code="policy_secret_access_unjustified",
                            message="secret access action has no matching policy decision record",
                            session_id=session_id,
                        )
                    )
                elif str(policy.get("payload", {}).get("decision")) == "allow":
                    findings.append(
                        VerificationFinding(
                            code="policy_secret_access_allowed",
                            message="policy allowed a secret or sensitive context access action",
                            session_id=session_id,
                        )
                    )
            if self._looks_like_config_mutation(cmd):
                findings.append(
                    VerificationFinding(
                        code="config_integrity_mutation_detected",
                        message="a destructive or mutating action targeted local configuration or environment state",
                        session_id=session_id,
                    )
                )
                if not (has_backup_locator or has_recovery_receipt or recovery_events):
                    findings.append(
                        VerificationFinding(
                            code="config_recovery_artifact_missing",
                            message="configuration mutation was observed without a protected recovery artifact",
                            session_id=session_id,
                        )
                    )
                if policy is None:
                    findings.append(
                        VerificationFinding(
                            code="policy_config_mutation_unjustified",
                            message="configuration mutation has no matching policy decision record",
                            session_id=session_id,
                        )
                    )
                elif str(policy.get("payload", {}).get("decision")) == "allow":
                    findings.append(
                        VerificationFinding(
                            code="policy_config_mutation_allowed",
                            message="policy allowed a destructive configuration or environment mutation",
                            session_id=session_id,
                        )
                    )
            if self._looks_like_persistent_state_mutation(cmd):
                findings.append(
                    VerificationFinding(
                        code="persistent_state_mutation_detected",
                        message="a privileged action modified persistent agent state, memory, plugin state, or tool registration",
                        session_id=session_id,
                    )
                )
                if policy is None:
                    findings.append(
                        VerificationFinding(
                            code="policy_persistent_state_mutation_unjustified",
                            message="persistent state mutation has no matching policy decision record",
                            session_id=session_id,
                        )
                    )
                elif str(policy.get("payload", {}).get("decision")) == "allow":
                    findings.append(
                        VerificationFinding(
                            code="policy_persistent_state_mutation_allowed",
                            message="policy allowed a persistent state mutation affecting future agent behavior",
                            session_id=session_id,
                        )
                    )
            availability_risk = self._looks_like_availability_risk(cmd)
            if availability_risk:
                findings.append(
                    VerificationFinding(
                        code="availability_risk_detected",
                        message="a command sequence indicates service restart, denial-of-service, or resource exhaustion risk",
                        session_id=session_id,
                    )
                )
                if policy is None:
                    findings.append(
                        VerificationFinding(
                            code="policy_availability_risk_unjustified",
                            message="availability-impacting action has no matching policy decision record",
                            session_id=session_id,
                        )
                    )
                elif str(policy.get("payload", {}).get("decision")) == "allow":
                    findings.append(
                        VerificationFinding(
                            code="policy_availability_risk_allowed",
                            message="policy allowed a service restart or resource exhaustion risk action",
                            session_id=session_id,
                        )
                    )
                if diagnostic_seen:
                    findings.append(
                        VerificationFinding(
                            code="intent_drift_sequence_detected",
                            message="session progressed from diagnostic actions to higher-risk service or availability mutations",
                            session_id=session_id,
                        )
                    )
        return self._dedupe_findings(findings)

    def analyze_session_risk_signals(
        self,
        *,
        rows: list[dict],
        receipts: list[AnchorReceipt],
    ) -> list[object]:
        from .signals import (
            RiskSignal,
            derive_signal_evidence_refs,
            derive_signal_subject,
            risk_signal_from_parts,
        )

        signals: list[RiskSignal] = []
        for finding in self.analyze_session_risks(
            rows=rows,
            receipts=receipts,
        ):
            base_signal = risk_signal_from_parts(
                code=finding.code,
                message=finding.message,
                session_id=finding.session_id,
            )
            signals.append(
                RiskSignal(
                    code=base_signal.code,
                    message=base_signal.message,
                    session_id=base_signal.session_id,
                    signal_type=base_signal.signal_type,
                    object_kind=base_signal.object_kind,
                    severity=base_signal.severity,
                    subject=derive_signal_subject(
                        code=finding.code,
                        session_id=finding.session_id,
                        rows=rows,
                        receipts=receipts,
                    ),
                    evidence_refs=derive_signal_evidence_refs(
                        code=finding.code,
                        session_id=finding.session_id,
                        rows=rows,
                        receipts=receipts,
                    ),
                )
            )
        return signals

    def _verify_remote_consistency(
        self,
        *,
        report: VerificationReport,
        session_id: str,
        rows: list[dict],
        receipts: list[AnchorReceipt],
        submissions: list[AnchorSubmission],
        remote_rows: list[dict],
        remote_receipts: list[AnchorReceipt],
        remote_submissions: list[AnchorSubmission],
        local_bundle_dirs: list[Path],
        remote_bundles: dict[str, dict],
        remote_metadata: dict[str, object],
    ) -> None:
        local_rows_by_event = {str(row["event_id"]): row for row in rows}
        remote_rows_by_event = {str(row["event_id"]): row for row in remote_rows}
        for event_id, row in local_rows_by_event.items():
            remote_row = remote_rows_by_event.get(event_id)
            if remote_row is None:
                report.add("remote_event_missing", f"remote copy missing event {event_id}", session_id)
                continue
            if self._stable_json(row) != self._stable_json(remote_row):
                report.add(
                    "remote_event_mismatch",
                    f"remote copy does not match local event {event_id}",
                    session_id,
                )
        for event_id in remote_rows_by_event:
            if event_id not in local_rows_by_event:
                report.add("remote_event_orphan", f"remote copy has orphan event {event_id}", session_id)

        local_receipt_by_seq = {receipt.batch_seq_no: receipt for receipt in receipts}
        remote_receipt_by_seq = {receipt.batch_seq_no: receipt for receipt in remote_receipts}
        for seq_no, receipt in local_receipt_by_seq.items():
            remote_receipt = remote_receipt_by_seq.get(seq_no)
            if remote_receipt is None:
                report.add(
                    "remote_receipt_missing",
                    f"remote copy missing receipt for batch sequence {seq_no}",
                    session_id,
                )
                continue
            if receipt != remote_receipt:
                report.add(
                    "remote_receipt_mismatch",
                    f"remote copy does not match local receipt for batch sequence {seq_no}",
                    session_id,
                )
        for seq_no in remote_receipt_by_seq:
            if seq_no not in local_receipt_by_seq:
                report.add(
                    "remote_receipt_orphan",
                    f"remote copy has orphan receipt for batch sequence {seq_no}",
                    session_id,
                )

        local_submission_by_key = {
            (submission.batch_seq_no, submission.anchor_reference): submission for submission in submissions
        }
        remote_submission_by_key = {
            (submission.batch_seq_no, submission.anchor_reference): submission
            for submission in remote_submissions
        }
        for key, submission in local_submission_by_key.items():
            remote_submission = remote_submission_by_key.get(key)
            if remote_submission is None:
                report.add(
                    "remote_submission_missing",
                    f"remote copy missing submission for batch sequence {key[0]}",
                    session_id,
                )
                continue
            if submission != remote_submission:
                report.add(
                    "remote_submission_mismatch",
                    f"remote copy does not match local submission for batch sequence {key[0]}",
                    session_id,
                )
        for key in remote_submission_by_key:
            if key not in local_submission_by_key:
                report.add(
                    "remote_submission_orphan",
                    f"remote copy has orphan submission for batch sequence {key[0]}",
                    session_id,
                )
        for receipt in receipts:
            bundle_ref = (receipt.metadata or {}).get("encrypted_bundle_ref")
            if not bundle_ref:
                continue
            local_bundle = self._load_bundle(str(bundle_ref), local_bundle_dirs)
            if local_bundle is None:
                continue
            remote_bundle = remote_bundles.get(str(bundle_ref))
            if remote_bundle is None:
                report.add(
                    "remote_bundle_missing",
                    f"remote copy missing encrypted bundle {bundle_ref}",
                    session_id,
                )
                continue
            if self._stable_json(local_bundle) != self._stable_json(remote_bundle):
                report.add(
                    "remote_bundle_mismatch",
                    f"remote copy does not match encrypted bundle {bundle_ref}",
                    session_id,
                )
        referenced_bundle_refs = {
            str((receipt.metadata or {}).get("encrypted_bundle_ref"))
            for receipt in receipts
            if (receipt.metadata or {}).get("encrypted_bundle_ref")
        }
        for bundle_ref in remote_bundles:
            if bundle_ref not in referenced_bundle_refs:
                report.add(
                    "remote_bundle_orphan",
                    f"remote copy has orphan encrypted bundle {bundle_ref}",
                    session_id,
                )
        self._verify_remote_sidecar_metadata(
            report=report,
            session_id=session_id,
            remote_metadata=remote_metadata,
        )

    def _verify_remote_sidecar_metadata(
        self,
        *,
        report: VerificationReport,
        session_id: str,
        remote_metadata: dict[str, object],
    ) -> None:
        if not remote_metadata:
            return
        valid, error = self._validate_remote_sidecar_metadata(remote_metadata)
        if error == "missing_profile":
            report.add(
                "remote_sidecar_metadata_missing",
                "remote evidence metadata is present but sidecar security profile is missing",
                session_id,
            )
            return
        if not valid:
            report.add(
                "remote_sidecar_metadata_invalid",
                error or "remote sidecar metadata is invalid",
                session_id,
            )
            return
        profile = remote_metadata["sidecar_security_profile"]
        if profile.get("auth_enabled") is not True:
            report.add(
                "remote_sidecar_auth_disabled",
                "remote sidecar security profile reports authentication disabled",
                session_id,
            )
        if profile.get("replay_protection_enabled") is not True:
            report.add(
                "remote_sidecar_replay_protection_disabled",
                "remote sidecar security profile reports replay protection disabled",
                session_id,
            )
        if profile.get("read_write_split") is not True:
            report.add(
                "remote_sidecar_read_write_split_disabled",
                "remote sidecar security profile reports no read/write credential separation",
                session_id,
            )

    def _validate_remote_sidecar_metadata(self, remote_metadata: dict[str, object]) -> tuple[bool, str | None]:
        profile = remote_metadata.get("sidecar_security_profile")
        if profile is None:
            return False, "missing_profile"
        metadata_version = remote_metadata.get("sidecar_metadata_version")
        if metadata_version is not None and metadata_version != "v1":
            return False, "remote sidecar metadata version is invalid"
        service_instance_id = remote_metadata.get("sidecar_service_instance_id")
        if service_instance_id is not None and (not isinstance(service_instance_id, str) or not service_instance_id):
            return False, "remote sidecar service instance id is invalid"
        started_at_ms = remote_metadata.get("sidecar_started_at_ms")
        if started_at_ms is not None and (not isinstance(started_at_ms, int) or started_at_ms <= 0):
            return False, "remote sidecar started_at timestamp is invalid"
        if not isinstance(profile, dict):
            return False, "remote sidecar security profile is not a valid object"
        required_fields = {
            "auth_enabled",
            "read_write_split",
            "replay_protection_enabled",
            "max_clock_skew_ms",
            "replay_window_size",
        }
        missing_fields = sorted(field for field in required_fields if field not in profile)
        if missing_fields:
            return False, f"remote sidecar security profile is missing fields: {', '.join(missing_fields)}"
        if not isinstance(profile.get("auth_enabled"), bool):
            return False, "remote sidecar security profile auth_enabled must be a boolean"
        if not isinstance(profile.get("read_write_split"), bool):
            return False, "remote sidecar security profile read_write_split must be a boolean"
        if not isinstance(profile.get("replay_protection_enabled"), bool):
            return False, "remote sidecar security profile replay_protection_enabled must be a boolean"
        if not isinstance(profile.get("max_clock_skew_ms"), int) or profile.get("max_clock_skew_ms", 0) <= 0:
            return False, "remote sidecar security profile max_clock_skew_ms must be a positive integer"
        if not isinstance(profile.get("replay_window_size"), int) or profile.get("replay_window_size", 0) <= 0:
            return False, "remote sidecar security profile replay_window_size must be a positive integer"
        transport_mode = profile.get("transport_mode")
        if transport_mode is not None and transport_mode not in {"http", "unix", "local", "generic"}:
            return False, "remote sidecar security profile transport_mode is invalid"
        credential_mode = profile.get("credential_mode")
        if credential_mode is not None and credential_mode not in {"none", "shared", "split"}:
            return False, "remote sidecar security profile credential_mode is invalid"
        return True, None

    def _extract_cmd(self, payload: dict) -> list[str]:
        params = payload.get("params")
        cmd = params.get("cmd") if isinstance(params, dict) else payload.get("cmd")
        if not isinstance(cmd, list):
            return []
        return [str(part) for part in cmd]

    def _looks_like_secret_access(self, cmd: list[str]) -> bool:
        joined = " ".join(part.lower() for part in cmd)
        sensitive_markers = (
            ".env",
            "id_rsa",
            ".ssh",
            "kubeconfig",
            "credentials",
            "secrets",
            "token",
            "apikey",
            "api_key",
        )
        return any(marker in joined for marker in sensitive_markers)

    def _looks_like_config_mutation(self, cmd: list[str]) -> bool:
        joined = " ".join(part.lower() for part in cmd)
        target_markers = (
            ".bashrc",
            ".zshrc",
            "~/.config",
            ".config/",
            "settings.local.json",
            "settings.json",
            "config.toml",
            "config.yaml",
            "config.yml",
        )
        destructive_markers = ("rm ", "rm -", "mv ", "cp ", "sed -i", "printf ", "echo ", "cat >")
        return any(marker in joined for marker in target_markers) and any(
            marker in joined for marker in destructive_markers
        )

    def _looks_like_persistent_state_mutation(self, cmd: list[str]) -> bool:
        joined = " ".join(part.lower() for part in cmd)
        state_markers = (
            "memory.json",
            "memory.db",
            "session_memory",
            "approve-all",
            "plugin install",
            "skill install",
            "mcp register",
            "tool registry",
            ".openclaw/",
            "state.json",
        )
        mutation_markers = ("printf ", "echo ", "cat >", "tee ", "cp ", "mv ", "sed -i", "python", "touch ")
        return any(marker in joined for marker in state_markers) and any(
            marker in joined for marker in mutation_markers
        )

    def _looks_like_availability_risk(self, cmd: list[str]) -> bool:
        joined = " ".join(part.lower() for part in cmd)
        risk_markers = (
            "systemctl restart",
            "service restart",
            "reboot",
            "shutdown -r",
            "stress",
            "yes >",
            "while true",
            "forkbomb",
            ":(){",
            "killall",
            "pkill",
            "dd if=/dev/zero",
            "ulimit -n",
            "ufw disable",
        )
        return any(marker in joined for marker in risk_markers)

    def _looks_like_diagnostic_action(self, cmd: list[str]) -> bool:
        joined = " ".join(part.lower() for part in cmd)
        diagnostic_markers = (
            "systemctl status",
            "journalctl",
            "ps ",
            "top",
            "df -h",
            "free -m",
            "curl -i",
            "cat /var/log",
        )
        return any(marker in joined for marker in diagnostic_markers)

    def _looks_like_initialization_trust_grant(self, cmd: list[str]) -> bool:
        joined = " ".join(part.lower() for part in cmd)
        registration_markers = (
            "plugin install",
            "skill install",
            "mcp register",
            "server register",
            ".mcp.json",
            "tool_registry.json",
            "skills/",
            "plugins/",
            "pip install",
            "npm install",
            "pnpm add",
        )
        mutation_markers = ("echo ", "printf ", "cat >", "tee ", "cp ", "mv ", "python", "touch ")
        return any(marker in joined for marker in registration_markers) and any(
            marker in joined for marker in mutation_markers
        )

    def _dedupe_findings(self, findings: list[VerificationFinding]) -> list[VerificationFinding]:
        seen: set[tuple[str, str, str]] = set()
        deduped: list[VerificationFinding] = []
        for finding in findings:
            key = (finding.code, finding.message, finding.session_id)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

    def _verify_submissions(
        self,
        *,
        report: VerificationReport,
        session_id: str,
        receipts: list[AnchorReceipt],
        submissions: list[AnchorSubmission],
    ) -> None:
        receipt_by_seq = {receipt.batch_seq_no: receipt for receipt in receipts}
        submission_by_seq = {submission.batch_seq_no: submission for submission in submissions}

        for seq_no in receipt_by_seq:
            if seq_no not in submission_by_seq:
                report.add(
                    "missing_submission",
                    f"missing submission for batch sequence {seq_no}",
                    session_id,
                )

        for seq_no, submission in submission_by_seq.items():
            receipt = receipt_by_seq.get(seq_no)
            if receipt is None:
                report.add(
                    "orphan_submission",
                    f"submission exists without receipt for batch sequence {seq_no}",
                    session_id,
                )
                continue
            if submission.merkle_root != receipt.merkle_root:
                report.add(
                    "submission_merkle_root_mismatch",
                    f"submission merkle root does not match receipt for batch sequence {seq_no}",
                    session_id,
                )
            receipt_manifest = (receipt.metadata or {}).get("encryption_manifest_digest")
            submission_manifest = submission.metadata.get("encryption_manifest_digest")
            if receipt_manifest != submission_manifest:
                report.add(
                    "submission_encryption_manifest_mismatch",
                    f"submission encryption_manifest_digest does not match receipt for batch sequence {seq_no}",
                    session_id,
                )
            if submission.commitment_type != receipt.commitment_type:
                report.add(
                    "submission_commitment_type_mismatch",
                    f"submission commitment_type does not match receipt for batch sequence {seq_no}",
                    session_id,
                )
            if submission.subject_id != receipt.subject_id:
                report.add(
                    "submission_subject_id_mismatch",
                    f"submission subject_id does not match receipt for batch sequence {seq_no}",
                    session_id,
                )
            if tuple(submission.event_ids) != tuple(receipt.event_ids):
                report.add(
                    "submission_event_ids_mismatch",
                    f"submission event_ids do not match receipt for batch sequence {seq_no}",
                    session_id,
                )
            if submission.anchor_mode != receipt.anchor_mode:
                report.add(
                    "submission_anchor_mode_mismatch",
                    f"submission anchor_mode does not match receipt for batch sequence {seq_no}",
                    session_id,
                )
            if receipt.anchor_backend is not None and submission.anchor_backend != receipt.anchor_backend:
                report.add(
                    "submission_anchor_backend_mismatch",
                    f"submission anchor_backend does not match receipt for batch sequence {seq_no}",
                    session_id,
                )
            if (
                receipt.anchor_reference is not None
                and submission.anchor_reference != receipt.anchor_reference
            ):
                report.add(
                    "submission_anchor_reference_mismatch",
                    f"submission anchor_reference does not match receipt for batch sequence {seq_no}",
                    session_id,
                )
            self._verify_submission_status(
                report=report,
                session_id=session_id,
                seq_no=seq_no,
                submission=submission,
            )

    def _verify_receipts(
        self,
        *,
        report: VerificationReport,
        session_id: str,
        rows: list[dict],
        receipts: list[AnchorReceipt],
        local_bundle_dirs: list[Path],
        bundle_private_keys: dict[str, str],
    ) -> None:
        rows_by_event_id = {
            str(row.get("event_id", f"{row.get('session_id', session_id)}:{row.get('event_index', index)}")): row
            for index, row in enumerate(rows)
        }
        for receipt in receipts:
            metadata = receipt.metadata or {}
            if receipt.commitment_type == "event_batch":
                if receipt.subject_id != session_id:
                    report.add(
                        "event_batch_subject_mismatch",
                        f"event_batch subject_id does not match session_id for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                batch_rows = [rows_by_event_id[event_id] for event_id in receipt.event_ids if event_id in rows_by_event_id]
                if len(batch_rows) != len(receipt.event_ids):
                    report.add(
                        "event_batch_event_missing",
                        f"event_batch receipt references missing events for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                observed_root = merkle_root([str(row["event_hash"]) for row in batch_rows])
                if observed_root != receipt.merkle_root:
                    report.add(
                        "merkle_root_mismatch",
                        "event_batch merkle root does not match receipt event subset",
                        session_id,
                    )
                event_count = metadata.get("event_count")
                if event_count is not None and int(event_count) != len(batch_rows):
                    report.add(
                        "event_batch_count_mismatch",
                        f"event_batch metadata event_count does not match observed batch rows for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("encryption_manifest_digest"):
                    report.add(
                        "event_batch_manifest_missing",
                        f"event_batch encryption_manifest_digest is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("commitment_envelope_digest"):
                    report.add(
                        "event_batch_envelope_missing",
                        f"event_batch commitment_envelope_digest is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                encrypted_bundle_ref = metadata.get("encrypted_bundle_ref")
                if encrypted_bundle_ref:
                    local_bundle = self._load_bundle(str(encrypted_bundle_ref), local_bundle_dirs)
                    if local_bundle is None:
                        report.add(
                            "event_batch_bundle_missing",
                            f"event_batch encrypted bundle is missing for batch sequence {receipt.batch_seq_no}",
                            session_id,
                        )
                    else:
                        self._verify_bundle_contents(
                            report=report,
                            session_id=session_id,
                            receipt=receipt,
                            bundle=local_bundle,
                            expected_kind="event_batch",
                            expected_subject_id=receipt.subject_id or "",
                            code_prefix="event_batch_bundle",
                            private_key_pem=bundle_private_keys.get("event_batch"),
                        )
                    self._verify_manifest_summary(
                        report=report,
                        session_id=session_id,
                        receipt=receipt,
                        expected_payload_scheme=EncryptionScheme.AES_256_GCM.value,
                        expected_key_wrap_scheme=EncryptionScheme.RSA_OAEP_SHA256.value,
                        expected_ciphertext_digest=None,
                        access_policy_digest=metadata.get("encryption_manifest", {}).get("access_policy_digest")
                        if isinstance(metadata.get("encryption_manifest"), dict)
                        else None,
                        expected_access_policy_digest=digest_text("event-batch-confidential-audit"),
                        missing_code="event_batch_manifest_summary_missing",
                        invalid_code="event_batch_manifest_summary_invalid",
                    )
                else:
                    self._verify_manifest_summary(
                        report=report,
                        session_id=session_id,
                        receipt=receipt,
                        expected_payload_scheme=EncryptionScheme.NONE.value,
                        expected_key_wrap_scheme=EncryptionScheme.NONE.value,
                        expected_ciphertext_digest=receipt.merkle_root,
                        access_policy_digest=metadata.get("encryption_manifest", {}).get("access_policy_digest")
                        if isinstance(metadata.get("encryption_manifest"), dict)
                        else None,
                        expected_access_policy_digest=None,
                        missing_code="event_batch_manifest_summary_missing",
                        invalid_code="event_batch_manifest_summary_invalid",
                    )
            elif receipt.commitment_type == "backup_locator":
                if not receipt.subject_id:
                    report.add(
                        "backup_locator_subject_missing",
                        f"backup_locator subject_id is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("snapshot_digest"):
                    report.add(
                        "backup_locator_snapshot_digest_missing",
                        f"backup_locator snapshot_digest is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("encryption_manifest_digest"):
                    report.add(
                        "backup_locator_manifest_missing",
                        f"backup_locator encryption_manifest_digest is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("commitment_envelope_digest"):
                    report.add(
                        "backup_locator_envelope_missing",
                        f"backup_locator commitment_envelope_digest is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                encrypted_bundle_ref = metadata.get("encrypted_bundle_ref")
                if encrypted_bundle_ref:
                    local_bundle = self._load_bundle(str(encrypted_bundle_ref), local_bundle_dirs)
                    if local_bundle is None:
                        report.add(
                            "backup_locator_bundle_missing",
                            f"backup_locator encrypted bundle is missing for batch sequence {receipt.batch_seq_no}",
                            session_id,
                        )
                    else:
                        self._verify_bundle_contents(
                            report=report,
                            session_id=session_id,
                            receipt=receipt,
                            bundle=local_bundle,
                            expected_kind="backup_locator",
                            expected_subject_id=receipt.subject_id or "",
                            code_prefix="backup_locator_bundle",
                            private_key_pem=bundle_private_keys.get("backup_locator"),
                        )
                self._verify_manifest_summary(
                    report=report,
                    session_id=session_id,
                    receipt=receipt,
                    expected_payload_scheme=EncryptionScheme.AES_256_GCM.value,
                    expected_key_wrap_scheme=EncryptionScheme.RSA_OAEP_SHA256.value,
                    expected_ciphertext_digest=None,
                    access_policy_digest=metadata.get("recovery_policy_digest"),
                    expected_access_policy_digest=metadata.get("recovery_policy_digest"),
                    missing_code="backup_locator_manifest_summary_missing",
                    invalid_code="backup_locator_manifest_summary_invalid",
                )
            elif receipt.commitment_type == "delegation":
                if not receipt.subject_id:
                    report.add(
                        "delegation_subject_missing",
                        f"delegation subject_id is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("parent_session_id"):
                    report.add(
                        "delegation_parent_session_missing",
                        f"delegation parent_session_id is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("delegation_scope_digest"):
                    report.add(
                        "delegation_scope_digest_missing",
                        f"delegation scope digest is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("encryption_manifest_digest"):
                    report.add(
                        "delegation_manifest_missing",
                        f"delegation encryption_manifest_digest is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("commitment_envelope_digest"):
                    report.add(
                        "delegation_envelope_missing",
                        f"delegation commitment_envelope_digest is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                encrypted_bundle_ref = metadata.get("encrypted_bundle_ref")
                if encrypted_bundle_ref:
                    local_bundle = self._load_bundle(str(encrypted_bundle_ref), local_bundle_dirs)
                    if local_bundle is None:
                        report.add(
                            "delegation_bundle_missing",
                            f"delegation encrypted bundle is missing for batch sequence {receipt.batch_seq_no}",
                            session_id,
                        )
                    else:
                        self._verify_bundle_contents(
                            report=report,
                            session_id=session_id,
                            receipt=receipt,
                            bundle=local_bundle,
                            expected_kind="delegation",
                            expected_subject_id=receipt.subject_id or "",
                            code_prefix="delegation_bundle",
                            private_key_pem=bundle_private_keys.get("delegation"),
                        )
                    self._verify_manifest_summary(
                        report=report,
                        session_id=session_id,
                        receipt=receipt,
                        expected_payload_scheme=EncryptionScheme.AES_256_GCM.value,
                        expected_key_wrap_scheme=EncryptionScheme.RSA_OAEP_SHA256.value,
                        expected_ciphertext_digest=None,
                        access_policy_digest=metadata.get("delegation_scope_digest"),
                        expected_access_policy_digest=digest_text("delegation-confidential-audit"),
                        missing_code="delegation_manifest_summary_missing",
                        invalid_code="delegation_manifest_summary_invalid",
                    )
                else:
                    self._verify_manifest_summary(
                        report=report,
                        session_id=session_id,
                        receipt=receipt,
                        expected_payload_scheme=EncryptionScheme.NONE.value,
                        expected_key_wrap_scheme=EncryptionScheme.NONE.value,
                        expected_ciphertext_digest=receipt.event_ids[0] if receipt.event_ids else None,
                        access_policy_digest=metadata.get("delegation_scope_digest"),
                        expected_access_policy_digest=None,
                        missing_code="delegation_manifest_summary_missing",
                        invalid_code="delegation_manifest_summary_invalid",
                    )
            elif receipt.commitment_type == "recovery":
                if not receipt.subject_id:
                    report.add(
                        "recovery_subject_missing",
                        f"recovery subject_id is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("target_path_hash"):
                    report.add(
                        "recovery_target_path_hash_missing",
                        f"recovery target_path_hash is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("source_kind"):
                    report.add(
                        "recovery_source_kind_missing",
                        f"recovery source_kind is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("phase"):
                    report.add(
                        "recovery_phase_missing",
                        f"recovery phase is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if metadata.get("phase") not in {"planned", "completed", "verified"}:
                    report.add(
                        "recovery_phase_invalid",
                        f"recovery phase is invalid for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if metadata.get("phase") == "verified" and "expected_digest" not in metadata:
                    report.add(
                        "recovery_expected_digest_missing",
                        f"verified recovery receipt is missing expected_digest for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if metadata.get("phase") == "verified" and metadata.get("verified") is not True:
                    report.add(
                        "recovery_verified_flag_invalid",
                        f"verified recovery receipt does not declare verified=true for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if receipt.event_ids and receipt.subject_id != receipt.event_ids[0]:
                    report.add(
                        "recovery_subject_event_mismatch",
                        f"recovery subject_id does not match event_ids[0] for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if metadata.get("recovery_id") != receipt.subject_id:
                    report.add(
                        "recovery_metadata_subject_mismatch",
                        f"recovery metadata recovery_id does not match subject_id for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if metadata.get("phase") == "planned" and metadata.get("verified") is not False:
                    report.add(
                        "recovery_planned_verified_flag_invalid",
                        f"planned recovery receipt must declare verified=false for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if metadata.get("phase") == "verified" and metadata.get("expected_digest") != receipt.merkle_root:
                    report.add(
                        "recovery_expected_digest_mismatch",
                        f"verified recovery expected_digest does not match receipt merkle_root for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )
                if not metadata.get("commitment_envelope_digest"):
                    report.add(
                        "recovery_envelope_missing",
                        f"recovery commitment_envelope_digest is missing for batch sequence {receipt.batch_seq_no}",
                        session_id,
                    )

    def _verify_submission_status(
        self,
        *,
        report: VerificationReport,
        session_id: str,
        seq_no: int,
        submission: AnchorSubmission,
    ) -> None:
        if submission.status not in KNOWN_SUBMISSION_STATUSES:
            report.add(
                "submission_unknown_status",
                f"submission has unknown status {submission.status!r} for batch sequence {seq_no}",
                session_id,
            )
            return
        if submission.status == "confirmed":
            poll_meta = submission.metadata.get("poll")
            confirmations = None
            if isinstance(poll_meta, dict) and poll_meta.get("confirmations") is not None:
                confirmations = int(poll_meta["confirmations"])
            if confirmations is not None and confirmations < 1:
                report.add(
                    "submission_confirmed_without_confirmations",
                    f"submission is confirmed without confirmations for batch sequence {seq_no}",
                    session_id,
                )
        if submission.status == "timeout":
            poll_attempts = submission.metadata.get("poll_attempts")
            if poll_attempts is None or int(poll_attempts) < 1:
                report.add(
                    "submission_timeout_without_poll_attempts",
                    f"submission timed out without poll attempts for batch sequence {seq_no}",
                    session_id,
                )
        if submission.status == "reverted":
            poll_meta = submission.metadata.get("poll")
            raw_status = poll_meta.get("status") if isinstance(poll_meta, dict) else None
            if raw_status != "reverted":
                report.add(
                    "submission_reverted_without_poll_status",
                    f"submission is reverted without reverted poll status for batch sequence {seq_no}",
                    session_id,
                )

    def _stable_json(self, value: object) -> str:
        return json.dumps(value, sort_keys=True, ensure_ascii=True)

    def _load_bundle(self, bundle_ref: str, candidate_dirs: list[Path]) -> dict[str, object] | None:
        for directory in candidate_dirs:
            path = directory / bundle_ref
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        return None

    def _verify_bundle_contents(
        self,
        *,
        report: VerificationReport,
        session_id: str,
        receipt: AnchorReceipt,
        bundle: dict[str, object],
        expected_kind: str,
        expected_subject_id: str,
        code_prefix: str,
        private_key_pem: str | None = None,
    ) -> None:
        if str(bundle.get("bundle_kind")) != expected_kind:
            report.add(
                f"{code_prefix}_kind_mismatch",
                f"{receipt.commitment_type} bundle_kind is invalid for batch sequence {receipt.batch_seq_no}",
                session_id,
            )
        if str(bundle.get("subject_id")) != expected_subject_id:
            report.add(
                f"{code_prefix}_subject_mismatch",
                f"{receipt.commitment_type} bundle subject_id is invalid for batch sequence {receipt.batch_seq_no}",
                session_id,
            )
        bundle_manifest = bundle.get("manifest")
        receipt_manifest = (receipt.metadata or {}).get("encryption_manifest")
        if not isinstance(bundle_manifest, dict) or not isinstance(receipt_manifest, dict):
            report.add(
                f"{code_prefix}_manifest_missing",
                f"{receipt.commitment_type} bundle manifest is missing for batch sequence {receipt.batch_seq_no}",
                session_id,
            )
            return
        if self._stable_json(bundle_manifest) != self._stable_json(receipt_manifest):
            report.add(
                f"{code_prefix}_manifest_mismatch",
                f"{receipt.commitment_type} bundle manifest does not match receipt metadata for batch sequence {receipt.batch_seq_no}",
                session_id,
            )
        if private_key_pem is None:
            return
        try:
            plaintext = decrypt_bundle_payload(payload=bundle, recipient_private_key_pem=private_key_pem)
        except Exception:
            report.add(
                f"{code_prefix}_decryption_failed",
                f"{receipt.commitment_type} bundle decryption failed for batch sequence {receipt.batch_seq_no}",
                session_id,
            )
            return
        self._verify_decrypted_bundle_payload(
            report=report,
            session_id=session_id,
            receipt=receipt,
            plaintext=plaintext,
            expected_kind=expected_kind,
            code_prefix=code_prefix,
        )

    def _verify_decrypted_bundle_payload(
        self,
        *,
        report: VerificationReport,
        session_id: str,
        receipt: AnchorReceipt,
        plaintext: dict[str, object],
        expected_kind: str,
        code_prefix: str,
    ) -> None:
        if expected_kind == "event_batch":
            if str(plaintext.get("session_id")) != str(receipt.subject_id):
                report.add(
                    f"{code_prefix}_payload_subject_mismatch",
                    f"event_batch decrypted session_id does not match receipt subject for batch sequence {receipt.batch_seq_no}",
                    session_id,
                )
            if str(plaintext.get("event_root")) != receipt.merkle_root:
                report.add(
                    f"{code_prefix}_payload_root_mismatch",
                    f"event_batch decrypted event_root does not match receipt merkle_root for batch sequence {receipt.batch_seq_no}",
                    session_id,
                )
            if int(plaintext.get("batch_seq_no", -1)) != receipt.batch_seq_no:
                report.add(
                    f"{code_prefix}_payload_sequence_mismatch",
                    f"event_batch decrypted batch_seq_no does not match receipt for batch sequence {receipt.batch_seq_no}",
                    session_id,
                )
        elif expected_kind == "delegation":
            if str(plaintext.get("child_session_id")) != str(receipt.subject_id):
                report.add(
                    f"{code_prefix}_payload_subject_mismatch",
                    f"delegation decrypted child_session_id does not match receipt subject for batch sequence {receipt.batch_seq_no}",
                    session_id,
                )
            if receipt.event_ids and str(plaintext.get("cert_id")) != str(receipt.event_ids[0]):
                report.add(
                    f"{code_prefix}_payload_cert_mismatch",
                    f"delegation decrypted cert_id does not match receipt event_ids for batch sequence {receipt.batch_seq_no}",
                    session_id,
                )
        elif expected_kind == "backup_locator":
            if str(plaintext.get("backup_id")) != str(receipt.subject_id):
                report.add(
                    f"{code_prefix}_payload_subject_mismatch",
                    f"backup_locator decrypted backup_id does not match receipt subject for batch sequence {receipt.batch_seq_no}",
                    session_id,
                )
            if str(plaintext.get("snapshot_digest")) != str((receipt.metadata or {}).get("snapshot_digest")):
                report.add(
                    f"{code_prefix}_payload_snapshot_mismatch",
                    f"backup_locator decrypted snapshot_digest does not match receipt metadata for batch sequence {receipt.batch_seq_no}",
                    session_id,
                )

    def _verify_manifest_summary(
        self,
        *,
        report: VerificationReport,
        session_id: str,
        receipt: AnchorReceipt,
        expected_payload_scheme: str,
        expected_key_wrap_scheme: str,
        expected_ciphertext_digest: str | None,
        access_policy_digest: object | None,
        expected_access_policy_digest: object | None,
        missing_code: str,
        invalid_code: str,
    ) -> None:
        metadata = receipt.metadata or {}
        summary = metadata.get("encryption_manifest")
        if not isinstance(summary, dict):
            report.add(
                missing_code,
                f"{receipt.commitment_type} encryption_manifest summary is missing for batch sequence {receipt.batch_seq_no}",
                session_id,
            )
            return
        expected_digest = metadata.get("encryption_manifest_digest")
        observed_digest = manifest_digest_from_summary(summary)
        if expected_digest != observed_digest:
            report.add(
                invalid_code,
                f"{receipt.commitment_type} encryption_manifest_digest does not match summary for batch sequence {receipt.batch_seq_no}",
                session_id,
            )
        if str(summary.get("payload_scheme")) != expected_payload_scheme:
            report.add(
                invalid_code,
                f"{receipt.commitment_type} payload_scheme is invalid for batch sequence {receipt.batch_seq_no}",
                session_id,
            )
        if str(summary.get("key_wrap_scheme")) != expected_key_wrap_scheme:
            report.add(
                invalid_code,
                f"{receipt.commitment_type} key_wrap_scheme is invalid for batch sequence {receipt.batch_seq_no}",
                session_id,
            )
        if expected_ciphertext_digest is not None and str(summary.get("ciphertext_digest")) != expected_ciphertext_digest:
            report.add(
                invalid_code,
                f"{receipt.commitment_type} ciphertext_digest is invalid for batch sequence {receipt.batch_seq_no}",
                session_id,
            )
        if expected_access_policy_digest is not None and summary.get("access_policy_digest") != expected_access_policy_digest:
            report.add(
                invalid_code,
                f"{receipt.commitment_type} access_policy_digest is invalid for batch sequence {receipt.batch_seq_no}",
                session_id,
            )
        if access_policy_digest is not None and not summary.get("access_policy_digest"):
            report.add(
                invalid_code,
                f"{receipt.commitment_type} access_policy_digest is missing for batch sequence {receipt.batch_seq_no}",
                session_id,
            )
