from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum

from .ids import digest_text, stable_json


class CommitmentType(StrEnum):
    EVENT_BATCH = "event_batch"
    BACKUP_LOCATOR = "backup_locator"
    DELEGATION = "delegation"
    RECOVERY = "recovery"


class EncryptionScheme(StrEnum):
    NONE = "none"
    AES_256_GCM = "aes-256-gcm"
    RSA_OAEP_SHA256 = "rsa-oaep-sha256"
    ENVELOPE = "envelope"


@dataclass(frozen=True)
class EncryptionManifest:
    manifest_version: str
    payload_scheme: EncryptionScheme
    key_wrap_scheme: EncryptionScheme
    recipient_set_digest: str
    access_policy_digest: str
    ciphertext_digest: str
    key_rotation_epoch: str | None = None

    def digest(self) -> str:
        return digest_text(stable_json(asdict(self)))

    def summary(self) -> dict[str, object]:
        return {
            "manifest_version": self.manifest_version,
            "payload_scheme": self.payload_scheme.value,
            "key_wrap_scheme": self.key_wrap_scheme.value,
            "recipient_set_digest": self.recipient_set_digest,
            "access_policy_digest": self.access_policy_digest,
            "ciphertext_digest": self.ciphertext_digest,
            "key_rotation_epoch": self.key_rotation_epoch,
        }


def manifest_digest_from_summary(summary: dict[str, object]) -> str:
    return digest_text(stable_json(summary))


def manifest_metadata(manifest: EncryptionManifest) -> dict[str, object]:
    summary = manifest.summary()
    return {
        "encryption_manifest_digest": manifest_digest_from_summary(summary),
        "encryption_manifest": summary,
    }


@dataclass(frozen=True)
class CommitmentEnvelope:
    commitment_type: CommitmentType
    subject_id: str
    sequence_no: int
    commitment: str
    prev_anchor: str | None = None
    metadata_digest: str | None = None
    encryption_manifest_digest: str | None = None
    evidence_policy_digest: str | None = None

    def digest(self) -> str:
        return digest_text(
            stable_json(
                {
                    "commitment_type": self.commitment_type.value,
                    "subject_id": self.subject_id,
                    "sequence_no": self.sequence_no,
                    "commitment": self.commitment,
                    "prev_anchor": self.prev_anchor,
                    "metadata_digest": self.metadata_digest,
                    "encryption_manifest_digest": self.encryption_manifest_digest,
                    "evidence_policy_digest": self.evidence_policy_digest,
                }
            )
        )


@dataclass(frozen=True)
class EventBatchCommitment:
    session_id: str
    batch_seq_no: int
    event_root: str
    receipt_root: str | None = None
    prev_anchor: str | None = None
    metadata_digest: str | None = None
    encryption_manifest: EncryptionManifest | None = None

    def to_envelope(self) -> CommitmentEnvelope:
        return CommitmentEnvelope(
            commitment_type=CommitmentType.EVENT_BATCH,
            subject_id=self.session_id,
            sequence_no=self.batch_seq_no,
            commitment=self.event_root,
            prev_anchor=self.prev_anchor,
            metadata_digest=self.metadata_digest,
            encryption_manifest_digest=(
                self.encryption_manifest.digest()
                if self.encryption_manifest is not None
                else None
            ),
        )


@dataclass(frozen=True)
class BackupLocatorCommitment:
    backup_id: str
    snapshot_digest: str
    locator_commitment: str
    created_ts_ms: int
    recovery_policy_digest: str | None = None
    encryption_manifest: EncryptionManifest | None = None

    def to_envelope(self, *, sequence_no: int, prev_anchor: str | None = None) -> CommitmentEnvelope:
        return CommitmentEnvelope(
            commitment_type=CommitmentType.BACKUP_LOCATOR,
            subject_id=self.backup_id,
            sequence_no=sequence_no,
            commitment=self.locator_commitment,
            prev_anchor=prev_anchor,
            metadata_digest=digest_text(
                stable_json(
                    {
                        "snapshot_digest": self.snapshot_digest,
                        "created_ts_ms": self.created_ts_ms,
                        "recovery_policy_digest": self.recovery_policy_digest,
                    }
                )
            ),
            encryption_manifest_digest=(
                self.encryption_manifest.digest()
                if self.encryption_manifest is not None
                else None
            ),
        )


@dataclass(frozen=True)
class DelegationCommitment:
    parent_session_id: str
    child_session_id: str
    delegation_digest: str
    delegation_scope_digest: str
    created_ts_ms: int
    metadata: dict[str, object] = field(default_factory=dict)
    encryption_manifest: EncryptionManifest | None = None

    def to_envelope(self, *, sequence_no: int, prev_anchor: str | None = None) -> CommitmentEnvelope:
        return CommitmentEnvelope(
            commitment_type=CommitmentType.DELEGATION,
            subject_id=self.child_session_id,
            sequence_no=sequence_no,
            commitment=self.delegation_digest,
            prev_anchor=prev_anchor,
            metadata_digest=digest_text(
                stable_json(
                    {
                        "parent_session_id": self.parent_session_id,
                        "delegation_scope_digest": self.delegation_scope_digest,
                        "created_ts_ms": self.created_ts_ms,
                        "metadata": self.metadata,
                    }
                )
            ),
            encryption_manifest_digest=(
                self.encryption_manifest.digest()
                if self.encryption_manifest is not None
                else None
            ),
        )


@dataclass(frozen=True)
class RecoveryCommitment:
    recovery_id: str
    target_path_hash: str
    source_kind: str
    result_digest: str
    verified: bool
    created_ts_ms: int
    metadata: dict[str, object] = field(default_factory=dict)
    encryption_manifest: EncryptionManifest | None = None

    def to_envelope(self, *, sequence_no: int, prev_anchor: str | None = None) -> CommitmentEnvelope:
        return CommitmentEnvelope(
            commitment_type=CommitmentType.RECOVERY,
            subject_id=self.recovery_id,
            sequence_no=sequence_no,
            commitment=self.result_digest,
            prev_anchor=prev_anchor,
            metadata_digest=digest_text(
                stable_json(
                    {
                        "target_path_hash": self.target_path_hash,
                        "source_kind": self.source_kind,
                        "verified": self.verified,
                        "created_ts_ms": self.created_ts_ms,
                        "metadata": self.metadata,
                    }
                )
            ),
            encryption_manifest_digest=(
                self.encryption_manifest.digest() if self.encryption_manifest is not None else None
            ),
        )


__all__ = [
    "BackupLocatorCommitment",
    "CommitmentEnvelope",
    "CommitmentType",
    "DelegationCommitment",
    "EncryptionManifest",
    "EncryptionScheme",
    "EventBatchCommitment",
    "RecoveryCommitment",
    "manifest_digest_from_summary",
    "manifest_metadata",
]
