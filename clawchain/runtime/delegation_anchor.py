from __future__ import annotations

from dataclasses import dataclass, field
from ..canonical.attestations import DelegationCertificate
from ..canonical.commitments import (
    CommitmentType,
    DelegationCommitment,
    EncryptionManifest,
    EncryptionScheme,
)
from ..canonical.ids import digest_text, stable_json
from .anchor import AnchorBackend, AnchorSubmissionExporter, LocalAnchorBackend
from .anchor_service_utils import build_anchor_metadata, persist_and_mirror_anchor_result
from .batching import AnchorReceipt
from .evidence_bundle import DelegationBundleStore
from .sidecar import ProvenanceSidecar
from .store import JsonAnchorSubmissionStore, JsonReceiptStore


def delegation_scope_digest(certificate: DelegationCertificate) -> str:
    return digest_text(
        stable_json(
            {
                "allowed_agents": list(certificate.scope.allowed_agents),
                "allowed_tools": list(certificate.scope.allowed_tools),
                "denied_tools": list(certificate.scope.denied_tools),
                "sandbox_mode": certificate.scope.sandbox_mode,
                "sub_delegation": certificate.scope.sub_delegation,
                "max_depth": certificate.scope.max_depth,
                "expiry_ts": certificate.scope.expiry_ts,
            }
        )
    )


def build_delegation_commitment(certificate: DelegationCertificate) -> DelegationCommitment:
    encryption_manifest = delegation_encryption_manifest(certificate)
    return DelegationCommitment(
        parent_session_id=certificate.parent_session_id,
        child_session_id=certificate.child_session_id,
        delegation_digest=certificate.cert_id,
        delegation_scope_digest=delegation_scope_digest(certificate),
        created_ts_ms=certificate.issued_ts,
        encryption_manifest=encryption_manifest,
        metadata={
            "parent_agent_id": certificate.parent_agent_id,
            "child_agent_id": certificate.child_agent_id,
            "run_id": certificate.run_id,
            "signer": certificate.signer,
        },
    )


def delegation_encryption_manifest(certificate: DelegationCertificate) -> EncryptionManifest:
    return EncryptionManifest(
        manifest_version="v1",
        payload_scheme=EncryptionScheme.NONE,
        key_wrap_scheme=EncryptionScheme.NONE,
        recipient_set_digest=digest_text(certificate.child_session_id),
        access_policy_digest=digest_text("delegation-audit"),
        ciphertext_digest=certificate.cert_id,
        key_rotation_epoch=None,
    )


@dataclass
class DelegationAnchorService:
    anchor_backend: AnchorBackend = field(default_factory=LocalAnchorBackend)
    receipt_store: JsonReceiptStore | None = None
    submission_store: JsonAnchorSubmissionStore | None = None
    bundle_store: DelegationBundleStore | None = None
    sidecar: ProvenanceSidecar | None = None
    session_id: str = "delegation-anchor"
    seq_no: int = 0

    def anchor_certificate(self, certificate: DelegationCertificate) -> AnchorReceipt:
        bundle_ref: str | None = None
        if self.bundle_store is not None:
            bundle = self.bundle_store.encrypt_certificate(certificate)
            commitment = build_delegation_commitment(certificate)
            commitment = DelegationCommitment(
                parent_session_id=commitment.parent_session_id,
                child_session_id=commitment.child_session_id,
                delegation_digest=commitment.delegation_digest,
                delegation_scope_digest=commitment.delegation_scope_digest,
                created_ts_ms=commitment.created_ts_ms,
                metadata=commitment.metadata,
                encryption_manifest=bundle.manifest,
            )
            bundle_ref = str(bundle.path.relative_to(self.bundle_store.root_dir))
        else:
            commitment = build_delegation_commitment(certificate)
        envelope = commitment.to_envelope(sequence_no=self.seq_no)
        receipt = AnchorReceipt(
            session_id=self.session_id,
            batch_seq_no=self.seq_no,
            merkle_root=envelope.commitment,
            event_ids=(certificate.cert_id,),
            commitment_type=CommitmentType.DELEGATION.value,
            subject_id=certificate.child_session_id,
            metadata=build_anchor_metadata(
                envelope=envelope,
                base_metadata={
                    "parent_session_id": certificate.parent_session_id,
                    "delegation_scope_digest": commitment.delegation_scope_digest,
                },
                manifest=commitment.encryption_manifest,
                bundle_ref=bundle_ref,
            ),
        )
        self.seq_no += 1
        anchored = self.anchor_backend.submit(receipt)
        persist_and_mirror_anchor_result(
            anchored=anchored,
            receipt_store=self.receipt_store,
            submission_store=self.submission_store,
            sidecar=self.sidecar,
            anchor_backend=self.anchor_backend,
            bundle_ref=bundle_ref,
            bundle_root=(self.bundle_store.root_dir if self.bundle_store is not None else None),
        )
        return anchored


__all__ = [
    "DelegationAnchorService",
    "build_delegation_commitment",
    "delegation_encryption_manifest",
    "delegation_scope_digest",
]
