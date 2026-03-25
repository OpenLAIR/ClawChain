from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from ..canonical.commitments import CommitmentEnvelope, EncryptionManifest, manifest_metadata

if TYPE_CHECKING:
    from .batching import AnchorReceipt
    from .sidecar import ProvenanceSidecar


class _AnchorSubmissionExporter(Protocol):
    def drain_submissions(self) -> list[object]: ...


class _AppendManyStore(Protocol):
    def append_many(self, items: list[object]) -> None: ...


def build_anchor_metadata(
    *,
    envelope: CommitmentEnvelope,
    base_metadata: dict[str, object] | None = None,
    manifest: EncryptionManifest | None = None,
    bundle_ref: str | None = None,
) -> dict[str, object]:
    metadata = dict(base_metadata or {})
    metadata["metadata_digest"] = envelope.metadata_digest
    metadata["commitment_envelope_digest"] = envelope.digest()
    if manifest is not None:
        metadata.update(manifest_metadata(manifest))
    if bundle_ref is not None:
        metadata["encrypted_bundle_ref"] = bundle_ref
    return metadata


def persist_and_mirror_anchor_result(
    *,
    anchored: "AnchorReceipt",
    receipt_store: "_AppendManyStore | None",
    submission_store: "_AppendManyStore | None",
    sidecar: "ProvenanceSidecar | None",
    anchor_backend: object,
    bundle_ref: str | None = None,
    bundle_root: object | None = None,
) -> None:
    if receipt_store is not None:
        receipt_store.append_many([anchored])
    if sidecar is not None:
        sidecar.mirror_receipts([anchored])
        if bundle_ref is not None and bundle_root is not None:
            sidecar.mirror_bundle(
                bundle_ref=bundle_ref,
                bundle_path=Path(bundle_root) / bundle_ref,
            )
    if submission_store is not None and hasattr(anchor_backend, "drain_submissions"):
        drained = cast(_AnchorSubmissionExporter, anchor_backend).drain_submissions()
        if drained:
            submission_store.append_many(drained)
            if sidecar is not None:
                sidecar.mirror_submissions(drained)


__all__ = ["build_anchor_metadata", "persist_and_mirror_anchor_result"]
