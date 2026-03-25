from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from ..canonical.events import CanonicalEvent
from .anchor import (
    AnchorBackend,
    AnchorSubmissionExporter,
    AnchorSubmissionPoller,
    LocalAnchorBackend,
)
from .batching import AnchorReceipt, BatchCommitter
from .bus import RuntimeEventBus
from .sidecar import ProvenanceSidecar
from .store import JsonAnchorSubmissionStore, JsonReceiptStore


@dataclass
class ClawChainRuntime:
    bus: RuntimeEventBus
    batcher: BatchCommitter = field(default_factory=BatchCommitter)
    anchor_backend: AnchorBackend = field(default_factory=LocalAnchorBackend)
    receipt_store: JsonReceiptStore | None = None
    submission_store: JsonAnchorSubmissionStore | None = None
    sidecar: ProvenanceSidecar | None = None
    receipts: list[AnchorReceipt] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.receipt_store is None:
            return
        for row in self.receipt_store.read_all():
            session_id = str(row["session_id"])
            next_seq_no = int(row["batch_seq_no"]) + 1
            self.batcher.set_next_seq_no(session_id, next_seq_no)

    def publish(self, event: CanonicalEvent) -> list[AnchorReceipt]:
        self.bus.publish(event)
        if self.sidecar is not None:
            self.sidecar.mirror_event(event)
        return self._anchor_receipts(self.batcher.enqueue(event))

    def flush(self) -> list[AnchorReceipt]:
        return self._anchor_receipts(self.batcher.flush_ready())

    def _anchor_receipts(self, pending_receipts: list[AnchorReceipt]) -> list[AnchorReceipt]:
        anchored = [self.anchor_backend.submit(receipt) for receipt in pending_receipts]
        self.receipts.extend(anchored)
        if self.receipt_store is not None and anchored:
            self.receipt_store.append_many(anchored)
        if self.sidecar is not None and anchored:
            self.sidecar.mirror_receipts(anchored)
            self._mirror_receipt_bundles(anchored)
        if self.submission_store is not None and hasattr(self.anchor_backend, "drain_submissions"):
            submissions = cast(AnchorSubmissionExporter, self.anchor_backend).drain_submissions()
            if submissions:
                self.submission_store.append_many(submissions)
                if self.sidecar is not None:
                    self.sidecar.mirror_submissions(submissions)
        return anchored

    def poll_anchor_submissions(self) -> list[dict]:
        if self.submission_store is None or not hasattr(self.anchor_backend, "poll_submissions"):
            return []
        rows = self.submission_store.read_all()
        poller = cast(AnchorSubmissionPoller, self.anchor_backend)
        from .anchor import AnchorSubmission

        submissions = [
            AnchorSubmission(
                session_id=str(row["session_id"]),
                batch_seq_no=int(row["batch_seq_no"]),
                merkle_root=str(row["merkle_root"]),
                event_ids=tuple(str(value) for value in row["event_ids"]),
                commitment_type=str(row.get("commitment_type", "event_batch")),
                subject_id=(str(row["subject_id"]) if row.get("subject_id") is not None else None),
                anchor_mode=str(row["anchor_mode"]),
                anchor_backend=str(row["anchor_backend"]),
                anchor_reference=str(row["anchor_reference"]),
                metadata=dict(row.get("metadata", {})),
                status=str(row.get("status", "submitted")),
            )
            for row in rows
        ]
        updated = poller.poll_submissions(submissions)
        self.submission_store.replace_all(updated)
        if self.sidecar is not None and updated:
            self.sidecar.mirror_submissions(updated)
        if self.receipt_store is not None and updated:
            refreshed_receipts = [
                AnchorReceipt(
                    session_id=submission.session_id,
                    batch_seq_no=submission.batch_seq_no,
                    merkle_root=submission.merkle_root,
                    event_ids=submission.event_ids,
                    commitment_type=submission.commitment_type,
                    subject_id=submission.subject_id,
                    metadata=submission.metadata,
                    anchor_mode=submission.anchor_mode,
                    anchor_backend=submission.anchor_backend,
                    anchor_reference=submission.anchor_reference,
                )
                for submission in updated
            ]
            self.receipt_store.append_many(refreshed_receipts)
            if self.sidecar is not None:
                self.sidecar.mirror_receipts(refreshed_receipts)
        return [submission.metadata for submission in updated]

    def _mirror_receipt_bundles(self, receipts: list[AnchorReceipt]) -> None:
        if self.sidecar is None or self.batcher.bundle_store is None:
            return
        bundle_root = self.batcher.bundle_store.root_dir
        for receipt in receipts:
            metadata = receipt.metadata or {}
            bundle_ref = metadata.get("encrypted_bundle_ref")
            if not bundle_ref:
                continue
            bundle_path = bundle_root / str(bundle_ref)
            if bundle_path.exists():
                self.sidecar.mirror_bundle(bundle_ref=str(bundle_ref), bundle_path=bundle_path)
