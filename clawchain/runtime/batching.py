from __future__ import annotations

from dataclasses import dataclass, field

from ..canonical.commitments import (
    EncryptionManifest,
    EncryptionScheme,
    EventBatchCommitment,
)
from ..canonical.events import CanonicalEvent
from ..canonical.ids import digest_text, stable_json
from .anchor_service_utils import build_anchor_metadata
from .evidence_bundle import EventBatchBundleStore


def merkle_root(items: list[str]) -> str:
    if not items:
        return digest_text("")
    level = items[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: list[str] = []
        for index in range(0, len(level), 2):
            next_level.append(digest_text(f"{level[index]}:{level[index + 1]}"))
        level = next_level
    return level[0]


def event_batch_encryption_manifest(*, session_id: str, event_root: str) -> EncryptionManifest:
    return EncryptionManifest(
        manifest_version="v1",
        payload_scheme=EncryptionScheme.NONE,
        key_wrap_scheme=EncryptionScheme.NONE,
        recipient_set_digest=digest_text(f"event-batch:{session_id}"),
        access_policy_digest=digest_text("event-batch-audit"),
        ciphertext_digest=event_root,
        key_rotation_epoch=None,
    )


@dataclass(frozen=True)
class BatchWindow:
    max_events: int = 64


@dataclass(frozen=True)
class AnchorReceipt:
    session_id: str
    batch_seq_no: int
    merkle_root: str
    event_ids: tuple[str, ...]
    commitment_type: str = "event_batch"
    subject_id: str | None = None
    metadata: dict[str, object] | None = None
    anchor_mode: str = "pending"
    anchor_backend: str | None = None
    anchor_reference: str | None = None


@dataclass
class BatchCommitter:
    window: BatchWindow = field(default_factory=BatchWindow)
    bundle_store: EventBatchBundleStore | None = None
    pending: dict[str, list[CanonicalEvent]] = field(default_factory=dict)
    seq_nos: dict[str, int] = field(default_factory=dict)
    prev_commitment_digests: dict[str, str] = field(default_factory=dict)

    def enqueue(self, event: CanonicalEvent) -> list[AnchorReceipt]:
        session_pending = self.pending.setdefault(event.session_id, [])
        session_pending.append(event)
        if len(session_pending) < self.window.max_events:
            return []
        return [self._flush_session(event.session_id)]

    def set_next_seq_no(self, session_id: str, next_seq_no: int) -> None:
        current = self.seq_nos.get(session_id)
        if current is None or next_seq_no > current:
            self.seq_nos[session_id] = next_seq_no

    def flush_ready(self) -> list[AnchorReceipt]:
        receipts: list[AnchorReceipt] = []
        for session_id in list(self.pending):
            if self.pending[session_id]:
                receipts.append(self._flush_session(session_id))
        return receipts

    def _flush_session(self, session_id: str) -> AnchorReceipt:
        events = self.pending.get(session_id, [])
        batch_seq_no = self.seq_nos.get(session_id, 0)
        event_root = merkle_root([event.event_hash for event in events])
        metadata_digest = digest_text(
            stable_json(
                {
                    "event_count": len(events),
                    "event_ids": [event.event_id for event in events],
                }
            )
        )
        bundle_ref: str | None = None
        if self.bundle_store is not None:
            bundle = self.bundle_store.encrypt_batch(
                session_id=session_id,
                batch_seq_no=batch_seq_no,
                events=events,
                event_root=event_root,
            )
            encryption_manifest = bundle.manifest
            bundle_ref = str(bundle.path.relative_to(self.bundle_store.root_dir))
        else:
            encryption_manifest = event_batch_encryption_manifest(
                session_id=session_id,
                event_root=event_root,
            )
        commitment = EventBatchCommitment(
            session_id=session_id,
            batch_seq_no=batch_seq_no,
            event_root=event_root,
            prev_anchor=self.prev_commitment_digests.get(session_id),
            metadata_digest=metadata_digest,
            encryption_manifest=encryption_manifest,
        )
        envelope = commitment.to_envelope()
        receipt = AnchorReceipt(
            session_id=session_id,
            batch_seq_no=batch_seq_no,
            merkle_root=event_root,
            event_ids=tuple(event.event_id for event in events),
            commitment_type="event_batch",
            subject_id=session_id,
            metadata=build_anchor_metadata(
                envelope=envelope,
                base_metadata={
                    "event_count": len(events),
                    "prev_commitment_digest": commitment.prev_anchor,
                },
                manifest=encryption_manifest,
                bundle_ref=bundle_ref,
            ),
        )
        self.pending[session_id] = []
        self.seq_nos[session_id] = receipt.batch_seq_no + 1
        self.prev_commitment_digests[session_id] = envelope.digest()
        return receipt
