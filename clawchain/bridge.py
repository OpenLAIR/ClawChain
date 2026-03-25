from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .audit.cli import verify_jsonl_store
from .canonical.commitments import EventBatchCommitment
from .canonical.ids import digest_text, stable_json
from .runtime.anchor_service_utils import build_anchor_metadata
from .runtime.batching import AnchorReceipt, event_batch_encryption_manifest, merkle_root
from .runtime.anchor import AnchorSubmission
from .runtime.store import JsonlEventStore


@dataclass(frozen=True)
class RuntimeBridgeResult:
    event_store_path: Path
    receipts_path: Path
    submissions_path: Path | None
    receipt_count: int


def build_receipts_from_runtime_events(
    *,
    event_store_path: Path,
    receipts_path: Path,
    submissions_path: Path | None = None,
    overwrite_receipts: bool = True,
    overwrite_submissions: bool = True,
) -> RuntimeBridgeResult:
    store = JsonlEventStore(event_store_path)
    rows = store.read_all()
    by_session: dict[str, list[dict]] = {}
    for row in rows:
        session_id = str(row["session_id"])
        by_session.setdefault(session_id, []).append(row)

    receipts: list[dict[str, object]] = []
    for session_id, session_rows in sorted(by_session.items()):
        session_rows = sorted(session_rows, key=lambda row: int(row["event_index"]))
        event_root = merkle_root([str(row["event_hash"]) for row in session_rows])
        metadata_digest = digest_text(
            stable_json(
                {
                    "event_count": len(session_rows),
                    "event_ids": [str(row["event_id"]) for row in session_rows],
                }
            )
        )
        commitment = EventBatchCommitment(
            session_id=session_id,
            batch_seq_no=0,
            event_root=event_root,
            prev_anchor=None,
            metadata_digest=metadata_digest,
            encryption_manifest=event_batch_encryption_manifest(
                session_id=session_id,
                event_root=event_root,
            ),
        )
        envelope = commitment.to_envelope()
        receipts.append(
            {
                "session_id": session_id,
                "batch_seq_no": 0,
                "merkle_root": event_root,
                "event_ids": [str(row["event_id"]) for row in session_rows],
                "commitment_type": "event_batch",
                "subject_id": session_id,
                "metadata": build_anchor_metadata(
                    envelope=envelope,
                    base_metadata={
                        "event_count": len(session_rows),
                        "exported_by": "python-bridge",
                        "prev_commitment_digest": None,
                    },
                    manifest=commitment.encryption_manifest,
                ),
            }
        )
    if overwrite_receipts or not receipts_path.exists():
        receipts_path.parent.mkdir(parents=True, exist_ok=True)
        receipts_path.write_text(json.dumps(receipts, ensure_ascii=True, indent=2), encoding="utf-8")
    else:
        receipts = json.loads(receipts_path.read_text(encoding="utf-8"))
    if submissions_path is not None and (overwrite_submissions or not submissions_path.exists()):
        build_submissions_from_receipts(
            receipts_path=receipts_path,
            submissions_path=submissions_path,
        )
    return RuntimeBridgeResult(
        event_store_path=event_store_path,
        receipts_path=receipts_path,
        submissions_path=submissions_path,
        receipt_count=len(receipts),
    )


def build_submissions_from_receipts(
    *,
    receipts_path: Path,
    submissions_path: Path,
    default_anchor_mode: str = "local",
    default_anchor_backend: str = "python-bridge",
) -> list[AnchorSubmission]:
    receipts = load_receipts(receipts_path)
    submissions = [
        AnchorSubmission(
            session_id=receipt.session_id,
            batch_seq_no=receipt.batch_seq_no,
            merkle_root=receipt.merkle_root,
            event_ids=receipt.event_ids,
            commitment_type=receipt.commitment_type,
            subject_id=receipt.subject_id,
            anchor_mode=receipt.anchor_mode,
            anchor_backend=receipt.anchor_backend or default_anchor_backend,
            anchor_reference=(
                receipt.anchor_reference
                or f"{default_anchor_mode}:{receipt.session_id}:{receipt.batch_seq_no}"
            ),
            metadata={
                **(receipt.metadata or {}),
                "derived_from": str(receipts_path),
                "exported_by": "python-bridge",
            },
            status="exported",
        )
        for receipt in receipts
    ]
    submissions_path.parent.mkdir(parents=True, exist_ok=True)
    submissions_path.write_text(
        json.dumps(
            [
                {
                    "session_id": submission.session_id,
                    "batch_seq_no": submission.batch_seq_no,
                    "merkle_root": submission.merkle_root,
                    "event_ids": list(submission.event_ids),
                    "commitment_type": submission.commitment_type,
                    "subject_id": submission.subject_id,
                    "anchor_mode": submission.anchor_mode,
                    "anchor_backend": submission.anchor_backend,
                    "anchor_reference": submission.anchor_reference,
                    "metadata": submission.metadata,
                    "status": submission.status,
                }
                for submission in submissions
            ],
            ensure_ascii=True,
            indent=2,
        ),
        encoding="utf-8",
    )
    return submissions


def verify_runtime_session(
    *,
    event_store_path: Path,
    receipts_path: Path,
    session_id: str,
    submissions_path: Path | None = None,
):
    return verify_jsonl_store(
        event_store_path=event_store_path,
        receipts_path=receipts_path,
        session_id=session_id,
        submissions_path=submissions_path,
    )


def load_receipts(receipts_path: Path) -> list[AnchorReceipt]:
    rows = json.loads(receipts_path.read_text(encoding="utf-8"))
    return [
        AnchorReceipt(
            session_id=str(row["session_id"]),
            batch_seq_no=int(row["batch_seq_no"]),
            merkle_root=str(row["merkle_root"]),
            event_ids=tuple(str(value) for value in row["event_ids"]),
            commitment_type=str(row.get("commitment_type", "event_batch")),
            subject_id=(str(row["subject_id"]) if row.get("subject_id") is not None else None),
            metadata=dict(row.get("metadata", {})),
            anchor_mode=str(row.get("anchor_mode", "pending")),
            anchor_backend=(
                str(row["anchor_backend"]) if row.get("anchor_backend") is not None else None
            ),
            anchor_reference=(
                str(row["anchor_reference"]) if row.get("anchor_reference") is not None else None
            ),
        )
        for row in rows
    ]
