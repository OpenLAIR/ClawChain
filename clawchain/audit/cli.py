from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import sys

from ..runtime.anchor import AnchorSubmission
from ..runtime.batching import AnchorReceipt
from ..runtime.remote import LocalAppendOnlyEvidenceSink
from ..runtime.store import JsonlEventStore
from .signals import RiskSignal
from .verifier import VerificationReport, Verifier


def load_receipts(path: Path) -> list[AnchorReceipt]:
    if not path.exists():
        return []
    rows = json.loads(path.read_text(encoding="utf-8"))
    return [
        AnchorReceipt(
            session_id=str(row["session_id"]),
            batch_seq_no=int(row["batch_seq_no"]),
            merkle_root=str(row["merkle_root"]),
            event_ids=tuple(row["event_ids"]),
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

def load_submissions(path: Path) -> list[AnchorSubmission]:
    if not path.exists():
        return []
    rows = json.loads(path.read_text(encoding="utf-8"))
    return [
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


def verify_jsonl_store(
    *,
    event_store_path: Path,
    receipts_path: Path,
    session_id: str,
    submissions_path: Path | None = None,
    remote_root_dir: Path | None = None,
    bundle_private_keys: dict[str, str] | None = None,
) -> VerificationReport:
    verifier = Verifier()
    store = JsonlEventStore(event_store_path, create_if_missing=False)
    rows = store.read_session(session_id)
    receipts = [receipt for receipt in load_receipts(receipts_path) if receipt.session_id == session_id]
    local_bundle_dirs = [
        receipts_path.parent / "event-bundles",
        receipts_path.parent / "delegation-bundles",
        receipts_path.parent / "backup-bundles",
    ]
    submissions = None
    if submissions_path is not None and submissions_path.exists():
        submissions = [
            submission
            for submission in load_submissions(submissions_path)
            if submission.session_id == session_id
        ]
    remote_rows = None
    remote_receipts = None
    remote_submissions = None
    remote_bundles = None
    remote_metadata = None
    if remote_root_dir is not None and remote_root_dir.exists():
        snapshot = LocalAppendOnlyEvidenceSink(remote_root_dir).snapshot()
        remote_rows = [row for row in snapshot.rows if str(row.get("session_id")) == session_id]
        remote_receipts = [receipt for receipt in snapshot.receipts if receipt.session_id == session_id]
        remote_submissions = [
            submission for submission in snapshot.submissions if submission.session_id == session_id
        ]
        remote_bundles = dict(snapshot.bundles)
        remote_metadata = dict(snapshot.metadata)
    if not rows and remote_rows is not None:
        return verifier.verify_remote_recovery(
            session_id=session_id,
            remote_rows=remote_rows,
            remote_receipts=remote_receipts or [],
            remote_submissions=remote_submissions or [],
        )
    return verifier.verify_session(
        rows=rows,
        receipts=receipts,
        submissions=submissions,
        remote_rows=remote_rows,
        remote_receipts=remote_receipts,
        remote_submissions=remote_submissions,
        local_bundle_dirs=local_bundle_dirs,
        remote_bundles=remote_bundles,
        remote_metadata=remote_metadata,
        bundle_private_keys=bundle_private_keys,
    )


def analyze_jsonl_store(
    *,
    event_store_path: Path,
    receipts_path: Path,
    session_id: str,
) -> list[dict[str, str]]:
    return [signal.to_dict() for signal in extract_risk_signal_records(
        event_store_path=event_store_path,
        receipts_path=receipts_path,
        session_id=session_id,
    )]


def extract_risk_signal_records(
    *,
    event_store_path: Path,
    receipts_path: Path,
    session_id: str,
) -> list[RiskSignal]:
    verifier = Verifier()
    store = JsonlEventStore(event_store_path, create_if_missing=False)
    rows = store.read_session(session_id)
    receipts = [receipt for receipt in load_receipts(receipts_path) if receipt.session_id == session_id]
    return verifier.analyze_session_risk_signals(
        rows=rows,
        receipts=receipts,
    )


def extract_risk_signals(
    *,
    event_store_path: Path,
    receipts_path: Path,
    session_id: str,
) -> list[dict[str, str]]:
    return analyze_jsonl_store(
        event_store_path=event_store_path,
        receipts_path=receipts_path,
        session_id=session_id,
    )


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    if len(args) not in {3, 4, 5}:
        print(
            "usage: python -m clawchain.audit.cli <events.jsonl> <receipts.json> <session_id> [submissions.json] [remote_root_dir]"
        )
        return 2
    report = verify_jsonl_store(
        event_store_path=Path(args[0]),
        receipts_path=Path(args[1]),
        session_id=args[2],
        submissions_path=Path(args[3]) if len(args) >= 4 else None,
        remote_root_dir=Path(args[4]) if len(args) == 5 else None,
    )
    print(
        json.dumps(
            {
                "ok": report.ok,
                "findings": [asdict(finding) for finding in report.findings],
            },
            ensure_ascii=True,
        )
    )
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
