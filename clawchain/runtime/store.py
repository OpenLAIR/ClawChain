from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from ..canonical.events import CanonicalEvent
from .batching import AnchorReceipt
from .anchor import AnchorSubmission


@dataclass
class JsonlEventStore:
    path: Path
    create_if_missing: bool = True

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.create_if_missing:
            self.path.touch(exist_ok=True)

    def append(self, event: CanonicalEvent) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=True) + "\n")

    def event_store_paths(self) -> list[Path]:
        archived_paths = sorted(self.path.parent.glob("events.*.jsonl"))
        paths: list[Path] = []
        for archived_path in archived_paths:
            if archived_path.name == self.path.name:
                continue
            paths.append(archived_path)
        if self.path.exists():
            paths.append(self.path)
        return paths

    def read_all(self) -> list[dict]:
        rows: list[dict] = []
        for event_store_path in self.event_store_paths():
            if not event_store_path.exists():
                continue
            with event_store_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    rows.append(json.loads(line))
        return rows

    def read_session(self, session_id: str) -> list[dict]:
        return [row for row in self.read_all() if row.get("session_id") == session_id]


@dataclass
class JsonReceiptStore:
    path: Path

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]\n", encoding="utf-8")

    def append_many(self, receipts: list[AnchorReceipt]) -> None:
        rows = self.read_all()
        indexed = {
            self._row_key(row): row
            for row in rows
        }
        for receipt in receipts:
            serialized = self._serialize(receipt)
            indexed[self._row_key(serialized)] = serialized
        merged = sorted(
            indexed.values(),
            key=lambda row: (
                str(row["session_id"]),
                int(row["batch_seq_no"]),
                str(row.get("anchor_reference") or ""),
            ),
        )
        self.path.write_text(json.dumps(merged, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    def read_all(self) -> list[dict]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def highest_batch_seq_no(self, session_id: str) -> int | None:
        seq_nos = [
            int(row["batch_seq_no"])
            for row in self.read_all()
            if str(row.get("session_id")) == session_id
        ]
        if not seq_nos:
            return None
        return max(seq_nos)

    def _serialize(self, receipt: AnchorReceipt) -> dict[str, object]:
        return {
            "session_id": receipt.session_id,
            "batch_seq_no": receipt.batch_seq_no,
            "merkle_root": receipt.merkle_root,
            "event_ids": list(receipt.event_ids),
            "commitment_type": receipt.commitment_type,
            "subject_id": receipt.subject_id,
            "metadata": receipt.metadata or {},
            "anchor_mode": receipt.anchor_mode,
            "anchor_backend": receipt.anchor_backend,
            "anchor_reference": receipt.anchor_reference,
        }

    def _row_key(self, row: dict[str, object]) -> tuple[str, int]:
        return (str(row["session_id"]), int(row["batch_seq_no"]))


@dataclass
class JsonAnchorSubmissionStore:
    path: Path

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]\n", encoding="utf-8")

    def append_many(self, submissions: list[AnchorSubmission]) -> None:
        rows = self.read_all()
        indexed = {
            self._row_key(row): row
            for row in rows
        }
        for submission in submissions:
            serialized = self._serialize(submission)
            indexed[self._row_key(serialized)] = serialized
        merged = sorted(
            indexed.values(),
            key=lambda row: (
                str(row["session_id"]),
                int(row["batch_seq_no"]),
                str(row.get("anchor_reference") or ""),
            ),
        )
        self.path.write_text(json.dumps(merged, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    def read_all(self) -> list[dict]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def replace_all(self, submissions: list[AnchorSubmission]) -> None:
        rows = [self._serialize(submission) for submission in submissions]
        self.path.write_text(json.dumps(rows, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    def _serialize(self, submission: AnchorSubmission) -> dict[str, object]:
        return {
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

    def _row_key(self, row: dict[str, object]) -> tuple[str, int, str]:
        return (
            str(row["session_id"]),
            int(row["batch_seq_no"]),
            str(row.get("anchor_reference") or ""),
        )
