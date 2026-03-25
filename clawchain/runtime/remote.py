from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
from pathlib import Path
import socket
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from typing import Protocol
from uuid import uuid4

from ..canonical.events import CanonicalEvent
from .anchor import AnchorSubmission
from .batching import AnchorReceipt


@dataclass(frozen=True)
class RemoteEvidencePaths:
    root_dir: Path
    events_path: Path
    receipts_path: Path
    submissions_path: Path
    bundles_dir: Path
    metadata_path: Path


@dataclass(frozen=True)
class RemoteEvidenceSnapshot:
    rows: list[dict]
    receipts: list[AnchorReceipt]
    submissions: list[AnchorSubmission]
    bundles: dict[str, dict]
    metadata: dict[str, object]


class RemoteEvidenceSink(Protocol):
    def append_event(self, event: CanonicalEvent) -> None: ...

    def append_receipts(self, receipts: list[AnchorReceipt]) -> None: ...

    def append_submissions(self, submissions: list[AnchorSubmission]) -> None: ...

    def append_bundle(self, bundle_ref: str, bundle: dict[str, object]) -> None: ...

    def write_metadata(self, metadata: dict[str, object]) -> None: ...

    def snapshot(self) -> RemoteEvidenceSnapshot: ...


def sidecar_request_signature(
    *,
    method: str,
    path: str,
    body: bytes,
    request_id: str,
    timestamp_ms: int,
    auth_secret: str,
) -> str:
    message = b"\n".join(
        [
            method.upper().encode("utf-8"),
            path.encode("utf-8"),
            request_id.encode("utf-8"),
            str(timestamp_ms).encode("utf-8"),
            body,
        ]
    )
    return hmac.new(auth_secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def sidecar_request_metadata() -> tuple[str, int]:
    return uuid4().hex, int(time.time() * 1000)


def resolve_remote_evidence_paths(root_dir: Path) -> RemoteEvidencePaths:
    return RemoteEvidencePaths(
        root_dir=root_dir,
        events_path=root_dir / "events.remote.jsonl",
        receipts_path=root_dir / "receipts.remote.jsonl",
        submissions_path=root_dir / "submissions.remote.jsonl",
        bundles_dir=root_dir / "bundles",
        metadata_path=root_dir / "metadata.remote.json",
    )


@dataclass
class LocalAppendOnlyEvidenceSink:
    root_dir: Path

    def __post_init__(self) -> None:
        self.paths = resolve_remote_evidence_paths(self.root_dir)
        self.paths.root_dir.mkdir(parents=True, exist_ok=True)
        self.paths.events_path.touch(exist_ok=True)
        self.paths.receipts_path.touch(exist_ok=True)
        self.paths.submissions_path.touch(exist_ok=True)
        self.paths.bundles_dir.mkdir(parents=True, exist_ok=True)
        if not self.paths.metadata_path.exists():
            self.write_metadata({})

    def append_event(self, event: CanonicalEvent) -> None:
        self.append_event_row(event.to_dict())

    def append_event_row(self, row: dict[str, object]) -> None:
        self._append_jsonl(self.paths.events_path, {"kind": "event", "event": row})

    def append_receipts(self, receipts: list[AnchorReceipt]) -> None:
        for receipt in receipts:
            self.append_receipt_row(
                {
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
            )

    def append_receipt_row(self, row: dict[str, object]) -> None:
        self._append_jsonl(self.paths.receipts_path, {"kind": "receipt", "receipt": row})

    def append_submissions(self, submissions: list[AnchorSubmission]) -> None:
        for submission in submissions:
            self.append_submission_row(
                {
                    **asdict(submission),
                    "event_ids": list(submission.event_ids),
                }
            )

    def append_submission_row(self, row: dict[str, object]) -> None:
        self._append_jsonl(self.paths.submissions_path, {"kind": "submission", "submission": row})

    def append_bundle(self, bundle_ref: str, bundle: dict[str, object]) -> None:
        path = self.paths.bundles_dir / bundle_ref
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(bundle, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    def write_metadata(self, metadata: dict[str, object]) -> None:
        self.paths.metadata_path.write_text(
            json.dumps(metadata, ensure_ascii=True, indent=2) + "\n",
            encoding="utf-8",
        )

    def snapshot(self) -> RemoteEvidenceSnapshot:
        rows = [row["event"] for row in self._read_jsonl(self.paths.events_path) if "event" in row]

        receipt_rows: dict[tuple[str, int], AnchorReceipt] = {}
        for row in self._read_jsonl(self.paths.receipts_path):
            receipt = row.get("receipt")
            if not isinstance(receipt, dict):
                continue
            parsed = AnchorReceipt(
                session_id=str(receipt["session_id"]),
                batch_seq_no=int(receipt["batch_seq_no"]),
                merkle_root=str(receipt["merkle_root"]),
                event_ids=tuple(str(value) for value in receipt["event_ids"]),
                commitment_type=str(receipt.get("commitment_type", "event_batch")),
                subject_id=(str(receipt["subject_id"]) if receipt.get("subject_id") is not None else None),
                metadata=dict(receipt.get("metadata", {})),
                anchor_mode=str(receipt.get("anchor_mode", "pending")),
                anchor_backend=(
                    str(receipt["anchor_backend"]) if receipt.get("anchor_backend") is not None else None
                ),
                anchor_reference=(
                    str(receipt["anchor_reference"])
                    if receipt.get("anchor_reference") is not None
                    else None
                ),
            )
            receipt_rows[(parsed.session_id, parsed.batch_seq_no)] = parsed

        submission_rows: dict[tuple[str, int, str], AnchorSubmission] = {}
        for row in self._read_jsonl(self.paths.submissions_path):
            submission = row.get("submission")
            if not isinstance(submission, dict):
                continue
            parsed = AnchorSubmission(
                session_id=str(submission["session_id"]),
                batch_seq_no=int(submission["batch_seq_no"]),
                merkle_root=str(submission["merkle_root"]),
                event_ids=tuple(str(value) for value in submission["event_ids"]),
                commitment_type=str(submission.get("commitment_type", "event_batch")),
                subject_id=(
                    str(submission["subject_id"]) if submission.get("subject_id") is not None else None
                ),
                anchor_mode=str(submission["anchor_mode"]),
                anchor_backend=str(submission["anchor_backend"]),
                anchor_reference=str(submission["anchor_reference"]),
                metadata=dict(submission.get("metadata", {})),
                status=str(submission.get("status", "submitted")),
            )
            submission_rows[(parsed.session_id, parsed.batch_seq_no, parsed.anchor_reference)] = parsed

        return RemoteEvidenceSnapshot(
            rows=rows,
            receipts=sorted(receipt_rows.values(), key=lambda row: (row.session_id, row.batch_seq_no)),
            submissions=sorted(
                submission_rows.values(),
                key=lambda row: (row.session_id, row.batch_seq_no, row.anchor_reference),
            ),
            bundles=self._read_bundles(),
            metadata=self._read_metadata(),
        )

    def _append_jsonl(self, path: Path, payload: dict[str, object]) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")

    def _read_jsonl(self, path: Path) -> list[dict]:
        rows: list[dict] = []
        if not path.exists():
            return rows
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                rows.append(json.loads(line))
        return rows

    def _read_bundles(self) -> dict[str, dict]:
        bundles: dict[str, dict] = {}
        if not self.paths.bundles_dir.exists():
            return bundles
        for path in sorted(self.paths.bundles_dir.rglob("*.json")):
            bundle_ref = str(path.relative_to(self.paths.bundles_dir))
            bundles[bundle_ref] = json.loads(path.read_text(encoding="utf-8"))
        return bundles

    def _read_metadata(self) -> dict[str, object]:
        if not self.paths.metadata_path.exists():
            return {}
        return dict(json.loads(self.paths.metadata_path.read_text(encoding="utf-8")))


@dataclass(frozen=True)
class HttpEvidenceSink:
    base_url: str
    timeout_sec: float = 5.0
    auth_secret: str | None = None
    write_auth_secret: str | None = None
    read_auth_secret: str | None = None

    def append_event(self, event: CanonicalEvent) -> None:
        self._post_json("/events", {"event": event.to_dict()})

    def append_receipts(self, receipts: list[AnchorReceipt]) -> None:
        self._post_json(
            "/receipts",
            {
                "receipts": [
                    {
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
                    for receipt in receipts
                ]
            },
        )

    def append_submissions(self, submissions: list[AnchorSubmission]) -> None:
        self._post_json(
            "/submissions",
            {
                "submissions": [
                    {
                        **asdict(submission),
                        "event_ids": list(submission.event_ids),
                    }
                    for submission in submissions
                ]
            },
        )

    def append_bundle(self, bundle_ref: str, bundle: dict[str, object]) -> None:
        self._post_json("/bundles", {"bundle_ref": bundle_ref, "bundle": bundle})

    def write_metadata(self, metadata: dict[str, object]) -> None:
        self._post_json("/metadata", {"metadata": metadata})

    def snapshot(self) -> RemoteEvidenceSnapshot:
        payload = self._get_json("/snapshot")
        return RemoteEvidenceSnapshot(
            rows=list(payload.get("rows", [])),
            receipts=[
                AnchorReceipt(
                    session_id=str(row["session_id"]),
                    batch_seq_no=int(row["batch_seq_no"]),
                    merkle_root=str(row["merkle_root"]),
                    event_ids=tuple(str(value) for value in row["event_ids"]),
                    commitment_type=str(row.get("commitment_type", "event_batch")),
                    subject_id=(str(row["subject_id"]) if row.get("subject_id") is not None else None),
                    metadata=dict(row.get("metadata", {})),
                    anchor_mode=str(row.get("anchor_mode", "pending")),
                    anchor_backend=(str(row["anchor_backend"]) if row.get("anchor_backend") is not None else None),
                    anchor_reference=(
                        str(row["anchor_reference"]) if row.get("anchor_reference") is not None else None
                    ),
                )
                for row in payload.get("receipts", [])
            ],
            submissions=[
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
                for row in payload.get("submissions", [])
            ],
            bundles={
                str(key): value
                for key, value in dict(payload.get("bundles", {})).items()
                if isinstance(value, dict)
            },
            metadata=dict(payload.get("metadata", {})),
        )

    def _post_json(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        request_id, timestamp_ms = sidecar_request_metadata()
        headers["X-ClawChain-Request-Id"] = request_id
        headers["X-ClawChain-Timestamp-Ms"] = str(timestamp_ms)
        secret = self.write_auth_secret or self.auth_secret
        if secret is not None:
            headers["X-ClawChain-Auth"] = sidecar_request_signature(
                method="POST",
                path=path,
                body=body,
                request_id=request_id,
                timestamp_ms=timestamp_ms,
                auth_secret=secret,
            )
        request = Request(
            f"{self.base_url.rstrip('/')}{path}",
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_sec) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise PermissionError(f"http sidecar request failed with status {exc.code}") from exc

    def _get_json(self, path: str) -> dict[str, object]:
        headers: dict[str, str] = {}
        request_id, timestamp_ms = sidecar_request_metadata()
        headers["X-ClawChain-Request-Id"] = request_id
        headers["X-ClawChain-Timestamp-Ms"] = str(timestamp_ms)
        secret = self.read_auth_secret or self.auth_secret
        if secret is not None:
            headers["X-ClawChain-Auth"] = sidecar_request_signature(
                method="GET",
                path=path,
                body=b"",
                request_id=request_id,
                timestamp_ms=timestamp_ms,
                auth_secret=secret,
            )
        request = Request(f"{self.base_url.rstrip('/')}{path}", headers=headers, method="GET")
        try:
            with urlopen(request, timeout=self.timeout_sec) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise PermissionError(f"http sidecar request failed with status {exc.code}") from exc


@dataclass(frozen=True)
class UnixSocketEvidenceSink:
    socket_path: Path
    timeout_sec: float = 5.0
    auth_secret: str | None = None
    write_auth_secret: str | None = None
    read_auth_secret: str | None = None

    def append_event(self, event: CanonicalEvent) -> None:
        self._round_trip({"action": "append_event", "event": event.to_dict()}, role="write")

    def append_receipts(self, receipts: list[AnchorReceipt]) -> None:
        self._round_trip(
            {
                "action": "append_receipts",
                "receipts": [
                    {
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
                    for receipt in receipts
                ],
            },
            role="write",
        )

    def append_submissions(self, submissions: list[AnchorSubmission]) -> None:
        self._round_trip(
            {
                "action": "append_submissions",
                "submissions": [
                    {
                        **asdict(submission),
                        "event_ids": list(submission.event_ids),
                    }
                    for submission in submissions
                ],
            },
            role="write",
        )

    def append_bundle(self, bundle_ref: str, bundle: dict[str, object]) -> None:
        self._round_trip({"action": "append_bundle", "bundle_ref": bundle_ref, "bundle": bundle}, role="write")

    def write_metadata(self, metadata: dict[str, object]) -> None:
        self._round_trip({"action": "write_metadata", "metadata": metadata}, role="write")

    def snapshot(self) -> RemoteEvidenceSnapshot:
        payload = self._round_trip({"action": "snapshot"}, role="read")
        return RemoteEvidenceSnapshot(
            rows=list(payload.get("rows", [])),
            receipts=[
                AnchorReceipt(
                    session_id=str(row["session_id"]),
                    batch_seq_no=int(row["batch_seq_no"]),
                    merkle_root=str(row["merkle_root"]),
                    event_ids=tuple(str(value) for value in row["event_ids"]),
                    commitment_type=str(row.get("commitment_type", "event_batch")),
                    subject_id=(str(row["subject_id"]) if row.get("subject_id") is not None else None),
                    metadata=dict(row.get("metadata", {})),
                    anchor_mode=str(row.get("anchor_mode", "pending")),
                    anchor_backend=(str(row["anchor_backend"]) if row.get("anchor_backend") is not None else None),
                    anchor_reference=(
                        str(row["anchor_reference"]) if row.get("anchor_reference") is not None else None
                    ),
                )
                for row in payload.get("receipts", [])
            ],
            submissions=[
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
                for row in payload.get("submissions", [])
            ],
            bundles={
                str(key): value
                for key, value in dict(payload.get("bundles", {})).items()
                if isinstance(value, dict)
            },
            metadata=dict(payload.get("metadata", {})),
        )

    def _round_trip(self, payload: dict[str, object], *, role: str) -> dict[str, object]:
        request_id, timestamp_ms = sidecar_request_metadata()
        request_payload: dict[str, object]
        secret = (
            self.write_auth_secret if role == "write" and self.write_auth_secret is not None else
            self.read_auth_secret if role == "read" and self.read_auth_secret is not None else
            self.auth_secret
        )
        if secret is not None:
            request_payload = {
                "payload": payload,
                "request_id": request_id,
                "timestamp_ms": timestamp_ms,
                "role": role,
                "auth": sidecar_request_signature(
                    method="UNIX",
                    path="sidecar",
                    body=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
                    request_id=request_id,
                    timestamp_ms=timestamp_ms,
                    auth_secret=secret,
                ),
            }
        else:
            request_payload = {
                "payload": payload,
                "request_id": request_id,
                "timestamp_ms": timestamp_ms,
                "role": role,
            }
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(self.timeout_sec)
            client.connect(str(self.socket_path))
            client.sendall(json.dumps(request_payload, ensure_ascii=True).encode("utf-8") + b"\n")
            chunks: list[bytes] = []
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        if not chunks:
            return {}
        response = json.loads(b"".join(chunks).decode("utf-8").strip())
        if response.get("ok") is False:
            raise PermissionError(f"unix sidecar request failed: {response.get('error', 'unknown')}")
        return dict(response)
