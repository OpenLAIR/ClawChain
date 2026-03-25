from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import sys

from .bridge import (
  build_receipts_from_runtime_events,
  verify_runtime_session,
)
from .runtime.store import JsonAnchorSubmissionStore, JsonlEventStore


def resolve_runtime_paths(runtime_root: Path) -> tuple[Path, Path, Path]:
  return (
      runtime_root / "events.jsonl",
      runtime_root / "receipts.json",
      runtime_root / "submissions.json",
  )


def summarize_runtime_store(event_store_path: Path) -> dict[str, object]:
  store = JsonlEventStore(event_store_path)
  rows = store.read_all()
  event_types = sorted({str(row["event_type"]) for row in rows})
  session_ids = sorted({str(row["session_id"]) for row in rows})
  return {
      "event_store_path": str(event_store_path),
      "event_store_segment_count": len(store.event_store_paths()),
      "event_count": len(rows),
      "session_ids": session_ids,
      "event_types": event_types,
  }


def summarize_submissions(submission_store_path: Path) -> dict[str, object]:
  if not submission_store_path.exists():
      return {
          "submission_store_path": str(submission_store_path),
          "submission_count": 0,
          "statuses": [],
          "status_counts": {},
          "backends": [],
      }
  rows = JsonAnchorSubmissionStore(submission_store_path).read_all()
  status_counts: dict[str, int] = {}
  for row in rows:
      status = str(row.get("status", "unknown"))
      status_counts[status] = status_counts.get(status, 0) + 1
  return {
      "submission_store_path": str(submission_store_path),
      "submission_count": len(rows),
      "statuses": sorted({str(row.get("status", "unknown")) for row in rows}),
      "status_counts": dict(sorted(status_counts.items())),
      "backends": sorted(
          {str(row["anchor_backend"]) for row in rows if row.get("anchor_backend") is not None}
      ),
  }


def export_and_verify_runtime(runtime_root: Path) -> dict[str, object]:
  event_store_path, receipts_path, submission_store_path = resolve_runtime_paths(runtime_root)
  bridge = build_receipts_from_runtime_events(
      event_store_path=event_store_path,
      receipts_path=receipts_path,
      submissions_path=submission_store_path,
      overwrite_receipts=False,
      overwrite_submissions=False,
  )
  summary = summarize_runtime_store(event_store_path)
  submission_summary = summarize_submissions(submission_store_path)
  verification = []
  for session_id in summary["session_ids"]:
      report = verify_runtime_session(
          event_store_path=event_store_path,
          receipts_path=receipts_path,
          session_id=str(session_id),
          submissions_path=submission_store_path,
      )
      verification.append(
          {
              "session_id": session_id,
              "ok": report.ok,
              "findings": [asdict(finding) for finding in report.findings],
          }
      )
  return {
      "runtime_root": str(runtime_root),
      "receipt_count": bridge.receipt_count,
      "summary": summary,
      "submissions": submission_summary,
      "verification": verification,
  }


def main(argv: list[str] | None = None) -> int:
  args = argv or sys.argv[1:]
  if len(args) != 1:
      print("usage: python -m clawchain.runtime_cli <runtime_root>")
      return 2
  result = export_and_verify_runtime(Path(args[0]))
  print(json.dumps(result, ensure_ascii=True, indent=2))
  failed = any(not entry["ok"] for entry in result["verification"])
  return 1 if failed else 0


if __name__ == "__main__":
  raise SystemExit(main())
