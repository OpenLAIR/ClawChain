from __future__ import annotations

from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
from pathlib import Path
import socketserver
import time
import uuid

from ..canonical.sidecar import SidecarRemoteMetadataRecord, SidecarSecurityProfileRecord
from .remote import LocalAppendOnlyEvidenceSink, sidecar_request_signature


@dataclass(frozen=True)
class SidecarServiceConfig:
    root_dir: Path
    host: str = "127.0.0.1"
    port: int = 8765
    socket_path: Path | None = None
    auth_secret: str | None = None
    write_auth_secret: str | None = None
    read_auth_secret: str | None = None
    max_clock_skew_ms: int = 60_000
    replay_window_size: int = 4096


@dataclass(frozen=True)
class SidecarSecurityProfile(SidecarSecurityProfileRecord):
    pass


@dataclass(frozen=True)
class SidecarRemoteMetadata(SidecarRemoteMetadataRecord):
    pass


def sidecar_security_profile(config: SidecarServiceConfig, *, transport_mode: str = "generic") -> SidecarSecurityProfile:
    auth_enabled = any(
        secret is not None for secret in (config.auth_secret, config.write_auth_secret, config.read_auth_secret)
    )
    read_write_split = (
        config.write_auth_secret is not None
        and config.read_auth_secret is not None
        and config.write_auth_secret != config.read_auth_secret
    )
    return SidecarSecurityProfile(
        profile_version="v1",
        service_version="ClawChainSidecar/0.1",
        transport_mode=transport_mode,
        auth_enabled=auth_enabled,
        read_write_split=read_write_split,
        replay_protection_enabled=True,
        credential_mode="split" if read_write_split else ("shared" if auth_enabled else "none"),
        max_clock_skew_ms=config.max_clock_skew_ms,
        replay_window_size=config.replay_window_size,
    )


def sidecar_remote_metadata(config: SidecarServiceConfig, *, transport_mode: str) -> SidecarRemoteMetadata:
    return SidecarRemoteMetadata(
        metadata_version="v1",
        service_instance_id=uuid.uuid4().hex,
        started_at_ms=int(time.time() * 1000),
        security_profile=sidecar_security_profile(config, transport_mode=transport_mode),
    )


def build_sidecar_http_server(config: SidecarServiceConfig) -> ThreadingHTTPServer:
    sink = LocalAppendOnlyEvidenceSink(config.root_dir)
    sink.write_metadata(sidecar_remote_metadata(config, transport_mode="http").to_dict())
    seen_request_ids: dict[str, int] = {}

    def required_secret(role: str) -> str | None:
        if role == "write" and config.write_auth_secret is not None:
            return config.write_auth_secret
        if role == "read" and config.read_auth_secret is not None:
            return config.read_auth_secret
        return config.auth_secret

    def prune_seen(now_ms: int) -> None:
        threshold = now_ms - config.max_clock_skew_ms
        stale = [request_id for request_id, seen_at in seen_request_ids.items() if seen_at < threshold]
        for request_id in stale:
            seen_request_ids.pop(request_id, None)
        if len(seen_request_ids) > config.replay_window_size:
            excess = len(seen_request_ids) - config.replay_window_size
            for request_id, _ in sorted(seen_request_ids.items(), key=lambda item: item[1])[:excess]:
                seen_request_ids.pop(request_id, None)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ClawChainSidecar/0.1"

        def do_GET(self) -> None:  # noqa: N802
            authorized, error = self._authorized(method="GET", path=self.path, body=b"", role="read")
            if not authorized:
                self._write_json(409 if error == "replay_detected" else 401, {"ok": False, "error": error})
                return
            if self.path == "/healthz":
                self._write_json(200, {"ok": True})
                return
            if self.path == "/snapshot":
                snapshot = sink.snapshot()
                self._write_json(
                    200,
                    {
                        "rows": snapshot.rows,
                        "receipts": [
                            {
                                "session_id": receipt.session_id,
                                "batch_seq_no": receipt.batch_seq_no,
                                "merkle_root": receipt.merkle_root,
                                "event_ids": list(receipt.event_ids),
                                "anchor_mode": receipt.anchor_mode,
                                "anchor_backend": receipt.anchor_backend,
                                "anchor_reference": receipt.anchor_reference,
                            }
                            for receipt in snapshot.receipts
                        ],
                        "submissions": [
                            {
                                **asdict(submission),
                                "event_ids": list(submission.event_ids),
                            }
                            for submission in snapshot.submissions
                        ],
                        "bundles": snapshot.bundles,
                        "metadata": snapshot.metadata,
                    },
                )
                return
            self._write_json(404, {"ok": False, "error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            body = self._read_body()
            authorized, error = self._authorized(method="POST", path=self.path, body=body, role="write")
            if not authorized:
                self._write_json(409 if error == "replay_detected" else 401, {"ok": False, "error": error})
                return
            payload = json.loads(body.decode("utf-8")) if body else {}
            if self.path == "/events":
                event = payload.get("event")
                if not isinstance(event, dict):
                    self._write_json(400, {"ok": False, "error": "missing_event"})
                    return
                sink.append_event_row(event)
                self._write_json(200, {"ok": True})
                return
            if self.path == "/receipts":
                receipts = payload.get("receipts")
                if not isinstance(receipts, list):
                    self._write_json(400, {"ok": False, "error": "missing_receipts"})
                    return
                for receipt in receipts:
                    if isinstance(receipt, dict):
                        sink.append_receipt_row(receipt)
                self._write_json(200, {"ok": True, "count": len(receipts)})
                return
            if self.path == "/submissions":
                submissions = payload.get("submissions")
                if not isinstance(submissions, list):
                    self._write_json(400, {"ok": False, "error": "missing_submissions"})
                    return
                for submission in submissions:
                    if isinstance(submission, dict):
                        sink.append_submission_row(submission)
                self._write_json(200, {"ok": True, "count": len(submissions)})
                return
            if self.path == "/bundles":
                bundle_ref = payload.get("bundle_ref")
                bundle = payload.get("bundle")
                if not isinstance(bundle_ref, str) or not isinstance(bundle, dict):
                    self._write_json(400, {"ok": False, "error": "missing_bundle"})
                    return
                sink.append_bundle(bundle_ref, bundle)
                self._write_json(200, {"ok": True, "bundle_ref": bundle_ref})
                return
            if self.path == "/metadata":
                metadata = payload.get("metadata")
                if not isinstance(metadata, dict):
                    self._write_json(400, {"ok": False, "error": "missing_metadata"})
                    return
                sink.write_metadata(metadata)
                self._write_json(200, {"ok": True})
                return
            self._write_json(404, {"ok": False, "error": "not_found"})

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

        def _read_json(self) -> dict[str, object]:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return b""
            return self.rfile.read(length)

        def _authorized(self, *, method: str, path: str, body: bytes, role: str) -> tuple[bool, str]:
            request_id = self.headers.get("X-ClawChain-Request-Id")
            timestamp_raw = self.headers.get("X-ClawChain-Timestamp-Ms")
            if request_id is None or timestamp_raw is None:
                return False, "missing_request_metadata"
            try:
                timestamp_ms = int(timestamp_raw)
            except ValueError:
                return False, "invalid_request_timestamp"
            now_ms = int(time.time() * 1000)
            prune_seen(now_ms)
            if abs(now_ms - timestamp_ms) > config.max_clock_skew_ms:
                return False, "stale_request"
            if request_id in seen_request_ids:
                return False, "replay_detected"
            secret = required_secret(role)
            if secret is None:
                seen_request_ids[request_id] = now_ms
                return True, "ok"
            observed = self.headers.get("X-ClawChain-Auth")
            if observed is None:
                return False, "unauthorized"
            expected = sidecar_request_signature(
                method=method,
                path=path,
                body=body,
                request_id=request_id,
                timestamp_ms=timestamp_ms,
                auth_secret=secret,
            )
            if not hmac.compare_digest(observed, expected):
                return False, "unauthorized"
            seen_request_ids[request_id] = now_ms
            return True, "ok"

        def _write_json(self, status: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer((config.host, config.port), Handler)


def build_sidecar_unix_server(config: SidecarServiceConfig) -> socketserver.UnixStreamServer:
    if config.socket_path is None:
        raise ValueError("socket_path is required for unix sidecar server")
    sink = LocalAppendOnlyEvidenceSink(config.root_dir)
    sink.write_metadata(sidecar_remote_metadata(config, transport_mode="unix").to_dict())
    seen_request_ids: dict[str, int] = {}

    def required_secret(role: str) -> str | None:
        if role == "write" and config.write_auth_secret is not None:
            return config.write_auth_secret
        if role == "read" and config.read_auth_secret is not None:
            return config.read_auth_secret
        return config.auth_secret

    def prune_seen(now_ms: int) -> None:
        threshold = now_ms - config.max_clock_skew_ms
        stale = [request_id for request_id, seen_at in seen_request_ids.items() if seen_at < threshold]
        for request_id in stale:
            seen_request_ids.pop(request_id, None)
        if len(seen_request_ids) > config.replay_window_size:
            excess = len(seen_request_ids) - config.replay_window_size
            for request_id, _ in sorted(seen_request_ids.items(), key=lambda item: item[1])[:excess]:
                seen_request_ids.pop(request_id, None)
    config.socket_path.parent.mkdir(parents=True, exist_ok=True)
    if config.socket_path.exists():
        config.socket_path.unlink()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            raw = self.rfile.readline()
            if not raw:
                return
            wrapper = json.loads(raw.decode("utf-8"))
            request_id = wrapper.get("request_id")
            timestamp_ms = wrapper.get("timestamp_ms")
            role = wrapper.get("role")
            if not isinstance(request_id, str) or not isinstance(timestamp_ms, int):
                self._write_json({"ok": False, "error": "missing_request_metadata"})
                return
            if role not in {"read", "write"}:
                self._write_json({"ok": False, "error": "missing_request_role"})
                return
            now_ms = int(time.time() * 1000)
            prune_seen(now_ms)
            if abs(now_ms - timestamp_ms) > config.max_clock_skew_ms:
                self._write_json({"ok": False, "error": "stale_request"})
                return
            if request_id in seen_request_ids:
                self._write_json({"ok": False, "error": "replay_detected"})
                return
            secret = required_secret(role)
            if secret is not None:
                auth = wrapper.get("auth")
                payload = wrapper.get("payload")
                if not isinstance(auth, str) or not isinstance(payload, dict):
                    self._write_json({"ok": False, "error": "unauthorized"})
                    return
                expected = sidecar_request_signature(
                    method="UNIX",
                    path="sidecar",
                    body=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
                    request_id=request_id,
                    timestamp_ms=timestamp_ms,
                    auth_secret=secret,
                )
                if not hmac.compare_digest(auth, expected):
                    self._write_json({"ok": False, "error": "unauthorized"})
                    return
            else:
                payload = wrapper.get("payload")
                if not isinstance(payload, dict):
                    self._write_json({"ok": False, "error": "missing_payload"})
                    return
            seen_request_ids[request_id] = now_ms
            action = payload.get("action")
            if action == "append_event":
                event = payload.get("event")
                if isinstance(event, dict):
                    sink.append_event_row(event)
                    self._write_json({"ok": True})
                    return
                self._write_json({"ok": False, "error": "missing_event"})
                return
            if action == "append_receipts":
                receipts = payload.get("receipts")
                if isinstance(receipts, list):
                    for receipt in receipts:
                        if isinstance(receipt, dict):
                            sink.append_receipt_row(receipt)
                    self._write_json({"ok": True, "count": len(receipts)})
                    return
                self._write_json({"ok": False, "error": "missing_receipts"})
                return
            if action == "append_submissions":
                submissions = payload.get("submissions")
                if isinstance(submissions, list):
                    for submission in submissions:
                        if isinstance(submission, dict):
                            sink.append_submission_row(submission)
                    self._write_json({"ok": True, "count": len(submissions)})
                    return
                self._write_json({"ok": False, "error": "missing_submissions"})
                return
            if action == "snapshot":
                snapshot = sink.snapshot()
                self._write_json(
                    {
                        "rows": snapshot.rows,
                        "receipts": [
                            {
                                "session_id": receipt.session_id,
                                "batch_seq_no": receipt.batch_seq_no,
                                "merkle_root": receipt.merkle_root,
                                "event_ids": list(receipt.event_ids),
                                "anchor_mode": receipt.anchor_mode,
                                "anchor_backend": receipt.anchor_backend,
                                "anchor_reference": receipt.anchor_reference,
                            }
                            for receipt in snapshot.receipts
                        ],
                        "submissions": [
                            {
                                **asdict(submission),
                                "event_ids": list(submission.event_ids),
                            }
                            for submission in snapshot.submissions
                        ],
                        "bundles": snapshot.bundles,
                        "metadata": snapshot.metadata,
                    }
                )
                return
            if action == "append_bundle":
                bundle_ref = payload.get("bundle_ref")
                bundle = payload.get("bundle")
                if isinstance(bundle_ref, str) and isinstance(bundle, dict):
                    sink.append_bundle(bundle_ref, bundle)
                    self._write_json({"ok": True, "bundle_ref": bundle_ref})
                    return
                self._write_json({"ok": False, "error": "missing_bundle"})
                return
            if action == "write_metadata":
                metadata = payload.get("metadata")
                if isinstance(metadata, dict):
                    sink.write_metadata(metadata)
                    self._write_json({"ok": True})
                    return
                self._write_json({"ok": False, "error": "missing_metadata"})
                return
            if action == "healthz":
                self._write_json({"ok": True})
                return
            self._write_json({"ok": False, "error": "not_found"})

        def _write_json(self, payload: dict[str, object]) -> None:
            self.wfile.write(json.dumps(payload, ensure_ascii=True).encode("utf-8") + b"\n")

    return socketserver.UnixStreamServer(str(config.socket_path), Handler)


def main(argv: list[str] | None = None) -> int:
    import sys

    args = argv or sys.argv[1:]
    if len(args) not in {1, 3, 4, 5}:
        print(
            "usage: python -m clawchain.runtime.sidecar_service <root_dir> [host port [auth_secret]] | <root_dir> unix <socket_path> [auth_secret]"
        )
        return 2
    root_dir = Path(args[0])
    if len(args) == 3 and args[1] == "unix":
        server = build_sidecar_unix_server(
            SidecarServiceConfig(root_dir=root_dir, socket_path=Path(args[2]))
        )
    elif len(args) >= 4 and args[1] == "unix":
        server = build_sidecar_unix_server(
            SidecarServiceConfig(
                root_dir=root_dir,
                socket_path=Path(args[2]),
                auth_secret=(args[3] if len(args) >= 4 else None),
            )
        )
    else:
        host = args[1] if len(args) == 3 else "127.0.0.1"
        port = int(args[2]) if len(args) >= 3 else 8765
        auth_secret = args[3] if len(args) >= 4 else None
        server = build_sidecar_http_server(
            SidecarServiceConfig(root_dir=root_dir, host=host, port=port, auth_secret=auth_secret)
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if getattr(server, "server_address", None) is None and len(args) >= 3 and args[1] == "unix":
            socket_path = Path(args[2])
            if socket_path.exists():
                socket_path.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
