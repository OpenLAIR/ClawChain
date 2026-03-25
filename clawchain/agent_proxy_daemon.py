from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
from typing import Any
import uuid

from .agent_proxy import AgentProxyConfig, TransparentAgentProxy


def _jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(inner) for key, inner in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(inner) for inner in value]
    return value


def _daemon_socket_path(base_dir: Path) -> Path:
    candidate = base_dir / "agent-proxy-daemon.sock"
    if len(str(candidate)) <= 96:
        return candidate
    return Path(tempfile.gettempdir()) / f"occp-daemon-{uuid.uuid4().hex[:10]}.sock"


@dataclass(frozen=True)
class AgentProxyDaemonArtifacts:
    socket_path: str
    env_path: str
    wrapper_path: str


@dataclass
class AgentProxyDaemon:
    proxy: TransparentAgentProxy
    socket_path: Path
    server: socketserver.UnixStreamServer
    thread: threading.Thread
    lock: threading.Lock

    @classmethod
    def start(
        cls,
        *,
        config: AgentProxyConfig,
        session_id: str,
        run_id: str,
    ) -> tuple["AgentProxyDaemon", AgentProxyDaemonArtifacts]:
        proxy = TransparentAgentProxy.create(config)
        artifacts = proxy.prepare_launch_artifacts(session_id=session_id, run_id=run_id)
        socket_path = _daemon_socket_path(proxy.paths.base_dir)
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        if socket_path.exists():
            socket_path.unlink()
        lock = threading.Lock()

        class ThreadingUnixStreamServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                raw = self.rfile.readline()
                if not raw:
                    return
                payload = json.loads(raw.decode("utf-8"))
                action = str(payload.get("action", ""))
                if action == "ping":
                    self._write_json({"ok": True, "action": "pong"})
                    return
                if action == "list_sessions":
                    with lock:
                        self._write_json(
                            {
                                "ok": True,
                                "sessions": [
                                    {
                                        "session_id": session_key,
                                        "next_event_index": proxy._session_next_index.get(session_key),
                                        "last_event_hash": proxy._session_last_hash.get(session_key),
                                    }
                                    for session_key in sorted(proxy._session_next_index)
                                ],
                            }
                        )
                    return
                if action == "session_status":
                    session_key = str(payload["session_id"])
                    with lock:
                        verification = proxy.system.verify_session(session_key)
                        self._write_json(
                            {
                                "ok": True,
                                "session_id": session_key,
                                "verify_ok": verification.ok,
                                "finding_codes": [finding.code for finding in verification.findings],
                                "next_event_index": proxy._session_next_index.get(session_key),
                                "last_event_hash": proxy._session_last_hash.get(session_key),
                            }
                        )
                    return
                if action == "execute_tool":
                    with lock:
                        result = proxy.execute_tool(
                            session_id=str(payload["session_id"]),
                            run_id=str(payload["run_id"]),
                            actor_id=str(payload.get("actor_id", config.account_id)),
                            tool_name=str(payload["tool_name"]),
                            params=dict(payload.get("params", {})),
                            cwd=Path(str(payload["cwd"])) if payload.get("cwd") is not None else None,
                        )
                        verification = proxy.system.verify_session(str(payload["session_id"]))
                    self._write_json(
                        {
                            "ok": True,
                            "result": _jsonable(
                                {
                                    **asdict(result),
                                    "bootstrap": asdict(result.bootstrap),
                                }
                            ),
                            "verify_ok": verification.ok,
                            "finding_codes": [finding.code for finding in verification.findings],
                        }
                    )
                    return
                if action == "execute_command":
                    with lock:
                        result = proxy.execute_command(
                            session_id=str(payload["session_id"]),
                            run_id=str(payload["run_id"]),
                            actor_id=str(payload.get("actor_id", config.account_id)),
                            cmd=[str(part) for part in payload.get("cmd", [])],
                            cwd=Path(str(payload["cwd"])) if payload.get("cwd") is not None else None,
                            auto_recover=bool(payload.get("auto_recover", False)),
                        )
                        verification = proxy.system.verify_session(str(payload["session_id"]))
                    self._write_json(
                        {
                            "ok": True,
                            "result": _jsonable(
                                {
                                    **asdict(result),
                                    "bootstrap": asdict(result.bootstrap),
                                }
                            ),
                            "verify_ok": verification.ok,
                            "finding_codes": [finding.code for finding in verification.findings],
                        }
                    )
                    return
                self._write_json({"ok": False, "error": "unsupported_action"})

            def _write_json(self, payload: dict[str, Any]) -> None:
                body = json.dumps(payload, ensure_ascii=True).encode("utf-8") + b"\n"
                self.wfile.write(body)

        server = ThreadingUnixStreamServer(str(socket_path), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        daemon = cls(proxy=proxy, socket_path=socket_path, server=server, thread=thread, lock=lock)
        client = AgentProxyDaemonClient(socket_path)
        client.ping()
        return daemon, AgentProxyDaemonArtifacts(
            socket_path=str(socket_path),
            env_path=artifacts.env_path,
            wrapper_path=artifacts.wrapper_path,
        )

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        if self.socket_path.exists():
            self.socket_path.unlink()
        self.proxy.close()


@dataclass(frozen=True)
class AgentProxyDaemonClient:
    socket_path: Path

    def ping(self) -> dict[str, object]:
        return self._round_trip({"action": "ping"})

    def list_sessions(self) -> dict[str, object]:
        return self._round_trip({"action": "list_sessions"})

    def session_status(self, *, session_id: str) -> dict[str, object]:
        return self._round_trip({"action": "session_status", "session_id": session_id})

    def execute_tool(
        self,
        *,
        session_id: str,
        run_id: str,
        tool_name: str,
        params: dict[str, object],
        actor_id: str,
        cwd: Path | None = None,
    ) -> dict[str, object]:
        return self._round_trip(
            {
                "action": "execute_tool",
                "session_id": session_id,
                "run_id": run_id,
                "tool_name": tool_name,
                "params": params,
                "actor_id": actor_id,
                "cwd": str(cwd) if cwd is not None else None,
            }
        )

    def _round_trip(self, payload: dict[str, object]) -> dict[str, object]:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(self.socket_path))
            client.sendall(json.dumps(payload, ensure_ascii=True).encode("utf-8") + b"\n")
            chunks: list[bytes] = []
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        if not chunks:
            return {}
        return dict(json.loads(b"".join(chunks).decode("utf-8").strip()))


__all__ = [
    "AgentProxyDaemon",
    "AgentProxyDaemonArtifacts",
    "AgentProxyDaemonClient",
]
