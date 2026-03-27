#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import urlopen

REPO_ROOT = Path(__file__).resolve().parents[1]


def _env() -> dict[str, str]:
    env = os.environ.copy()
    current = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(REPO_ROOT) if not current else f"{REPO_ROOT}{os.pathsep}{current}"
    return env


def _terminate_pid(pid: int | None) -> None:
    if pid is None or pid <= 0:
        return
    if os.name == "nt":
        system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
        taskkill = shutil.which("taskkill") or str(system_root / "System32" / "taskkill.exe")
        try:
            subprocess.run([taskkill, "/PID", str(pid), "/T", "/F"], check=False, capture_output=True, text=True)
        except OSError:
            pass
        return
    try:
        os.kill(pid, 15)
    except OSError:
        return
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return
        time.sleep(0.05)
    try:
        os.kill(pid, 9)
    except OSError:
        pass


def _command_display(argv: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    import shlex
    return " ".join(shlex.quote(part) for part in argv)


def _run(argv: list[str], *, input_text: str | None = None, allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
    print(f"[smoke] $ {_command_display(argv)}")
    completed = subprocess.run(
        argv,
        input=input_text,
        text=True,
        capture_output=True,
        cwd=REPO_ROOT,
        env=_env(),
        check=False,
    )
    if completed.stdout.strip():
        print(completed.stdout.strip())
    if completed.returncode != 0 and not allow_failure:
        stderr = completed.stderr.strip()
        raise RuntimeError(stderr or f"command failed with exit code {completed.returncode}")
    return completed


def _run_json(argv: list[str], *, input_text: str | None = None, allow_failure: bool = False) -> dict[str, object]:
    completed = _run(argv, input_text=input_text, allow_failure=allow_failure)
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"expected JSON output from {' '.join(argv)}, got: {completed.stdout!r}") from exc
    if completed.returncode != 0 and not allow_failure:
        raise RuntimeError(str(payload))
    return dict(payload)


def _poll_http(url: str, *, timeout_sec: float = 15.0) -> str:
    deadline = time.time() + timeout_sec
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=1.0) as response:  # noqa: S310
                body = response.read().decode("utf-8", errors="replace")
            return body
        except URLError as exc:
            last_error = exc
            time.sleep(0.2)
    raise RuntimeError(f"UI did not become ready at {url}: {last_error}")


def _ui_process(port: int) -> subprocess.Popen[str]:
    argv = [
        sys.executable,
        "-m",
        "clawchain.agent_proxy_cli",
        "ui",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ]
    print(f"[smoke] $ {_command_display(argv)}")
    popen_kwargs: dict[str, object] = {
        "cwd": REPO_ROOT,
        "env": _env(),
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "text": True,
    }
    if os.name == "nt":
        flags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) or 0)
        flags |= int(getattr(subprocess, "CREATE_NO_WINDOW", 0) or 0)
        if flags:
            popen_kwargs["creationflags"] = flags
    else:
        popen_kwargs["start_new_session"] = True
    return subprocess.Popen(argv, **popen_kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-platform ClawChain smoke runner")
    parser.add_argument("--platform", choices=("auto", "linux", "windows"), default="auto")
    parser.add_argument("--account", default=None)
    parser.add_argument("--password", default="smoke-password")
    parser.add_argument("--workspace", default=str(REPO_ROOT))
    parser.add_argument("--root-dir", default=None)
    parser.add_argument("--session", default="smoke-session")
    parser.add_argument("--run", default="smoke-run")
    parser.add_argument("--port", type=int, default=8893)
    parser.add_argument("--bootstrap-local-evm", action="store_true")
    parser.add_argument("--deployer-private-key", default=None)
    args = parser.parse_args()

    platform_name = args.platform
    if platform_name == "auto":
        platform_name = "windows" if os.name == "nt" else "linux"
    account = args.account or f"smoke-{platform_name}"
    registry_root = Path(args.root_dir).expanduser().resolve() if args.root_dir else (
        Path(tempfile.gettempdir()) / f"clawchain-smoke-{platform_name}-{int(time.time())}"
    )
    workspace = Path(args.workspace).expanduser().resolve()
    registry_root.mkdir(parents=True, exist_ok=True)
    account_root = registry_root / account
    account_root.mkdir(parents=True, exist_ok=True)

    config_path = account_root / "agent-proxy.config.json"
    state_path = account_root / "agent-proxy-service.json"
    proof_manifest_path = account_root / "proof-manifest.json"
    smoke_file = account_root / "daemon-output.txt"
    ui_url = f"http://127.0.0.1:{args.port}/"
    ui_proc: subprocess.Popen[str] | None = None
    local_devnet_pid: int | None = None

    try:
        _run_json([
            sys.executable,
            "-m",
            "clawchain.agent_proxy_cli",
            "config-init",
            account,
            args.password,
            "--config",
            str(config_path),
            "--root-dir",
            str(account_root),
            "--workspace",
            str(workspace),
            "--session",
            args.session,
            "--run",
            args.run,
            "--no-auto-evm",
        ])

        if args.bootstrap_local_evm:
            chain_argv = [
                sys.executable,
                "-m",
                "clawchain.agent_proxy_cli",
                "chain-connect",
                account,
                "--root-dir",
                str(registry_root),
                "--bootstrap-local-evm",
            ]
            if args.deployer_private_key:
                chain_argv.extend(["--deployer-private-key", args.deployer_private_key])
            chain_payload = _run_json(chain_argv)
            if not chain_payload.get("ok"):
                raise RuntimeError(f"chain bootstrap failed: {chain_payload}")
            local_devnet_pid = int(chain_payload.get("local_devnet_pid") or 0) or None
            chain_status = _run_json([
                sys.executable,
                "-m",
                "clawchain.agent_proxy_cli",
                "chain-status",
                account,
                "--root-dir",
                str(registry_root),
            ])
            if not chain_status.get("ok"):
                raise RuntimeError(f"chain status failed: {chain_status}")

        service_start = _run_json([
            sys.executable,
            "-m",
            "clawchain.agent_proxy_cli",
            "service-start",
            str(config_path),
        ])
        if not service_start.get("ok"):
            raise RuntimeError(f"service-start failed: {service_start}")

        service_status = _run_json([
            sys.executable,
            "-m",
            "clawchain.agent_proxy_cli",
            "service-status",
            str(config_path),
        ])
        if not service_status.get("ok") or not service_status.get("running"):
            raise RuntimeError(f"service-status failed: {service_status}")

        state = json.loads(state_path.read_text(encoding="utf-8"))
        socket_endpoint = str(state.get("socket_path") or "")
        if not socket_endpoint:
            raise RuntimeError(f"missing daemon socket endpoint: {state}")

        tool_payload = {
            "session_id": args.session,
            "run_id": args.run,
            "tool_name": "fs.write_text",
            "params": {"path": str(smoke_file), "content": "platform smoke\n"},
            "actor_id": account,
            "cwd": str(account_root),
        }
        tool_response = _run_json(
            [
                sys.executable,
                "-m",
                "clawchain.agent_proxy_cli",
                "daemon-tool-json",
                socket_endpoint,
            ],
            input_text=json.dumps(tool_payload, ensure_ascii=True),
        )
        if not tool_response.get("ok") or not smoke_file.exists():
            raise RuntimeError(f"daemon-tool-json failed: {tool_response}")

        proof_payload = _run_json([
            sys.executable,
            "-m",
            "clawchain.agent_proxy_cli",
            "proof",
            "--account",
            account,
            "--root-dir",
            str(registry_root),
            "--limit",
            "1",
            "--save-manifest",
            str(proof_manifest_path),
        ])
        if not proof_payload.get("ok") or not proof_manifest_path.exists():
            raise RuntimeError(f"proof export failed: {proof_payload}")

        verify_payload = _run_json([
            sys.executable,
            "-m",
            "clawchain.agent_proxy_cli",
            "verify",
            "--manifest",
            str(proof_manifest_path),
            "--account",
            account,
            "--root-dir",
            str(registry_root),
        ])
        if not verify_payload.get("ok"):
            raise RuntimeError(f"proof verify failed: {verify_payload}")

        ui_proc = _ui_process(args.port)
        body = _poll_http(ui_url)
        if "ClawChain Console" not in body:
            raise RuntimeError("UI responded but did not return the expected page")

        summary = {
            "ok": True,
            "platform": platform_name,
            "account": account,
            "root_dir": str(registry_root),
            "account_root": str(account_root),
            "workspace": str(workspace),
            "config_path": str(config_path),
            "state_path": str(state_path),
            "socket_endpoint": socket_endpoint,
            "ui_url": ui_url,
            "smoke_file": str(smoke_file),
            "proof_manifest_path": str(proof_manifest_path),
            "local_devnet_pid": local_devnet_pid,
        }
        print(json.dumps(summary, ensure_ascii=True, indent=2))
        return 0
    finally:
        if ui_proc is not None:
            ui_proc.terminate()
            try:
                ui_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                ui_proc.kill()
        if config_path.exists():
            _run([
                sys.executable,
                "-m",
                "clawchain.agent_proxy_cli",
                "service-stop",
                str(config_path),
            ], allow_failure=True)
        _terminate_pid(local_devnet_pid)


if __name__ == "__main__":
    raise SystemExit(main())
