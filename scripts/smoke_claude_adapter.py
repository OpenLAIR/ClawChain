#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
ACCOUNT_ID = 'claude-smoke'
PASSWORD = 'smoke-password'


def _run(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        argv,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        text=True,
        input=input_text,
        capture_output=True,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f'command failed: {argv}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}'
        )
    return completed


def _run_json(argv: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None, check: bool = True) -> dict[str, object]:
    completed = _run(argv, env=env, cwd=cwd, check=check)
    payload = completed.stdout.strip()
    if not payload:
        return {}
    return json.loads(payload)


def _wait_until(predicate, *, timeout_sec: float = 10.0, interval_sec: float = 0.1, label: str) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(interval_sec)
    raise TimeoutError(f'timed out waiting for {label}')


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding='utf-8')
    path.chmod(0o755)


def main() -> int:
    temp_root = Path(tempfile.mkdtemp(prefix='claude-adapter-smoke-'))
    smoke_root = temp_root / 'smoke-root'
    workspace = temp_root / 'workspace'
    fake_bin = temp_root / 'fake-bin'
    fake_log = temp_root / 'fake-claude.log'
    manifest_path = temp_root / 'proof-manifest.json'
    fake_bin.mkdir(parents=True, exist_ok=True)
    workspace.mkdir(parents=True, exist_ok=True)

    target_dir = workspace / 'test-delete-dir'
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / 'payload.txt').write_text('claude smoke target\n', encoding='utf-8')

    fake_claude = fake_bin / 'claude'
    _write_executable(
        fake_claude,
        """#!/usr/bin/env bash
set -euo pipefail
: \"${FAKE_CLAUDE_LOG:?}\"
echo \"$0 $*\" >> \"$FAKE_CLAUDE_LOG\"
if [[ -n \"${CLAWCHAIN_AGENT_ID:-}\" ]]; then
  echo \"managed:${CLAWCHAIN_AGENT_ID}\" >> \"$FAKE_CLAUDE_LOG\"
  rm -rf \"${FAKE_CLAUDE_DELETE_TARGET:?}\"
  sleep 2
else
  echo \"unmanaged\" >> \"$FAKE_CLAUDE_LOG\"
  sleep 300
fi
""",
    )

    env = {**os.environ}
    env['PATH'] = f'{fake_bin}:{env.get("PATH", "")}'
    env['PYTHONPATH'] = str(REPO_ROOT)
    env['FAKE_CLAUDE_DELETE_TARGET'] = str(target_dir)
    env['FAKE_CLAUDE_LOG'] = str(fake_log)

    unmanaged = subprocess.Popen(
        ['claude', '--dangerously-skip-permissions'],
        cwd=str(workspace),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    registry_path = smoke_root / ACCOUNT_ID / 'session-registry.json'
    try:
        supervise_payload = _run(
            [
                PYTHON,
                '-m',
                'clawchain.agent_proxy_cli',
                'onboard',
                'claude-code',
                ACCOUNT_ID,
                PASSWORD,
                '--root-dir',
                str(smoke_root),
            ],
            env=env,
            cwd=REPO_ROOT,
            input_text='1\n1\nclaude-smoke-session\n',
        )

        _wait_until(lambda: registry_path.exists(), timeout_sec=15.0, label='session registry')
        registry = json.loads(registry_path.read_text(encoding='utf-8'))
        sessions = list(registry.get('sessions', []))
        if not sessions:
            raise RuntimeError(f'no sessions persisted in registry: {registry}')
        row = sessions[0]
        session_id = str(row.get('session_id') or '')
        config_path = Path(str(row.get('config_path') or ''))
        if not session_id or not config_path.exists():
            raise RuntimeError(f'invalid registry row: {row}')

        _wait_until(lambda: not target_dir.exists(), timeout_sec=15.0, label='managed Claude delete')

        history_output = _run(
            [
                PYTHON,
                '-m',
                'clawchain.agent_proxy_cli',
                'history',
                '--config',
                str(config_path),
                '--session',
                session_id,
            ],
            env=env,
            cwd=REPO_ROOT,
        )

        restore_output = _run(
            [
                PYTHON,
                '-m',
                'clawchain.agent_proxy_cli',
                'restore',
                '--config',
                str(config_path),
                '--session',
                session_id,
                '--approve',
            ],
            env=env,
            cwd=REPO_ROOT,
        )

        _wait_until(lambda: target_dir.exists(), timeout_sec=15.0, label='restored target')

        proof_payload = _run_json(
            [
                PYTHON,
                '-m',
                'clawchain.agent_proxy_cli',
                'proof',
                '--account',
                ACCOUNT_ID,
                '--root-dir',
                str(smoke_root),
                '--limit',
                '1',
                '--save-manifest',
                str(manifest_path),
            ],
            env=env,
            cwd=REPO_ROOT,
        )

        verify_payload = _run_json(
            [
                PYTHON,
                '-m',
                'clawchain.agent_proxy_cli',
                'verify',
                '--manifest',
                str(manifest_path),
                '--account',
                ACCOUNT_ID,
                '--root-dir',
                str(smoke_root),
            ],
            env=env,
            cwd=REPO_ROOT,
        )

        service_stop = _run_json(
            [
                PYTHON,
                '-m',
                'clawchain.agent_proxy_cli',
                'service-stop',
                str(config_path),
            ],
            env=env,
            cwd=REPO_ROOT,
            check=False,
        )

        result = {
            'ok': True,
            'temp_root': str(temp_root),
            'registry_path': str(registry_path),
            'session_id': session_id,
            'config_path': str(config_path),
            'supervise_stdout': supervise_payload.stdout.strip(),
            'history_stdout': history_output.stdout.strip(),
            'restore_stdout': restore_output.stdout.strip(),
            'proof': proof_payload,
            'verify': verify_payload,
            'service_stop': service_stop,
            'fake_claude_log': fake_log.read_text(encoding='utf-8') if fake_log.exists() else '',
        }
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    finally:
        try:
            unmanaged.terminate()
        except ProcessLookupError:
            pass
        try:
            unmanaged.kill()
        except ProcessLookupError:
            pass


if __name__ == '__main__':
    raise SystemExit(main())
