from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time
from uuid import uuid4

from .protected_backup import (
    EncryptedBackupLocator,
    seal_backup_locator,
    unseal_backup_locator,
)
from ..canonical.commitments import CommitmentType, RecoveryCommitment
from .anchor import AnchorBackend, LocalAnchorBackend
from .anchor_service_utils import build_anchor_metadata, persist_and_mirror_anchor_result
from .batching import AnchorReceipt
from .sidecar import ProvenanceSidecar
from .store import JsonAnchorSubmissionStore, JsonReceiptStore


def _digest_path(path: Path) -> str:
    if path.is_file():
        return sha256(path.read_bytes()).hexdigest()
    entries: list[str] = []
    for child in sorted(path.rglob("*")):
        if child.is_dir():
            continue
        rel = child.relative_to(path)
        entries.append(f"{rel.as_posix()}:{sha256(child.read_bytes()).hexdigest()}")
    return sha256("\n".join(entries).encode("utf-8")).hexdigest()


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


@dataclass(frozen=True)
class RecoveryLocatorRecord:
    recovery_id: str
    created_ts_ms: int
    source_kind: str
    target_path_hash: str
    target_name_hint: str
    target_digest: str
    locator: EncryptedBackupLocator
    risk_reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "recovery_id": self.recovery_id,
            "created_ts_ms": self.created_ts_ms,
            "source_kind": self.source_kind,
            "target_path_hash": self.target_path_hash,
            "target_name_hint": self.target_name_hint,
            "target_digest": self.target_digest,
            "locator": asdict(self.locator),
            "risk_reason": self.risk_reason,
        }


@dataclass(frozen=True)
class RecoveryPlan:
    recovery_id: str
    source_kind: str
    target_path: Path
    risk_reason: str
    locator_record: RecoveryLocatorRecord


@dataclass(frozen=True)
class RecoveryProtectionBundle:
    target_path: Path
    command_preview: str
    plans: tuple[RecoveryPlan, ...]

    def primary_source_kind(self) -> str | None:
        return self.plans[0].source_kind if self.plans else None


@dataclass(frozen=True)
class RecoveryExecutionPolicy:
    mode: str = "assisted"
    auto_allowed_sources: tuple[str, ...] = ("snapshot", "git")
    require_manual_for_sources: tuple[str, ...] = ()

    def allows_auto(self, source_kind: str) -> bool:
        return self.mode == "auto" and source_kind in self.auto_allowed_sources


@dataclass(frozen=True)
class RecoveryImpactSetRecord:
    impact_set_id: str
    session_id: str
    created_ts_ms: int
    target_root: str
    risk_reason: str
    recovery_ids: tuple[str, ...]
    target_name_hints: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "impact_set_id": self.impact_set_id,
            "session_id": self.session_id,
            "created_ts_ms": self.created_ts_ms,
            "target_root": self.target_root,
            "risk_reason": self.risk_reason,
            "recovery_ids": list(self.recovery_ids),
            "target_name_hints": list(self.target_name_hints),
        }


@dataclass
class RecoveryAnchorService:
    anchor_backend: AnchorBackend = field(default_factory=LocalAnchorBackend)
    receipt_store: JsonReceiptStore | None = None
    submission_store: JsonAnchorSubmissionStore | None = None
    sidecar: ProvenanceSidecar | None = None
    seq_no: int = 0

    def anchor_plan(self, *, session_id: str, plan: RecoveryPlan) -> AnchorReceipt:
        commitment = RecoveryCommitment(
            recovery_id=plan.recovery_id,
            target_path_hash=plan.locator_record.target_path_hash,
            source_kind=plan.source_kind,
            result_digest=plan.locator_record.target_digest,
            verified=False,
            created_ts_ms=plan.locator_record.created_ts_ms,
            metadata={
                "recovery_id": plan.recovery_id,
                "target_name_hint": plan.locator_record.target_name_hint,
                "risk_reason": plan.risk_reason,
                "phase": "planned",
            },
        )
        return self._anchor_commitment(commitment, session_id=session_id)

    def anchor_result(
        self,
        *,
        session_id: str,
        plan: RecoveryPlan,
        restored_digest: str,
        verified: bool,
    ) -> AnchorReceipt:
        commitment = RecoveryCommitment(
            recovery_id=plan.recovery_id,
            target_path_hash=plan.locator_record.target_path_hash,
            source_kind=plan.source_kind,
            result_digest=restored_digest,
            verified=verified,
            created_ts_ms=int(time.time() * 1000),
            metadata={
                "recovery_id": plan.recovery_id,
                "target_name_hint": plan.locator_record.target_name_hint,
                "risk_reason": plan.risk_reason,
                "phase": "verified" if verified else "completed",
                "expected_digest": plan.locator_record.target_digest,
            },
        )
        return self._anchor_commitment(commitment, session_id=session_id)

    def _anchor_commitment(self, commitment: RecoveryCommitment, *, session_id: str) -> AnchorReceipt:
        envelope = commitment.to_envelope(sequence_no=self.seq_no)
        receipt = AnchorReceipt(
            session_id=session_id,
            batch_seq_no=self.seq_no,
            merkle_root=envelope.commitment,
            event_ids=(commitment.recovery_id,),
            commitment_type=CommitmentType.RECOVERY.value,
            subject_id=commitment.recovery_id,
            metadata=build_anchor_metadata(
                envelope=envelope,
                base_metadata={
                    "target_path_hash": commitment.target_path_hash,
                    "source_kind": commitment.source_kind,
                    "verified": commitment.verified,
                    **commitment.metadata,
                },
            ),
        )
        self.seq_no += 1
        anchored = self.anchor_backend.submit(receipt)
        persist_and_mirror_anchor_result(
            anchored=anchored,
            receipt_store=self.receipt_store,
            submission_store=self.submission_store,
            sidecar=self.sidecar,
            anchor_backend=self.anchor_backend,
        )
        return anchored


@dataclass
class RecoveryCatalogStore:
    path: Path

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def append(self, record: RecoveryLocatorRecord) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_dict(), ensure_ascii=True) + "\n")

    def read_all(self) -> list[RecoveryLocatorRecord]:
        rows: list[RecoveryLocatorRecord] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                rows.append(recovery_locator_record_from_dict(json.loads(line)))
        return rows


@dataclass
class RecoveryImpactSetCatalogStore:
    path: Path

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def append(self, record: RecoveryImpactSetRecord) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_dict(), ensure_ascii=True) + "\n")

    def read_all(self) -> list[RecoveryImpactSetRecord]:
        rows: list[RecoveryImpactSetRecord] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                rows.append(recovery_impact_set_record_from_dict(json.loads(line)))
        return rows


@dataclass
class RecoveryRepository:
    vault_root: Path
    catalog_store: RecoveryCatalogStore

    def __post_init__(self) -> None:
        self.vault_root.mkdir(parents=True, exist_ok=True)

    def create_snapshot_plan(
        self,
        *,
        source_path: Path,
        recipient_public_key_pem: str,
        risk_reason: str,
    ) -> RecoveryPlan:
        if not source_path.exists():
            raise FileNotFoundError(source_path)
        recovery_id = f"recovery-{uuid4().hex}"
        snapshot_root = self.vault_root / recovery_id
        snapshot_root.mkdir(parents=True, exist_ok=True)
        snapshot_path = snapshot_root / source_path.name
        if source_path.is_dir():
            shutil.copytree(source_path, snapshot_path)
            snapshot_kind = "directory"
        else:
            shutil.copy2(source_path, snapshot_path)
            snapshot_kind = "file"
        locator_payload = {
            "source_kind": "snapshot",
            "source_path": str(source_path),
            "snapshot_path": str(snapshot_path),
            "snapshot_kind": snapshot_kind,
        }
        locator = seal_backup_locator(locator_payload, recipient_public_key_pem)
        record = RecoveryLocatorRecord(
            recovery_id=recovery_id,
            created_ts_ms=int(time.time() * 1000),
            source_kind="snapshot",
            target_path_hash=sha256(str(source_path.resolve()).encode("utf-8")).hexdigest(),
            target_name_hint=source_path.name,
            target_digest=_digest_path(source_path),
            locator=locator,
            risk_reason=risk_reason,
        )
        self.catalog_store.append(record)
        return RecoveryPlan(
            recovery_id=recovery_id,
            source_kind="snapshot",
            target_path=source_path,
            risk_reason=risk_reason,
            locator_record=record,
        )

    def create_git_plan(
        self,
        *,
        source_path: Path,
        recipient_public_key_pem: str,
        risk_reason: str,
        revision: str = "HEAD",
    ) -> RecoveryPlan | None:
        repo_probe = source_path.parent if source_path.exists() and source_path.is_file() else source_path
        repo_root = self._git_repo_root(repo_probe)
        if repo_root is None:
            return None
        resolved_source = source_path.expanduser().resolve()
        try:
            relative_path = str(resolved_source.relative_to(repo_root.resolve()))
        except ValueError:
            return None
        object_id_probe = _run_git(["rev-parse", f"{revision}:{relative_path}"], cwd=repo_root)
        if object_id_probe.returncode != 0:
            return None
        object_id = object_id_probe.stdout.strip()
        if not object_id:
            return None
        object_type_probe = _run_git(["cat-file", "-t", object_id], cwd=repo_root)
        object_type = object_type_probe.stdout.strip() if object_type_probe.returncode == 0 else ""
        if source_path.exists():
            target_digest = _digest_path(source_path)
        elif object_type == "blob":
            show = subprocess.run(
                ["git", "show", f"{revision}:{relative_path}"],
                cwd=repo_root,
                capture_output=True,
                check=False,
            )
            if show.returncode != 0:
                return None
            target_digest = sha256(show.stdout).hexdigest()
        else:
            target_digest = object_id
        recovery_id = f"recovery-{uuid4().hex}"
        locator_payload = {
            "source_kind": "git",
            "source_path": str(source_path),
            "repo_root": str(repo_root),
            "relative_path": relative_path,
            "revision": revision,
            "blob_id": object_id,
            "git_object_type": object_type or None,
        }
        locator = seal_backup_locator(locator_payload, recipient_public_key_pem)
        record = RecoveryLocatorRecord(
            recovery_id=recovery_id,
            created_ts_ms=int(time.time() * 1000),
            source_kind="git",
            target_path_hash=sha256(str(source_path.resolve()).encode("utf-8")).hexdigest(),
            target_name_hint=source_path.name,
            target_digest=target_digest,
            locator=locator,
            risk_reason=risk_reason,
        )
        self.catalog_store.append(record)
        return RecoveryPlan(
            recovery_id=recovery_id,
            source_kind="git",
            target_path=source_path,
            risk_reason=risk_reason,
            locator_record=record,
        )

    def restore(
        self,
        *,
        plan: RecoveryPlan,
        recipient_private_key_pem: str,
        destination_path: Path | None = None,
    ) -> Path:
        locator = unseal_backup_locator(plan.locator_record.locator, recipient_private_key_pem)
        source_kind = str(locator["source_kind"])
        destination = destination_path or Path(str(locator["source_path"]))
        if source_kind == "snapshot":
            snapshot_path = Path(str(locator["snapshot_path"]))
            snapshot_kind = str(locator["snapshot_kind"])
            if snapshot_kind == "directory":
                if destination.exists():
                    shutil.rmtree(destination)
                shutil.copytree(snapshot_path, destination)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(snapshot_path, destination)
            return destination
        if source_kind == "git":
            repo_root = Path(str(locator["repo_root"]))
            relative_path = str(locator["relative_path"])
            revision = str(locator["revision"])
            source_path = Path(str(locator["source_path"]))
            if destination.resolve() == source_path.resolve():
                result = _run_git(["checkout", revision, "--", relative_path], cwd=repo_root)
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or "git checkout failed")
                return destination
            show = _run_git(["show", f"{revision}:{relative_path}"], cwd=repo_root)
            if show.returncode != 0:
                raise RuntimeError(show.stderr.strip() or "git show failed")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(show.stdout, encoding="utf-8")
            return destination
        raise RuntimeError(f"unsupported recovery source kind: {source_kind}")

    def plan_from_record(
        self,
        *,
        record: RecoveryLocatorRecord,
        recipient_private_key_pem: str,
    ) -> RecoveryPlan:
        locator = unseal_backup_locator(record.locator, recipient_private_key_pem)
        target_path = Path(str(locator["source_path"]))
        return RecoveryPlan(
            recovery_id=record.recovery_id,
            source_kind=record.source_kind,
            target_path=target_path,
            risk_reason=record.risk_reason,
            locator_record=record,
        )

    @staticmethod
    def _git_repo_root(start: Path) -> Path | None:
        probe_start = start
        while not probe_start.exists():
            parent = probe_start.parent
            if parent == probe_start:
                return None
            probe_start = parent
        probe = _run_git(["rev-parse", "--show-toplevel"], cwd=probe_start if probe_start.is_dir() else probe_start.parent)
        if probe.returncode != 0:
            return None
        return Path(probe.stdout.strip())


_SENSITIVE_PATH_TOKENS: tuple[str, ...] = (
    ".env", ".ssh/", ".gnupg/", ".aws/", ".kube/",
    ".bashrc", ".zshrc", ".profile", ".bash_profile",
    "id_rsa", "id_ed25519", "credentials",
)


def _path_is_sensitive(path: str) -> bool:
    lowered = path.lower()
    return any(token in lowered for token in _SENSITIVE_PATH_TOKENS)


def _shell_tokens(command_text: str) -> list[str]:
    text = str(command_text or "").strip()
    if not text:
        return []
    looks_windows = bool(re.search(r"[A-Za-z]:\\", text)) or ("\\" in text and os.name != "nt")
    try:
        return [str(token) for token in shlex.split(text, posix=(False if looks_windows else (os.name != "nt")))]
    except ValueError:
        return text.split()


def _unwrap_shell_command(command_text: str) -> tuple[list[str], str]:
    text = str(command_text or "").strip()
    tokens = _shell_tokens(text)
    lowered = [token.lower() for token in tokens]
    if not tokens:
        return [], text
    launcher = Path(tokens[0]).name.lower()
    if launcher in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        for flag in ("-command", "-c"):
            if flag in lowered:
                index = lowered.index(flag)
                nested = " ".join(tokens[index + 1:])
                return _unwrap_shell_command(nested)
    if launcher in {"cmd", "cmd.exe"} and len(tokens) >= 3 and lowered[1] in {"/c", "/k"}:
        nested = " ".join(tokens[2:])
        return _unwrap_shell_command(nested)
    return tokens, text


def _is_output_only_command(tokens: list[str]) -> bool:
    if not tokens:
        return False
    return Path(tokens[0]).name.lower() in {"write-output", "write-host", "write-information", "echo", "printf"}


def looks_like_risky_action(*, tool_name: str, params: dict[str, object]) -> tuple[bool, str]:
    if tool_name == "fs.delete":
        return True, "destructive_delete"
    if tool_name == "fs.move":
        src = str(params.get("src", params.get("path", ""))).lower()
        dst = str(params.get("dst", "")).lower()
        if dst.endswith((".bak", ".tmp", ".trash")):
            return True, "destructive_move"
        if _path_is_sensitive(src):
            return True, "sensitive_file_move"
        return True, "destructive_move"
    if tool_name == "fs.write_text":
        path = str(params.get("path", "")).lower()
        if any(token in path for token in (".env", ".bashrc", ".zshrc", "config", "settings")):
            return True, "config_integrity_mutation"
    if tool_name == "fs.chmod":
        mode = str(params.get("mode", ""))
        if mode in ("000", "0o000", "0"):
            return True, "destructive_permission_change"
        path = str(params.get("path", ""))
        if _path_is_sensitive(path):
            return True, "sensitive_permission_change"
    if tool_name == "fs.chown":
        path = str(params.get("path", ""))
        if _path_is_sensitive(path):
            return True, "sensitive_ownership_change"
        return True, "ownership_change"
    if tool_name == "secret.read_env":
        return True, "secret_access"
    if tool_name != "system.run":
        return False, "non-shell-action"
    cmd = params.get("cmd")
    if isinstance(cmd, (list, tuple)):
        tokens = [str(token) for token in cmd]
        command_text = " ".join(tokens)
    else:
        command_text = str(cmd or "")
        tokens = []
    tokens, command_text = _unwrap_shell_command(command_text)
    normalized = command_text.lower()
    if _is_output_only_command(tokens):
        return False, "shell-output-only"
    if "git reset --hard" in normalized:
        return True, "destructive_git_reset"
    if "git clean" in normalized and ("-fd" in normalized or "-fx" in normalized):
        return True, "destructive_git_clean"
    if "remove-item" in normalized:
        return True, "destructive_delete"
    if any(token in {"del", "erase"} or token.endswith("\\del") or token.endswith("/del") for token in tokens):
        return True, "destructive_delete"
    if any(token == "rm" or token.endswith("/rm") for token in tokens):
        return True, "destructive_delete"
    if any("*" in token for token in tokens):
        return True, "wildcard_destructive_scope"
    if "find" in tokens and "-delete" in tokens:
        return True, "destructive_find_delete"
    if any(token == "mv" or token.endswith("/mv") for token in tokens):
        return True, "destructive_move"
    if any(token == "truncate" or token.endswith("/truncate") for token in tokens):
        return True, "destructive_truncate"
    if any(token == "dd" or token.endswith("/dd") for token in tokens):
        return True, "destructive_overwrite"
    if "chmod" in tokens and "000" in normalized:
        return True, "destructive_permission_change"
    if "pip" in tokens and "install" in tokens and "--force-reinstall" in normalized:
        return True, "dependency_force_reinstall"
    if "sed" in tokens and "-i" in tokens:
        return True, "in_place_file_edit"
    for token in tokens:
        if _path_is_sensitive(token):
            return True, "sensitive_path_access"
    return False, "not_high_risk"


def recovery_locator_record_from_dict(row: dict[str, object]) -> RecoveryLocatorRecord:
    locator_row = dict(row["locator"])
    locator = EncryptedBackupLocator(
        algorithm=str(locator_row["algorithm"]),
        recipient_key_id=str(locator_row["recipient_key_id"]),
        encrypted_key_b64=str(locator_row["encrypted_key_b64"]),
        nonce_b64=str(locator_row["nonce_b64"]),
        ciphertext_b64=str(locator_row["ciphertext_b64"]),
        key_encryption_algorithm=str(locator_row["key_encryption_algorithm"]),
        ciphertext_digest=str(locator_row["ciphertext_digest"]),
    )
    return RecoveryLocatorRecord(
        recovery_id=str(row["recovery_id"]),
        created_ts_ms=int(row["created_ts_ms"]),
        source_kind=str(row["source_kind"]),
        target_path_hash=str(row["target_path_hash"]),
        target_name_hint=str(row["target_name_hint"]),
        target_digest=str(row["target_digest"]),
        locator=locator,
        risk_reason=str(row["risk_reason"]),
    )


def recovery_impact_set_record_from_dict(row: dict[str, object]) -> RecoveryImpactSetRecord:
    return RecoveryImpactSetRecord(
        impact_set_id=str(row["impact_set_id"]),
        session_id=str(row["session_id"]),
        created_ts_ms=int(row["created_ts_ms"]),
        target_root=str(row["target_root"]),
        risk_reason=str(row["risk_reason"]),
        recovery_ids=tuple(str(item) for item in row.get("recovery_ids", ()) or ()),
        target_name_hints=tuple(str(item) for item in row.get("target_name_hints", ()) or ()),
    )


__all__ = [
    "RecoveryCatalogStore",
    "RecoveryAnchorService",
    "RecoveryExecutionPolicy",
    "RecoveryImpactSetCatalogStore",
    "RecoveryImpactSetRecord",
    "RecoveryLocatorRecord",
    "RecoveryPlan",
    "RecoveryProtectionBundle",
    "RecoveryRepository",
    "recovery_impact_set_record_from_dict",
    "looks_like_risky_action",
    "recovery_locator_record_from_dict",
]
