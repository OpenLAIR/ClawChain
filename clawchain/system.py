from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import subprocess
import time
from typing import Callable

from .audit.cli import extract_risk_signal_records
from .audit.cli import extract_risk_signals as extract_session_risk_signals
from .audit.cli import verify_jsonl_store
from .audit.signals import RiskSignal
from .audit.verifier import VerificationReport
from .canonical.attestations import DelegationCertificate
from .runtime.anchor import AnchorBackend, LocalAnchorBackend, SimulatedChainBackend
from .runtime.batching import AnchorReceipt, BatchCommitter, BatchWindow
from .runtime.bus import RuntimeEventBus
from .runtime.delegation_anchor import DelegationAnchorService
from .runtime.evidence_bundle import (
    BackupLocatorBundleStore,
    DelegationBundleStore,
    EventBatchBundleStore,
)
from .runtime.openclaw import OpenClawRuntimeAdapter
from .runtime.protected_backup import (
    AsymmetricKeyPair,
    BackupCatalogStore,
    ProtectedBackupAnchorService,
    ProtectedBackupRecord,
    ProtectedBackupRepository,
    generate_rsa_key_pair,
    load_rsa_key_pair,
    write_rsa_key_pair,
)
from .runtime.recovery import (
    RecoveryAnchorService,
    RecoveryCatalogStore,
    RecoveryExecutionPolicy,
    RecoveryImpactSetCatalogStore,
    RecoveryImpactSetRecord,
    RecoveryProtectionBundle,
    RecoveryRepository,
    looks_like_risky_action,
)
from .runtime.remote import LocalAppendOnlyEvidenceSink
from .runtime.remote import RemoteEvidenceSink
from .runtime.service import ClawChainRuntime
from .runtime.sidecar import ProvenanceSidecar
from .runtime.store import JsonAnchorSubmissionStore, JsonReceiptStore, JsonlEventStore


@dataclass(frozen=True)
class ClawChainConfig:
    capture_mode: str = "strict"
    remote_evidence_mode: str = "sidecar"
    encryption_mode: str = "protected"
    anchor_mode: str = "local"
    recovery_mode: str = "protected-backup"
    batch_max_events: int = 64
    risky_action_recovery_sources: tuple[str, ...] = ("snapshot",)
    recovery_execution_mode: str = "assisted"
    git_context_mode: str = "bind-existing-git"
    git_max_file_count_per_target: int = 512
    git_max_total_bytes_per_target: int = 32 * 1024 * 1024
    git_force_snapshot_path_tokens: tuple[str, ...] = (".git",)

    @property
    def uses_remote_evidence(self) -> bool:
        return self.remote_evidence_mode == "sidecar"

    @property
    def uses_protected_encryption(self) -> bool:
        return self.encryption_mode == "protected"

    @property
    def uses_protected_recovery(self) -> bool:
        return self.recovery_mode == "protected-backup"

    @property
    def needs_key_pair(self) -> bool:
        return self.uses_protected_encryption or self.uses_protected_recovery

    @classmethod
    def minimal(cls, *, anchor_mode: str = "local") -> "ClawChainConfig":
        return cls(
            remote_evidence_mode="none",
            encryption_mode="none",
            anchor_mode=anchor_mode,
            recovery_mode="none",
        )

    @classmethod
    def hardened(cls, *, anchor_mode: str = "local") -> "ClawChainConfig":
        return cls(
            remote_evidence_mode="sidecar",
            encryption_mode="protected",
            anchor_mode=anchor_mode,
            recovery_mode="protected-backup",
        )


@dataclass(frozen=True)
class ClawChainPaths:
    root_dir: Path
    local_root: Path
    remote_root: Path
    vault_root: Path
    event_store_path: Path
    receipt_store_path: Path
    submission_store_path: Path
    backup_catalog_path: Path
    recovery_catalog_path: Path
    recovery_impact_set_catalog_path: Path
    public_key_path: Path
    private_key_path: Path
    event_bundles_dir: Path
    delegation_bundles_dir: Path
    backup_bundles_dir: Path

    @classmethod
    def from_root(
        cls,
        root_dir: Path,
        *,
        remote_root: Path | None = None,
        vault_root: Path | None = None,
    ) -> "ClawChainPaths":
        local_root = root_dir / "local"
        return cls(
            root_dir=root_dir,
            local_root=local_root,
            remote_root=remote_root or (root_dir / "remote"),
            vault_root=vault_root or (root_dir / "vault"),
            event_store_path=local_root / "events.jsonl",
            receipt_store_path=local_root / "receipts.json",
            submission_store_path=local_root / "submissions.json",
            backup_catalog_path=local_root / "backup-catalog.jsonl",
            recovery_catalog_path=local_root / "recovery-catalog.jsonl",
            recovery_impact_set_catalog_path=local_root / "recovery-impact-sets.jsonl",
            public_key_path=local_root / "keys" / "clawchain-public.pem",
            private_key_path=local_root / "keys" / "clawchain-private.pem",
            event_bundles_dir=local_root / "event-bundles",
            delegation_bundles_dir=local_root / "delegation-bundles",
            backup_bundles_dir=local_root / "backup-bundles",
        )


@dataclass(frozen=True)
class ClawChainCoreGoals:
    evidence_integrity: bool
    evidence_survivability: bool
    evidence_confidentiality: bool
    accountability: bool
    recovery_orchestration: bool


@dataclass(frozen=True)
class ProtectedBackupResult:
    record: ProtectedBackupRecord
    receipt: AnchorReceipt | None


@dataclass(frozen=True)
class RecoveryValidationOutcome:
    validator: str
    ok: bool
    message: str


RecoveryValidator = Callable[[Path], RecoveryValidationOutcome]


@dataclass
class ClawChainSystem:
    config: ClawChainConfig
    paths: ClawChainPaths
    runtime: ClawChainRuntime
    adapter: OpenClawRuntimeAdapter
    anchor_backend: AnchorBackend
    protected_backup_repository: ProtectedBackupRepository | None = None
    protected_backup_anchor_service: ProtectedBackupAnchorService | None = None
    recovery_repository: RecoveryRepository | None = None
    recovery_impact_set_catalog: RecoveryImpactSetCatalogStore | None = None
    recovery_anchor_service: RecoveryAnchorService | None = None
    delegation_anchor_service: DelegationAnchorService | None = None
    key_pair: AsymmetricKeyPair | None = None
    recovery_policy: RecoveryExecutionPolicy | None = None

    @staticmethod
    def _is_config_like_target(path: Path) -> bool:
        lowered = path.name.lower()
        return any(
            token in lowered
            for token in ("config", "settings", ".bashrc", ".zshrc", ".toml", ".yaml", ".yml", ".json")
        )

    @classmethod
    def _snapshot_source_for_target(cls, target_path: Path, *, risk_reason: str) -> Path:
        if target_path.is_file() and (
            "config" in risk_reason
            or cls._is_config_like_target(target_path)
        ):
            return target_path.parent
        return target_path

    @staticmethod
    def _path_file_count(path: Path) -> int:
        if not path.exists():
            return 0
        if path.is_file():
            return 1
        return sum(1 for child in path.rglob("*") if child.is_file())

    @staticmethod
    def _path_total_bytes(path: Path) -> int:
        if not path.exists():
            return 0
        if path.is_file():
            return path.stat().st_size
        return sum(child.stat().st_size for child in path.rglob("*") if child.is_file())

    def _should_force_snapshot_for_target(self, target_path: Path) -> bool:
        parts = {part.lower() for part in target_path.resolve().parts}
        forced_tokens = {token.lower() for token in self.config.git_force_snapshot_path_tokens}
        if parts & forced_tokens:
            return True
        file_count = self._path_file_count(target_path)
        if file_count > self.config.git_max_file_count_per_target:
            return True
        total_bytes = self._path_total_bytes(target_path)
        return total_bytes > self.config.git_max_total_bytes_per_target

    @staticmethod
    def _probe_git_repo_root(target_path: Path) -> Path | None:
        cwd = target_path if target_path.is_dir() else target_path.parent
        probe = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode != 0:
            return None
        root = probe.stdout.strip()
        return Path(root) if root else None

    @staticmethod
    def _run_git(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )

    def _ensure_managed_session_git(self, target_path: Path) -> Path | None:
        repo_root = self._probe_git_repo_root(target_path)
        if repo_root is not None:
            return repo_root
        repo_root = target_path if target_path.is_dir() else target_path.parent
        init = self._run_git(["init"], cwd=repo_root)
        if init.returncode != 0:
            return None
        self._run_git(["config", "user.email", "clawchain@local.invalid"], cwd=repo_root)
        self._run_git(["config", "user.name", "ClawChain"], cwd=repo_root)
        self._run_git(["add", "-A"], cwd=repo_root)
        status = self._run_git(["status", "--porcelain"], cwd=repo_root)
        if status.returncode != 0:
            return None
        if status.stdout.strip():
            commit = self._run_git(["commit", "-m", "clawchain session baseline"], cwd=repo_root)
            if commit.returncode != 0:
                return None
        return repo_root

    def _git_context_ready(self, target_path: Path) -> bool:
        mode = self.config.git_context_mode
        if mode == "bind-existing-git":
            return self._probe_git_repo_root(target_path) is not None
        if mode == "managed-session-git":
            return self._ensure_managed_session_git(target_path) is not None
        return False

    def _select_recovery_sources_for_target(
        self,
        *,
        target_path: Path,
        requested_sources: tuple[str, ...],
    ) -> tuple[str, ...]:
        selected: list[str] = []
        if "snapshot" in requested_sources:
            selected.append("snapshot")
        if "git" not in requested_sources:
            return tuple(selected)
        if self._should_force_snapshot_for_target(target_path):
            return tuple(selected)
        if self._git_context_ready(target_path):
            selected.insert(0, "git")
        return tuple(dict.fromkeys(selected))

    @staticmethod
    def _default_recovery_validators(
        *,
        restored_path: Path,
    ) -> tuple[RecoveryValidationOutcome, ...]:
        outcomes = [
            RecoveryValidationOutcome(
                validator="exists",
                ok=restored_path.exists(),
                message="restored path exists" if restored_path.exists() else "restored path is missing",
            )
        ]
        if restored_path.exists() and restored_path.is_file():
            outcomes.append(
                RecoveryValidationOutcome(
                    validator="nonempty",
                    ok=restored_path.stat().st_size > 0,
                    message="restored file is non-empty" if restored_path.stat().st_size > 0 else "restored file is empty",
                )
            )
        return tuple(outcomes)

    @classmethod
    def create(
        cls,
        *,
        root_dir: Path,
        config: ClawChainConfig | None = None,
        anchor_backend: AnchorBackend | None = None,
        remote_sink: RemoteEvidenceSink | None = None,
        remote_root: Path | None = None,
        vault_root: Path | None = None,
        reset_root: bool = False,
    ) -> "ClawChainSystem":
        config = config or ClawChainConfig()
        paths = ClawChainPaths.from_root(root_dir, remote_root=remote_root, vault_root=vault_root)
        if reset_root and paths.root_dir.exists():
            import shutil

            shutil.rmtree(paths.root_dir)
        paths.local_root.mkdir(parents=True, exist_ok=True)
        paths.remote_root.mkdir(parents=True, exist_ok=True)
        paths.vault_root.mkdir(parents=True, exist_ok=True)

        key_pair = None
        if config.needs_key_pair:
            if paths.public_key_path.exists() and paths.private_key_path.exists():
                key_pair = load_rsa_key_pair(
                    public_key_path=paths.public_key_path,
                    private_key_path=paths.private_key_path,
                )
            else:
                key_pair = write_rsa_key_pair(
                    generate_rsa_key_pair(),
                    public_key_path=paths.public_key_path,
                    private_key_path=paths.private_key_path,
                )
        batch_bundle_store = None
        delegation_bundle_store = None
        backup_bundle_store = None
        if key_pair is not None and config.uses_protected_encryption:
            batch_bundle_store = EventBatchBundleStore(
                root_dir=paths.event_bundles_dir,
                recipient_public_key_pem=key_pair.public_key_pem,
            )
            delegation_bundle_store = DelegationBundleStore(
                root_dir=paths.delegation_bundles_dir,
                recipient_public_key_pem=key_pair.public_key_pem,
            )
        if key_pair is not None and config.uses_protected_recovery:
            backup_bundle_store = BackupLocatorBundleStore(
                root_dir=paths.backup_bundles_dir,
                recipient_public_key_pem=key_pair.public_key_pem,
            )

        if anchor_backend is None:
            if config.anchor_mode == "simulated":
                anchor_backend = SimulatedChainBackend()
            else:
                anchor_backend = LocalAnchorBackend()

        sidecar = None
        if config.uses_remote_evidence:
            sidecar = ProvenanceSidecar(remote_sink or LocalAppendOnlyEvidenceSink(paths.remote_root))

        runtime = ClawChainRuntime(
            bus=RuntimeEventBus(store=JsonlEventStore(paths.event_store_path)),
            batcher=BatchCommitter(
                window=BatchWindow(max_events=config.batch_max_events),
                bundle_store=batch_bundle_store,
            ),
            anchor_backend=anchor_backend,
            receipt_store=JsonReceiptStore(paths.receipt_store_path),
            submission_store=JsonAnchorSubmissionStore(paths.submission_store_path),
            sidecar=sidecar,
        )

        protected_backup_repository = None
        protected_backup_anchor_service = None
        recovery_repository = None
        recovery_impact_set_catalog = None
        recovery_anchor_service = None
        if config.uses_protected_recovery and key_pair is not None:
            protected_backup_repository = ProtectedBackupRepository(
                vault_root=paths.vault_root,
                catalog_store=BackupCatalogStore(paths.backup_catalog_path),
            )
            recovery_repository = RecoveryRepository(
                vault_root=paths.vault_root / "recovery-snapshots",
                catalog_store=RecoveryCatalogStore(paths.recovery_catalog_path),
            )
            recovery_impact_set_catalog = RecoveryImpactSetCatalogStore(
                paths.recovery_impact_set_catalog_path,
            )
            protected_backup_anchor_service = ProtectedBackupAnchorService(
                anchor_backend=anchor_backend,
                receipt_store=runtime.receipt_store,
                submission_store=runtime.submission_store,
                bundle_store=backup_bundle_store,
                sidecar=sidecar,
            )
            recovery_anchor_service = RecoveryAnchorService(
                anchor_backend=anchor_backend,
                receipt_store=runtime.receipt_store,
                submission_store=runtime.submission_store,
                sidecar=sidecar,
            )

        delegation_anchor_service = DelegationAnchorService(
            anchor_backend=anchor_backend,
            receipt_store=runtime.receipt_store,
            submission_store=runtime.submission_store,
            bundle_store=delegation_bundle_store,
            sidecar=sidecar,
        )

        return cls(
            config=config,
            paths=paths,
            runtime=runtime,
            adapter=OpenClawRuntimeAdapter(),
            anchor_backend=anchor_backend,
            protected_backup_repository=protected_backup_repository,
            protected_backup_anchor_service=protected_backup_anchor_service,
            recovery_repository=recovery_repository,
            recovery_impact_set_catalog=recovery_impact_set_catalog,
            recovery_anchor_service=recovery_anchor_service,
            delegation_anchor_service=delegation_anchor_service,
            key_pair=key_pair,
            recovery_policy=RecoveryExecutionPolicy(mode=config.recovery_execution_mode),
        )

    def publish(self, event) -> list[AnchorReceipt]:
        return self.runtime.publish(event)

    def flush(self) -> list[AnchorReceipt]:
        return self.runtime.flush()

    def poll_anchor_submissions(self) -> list[dict]:
        return self.runtime.poll_anchor_submissions()

    def verify_session(self, session_id: str) -> VerificationReport:
        return verify_jsonl_store(
            event_store_path=self.paths.event_store_path,
            receipts_path=self.paths.receipt_store_path,
            submissions_path=self.paths.submission_store_path,
            session_id=session_id,
            remote_root_dir=(
                self.paths.remote_root if self.config.uses_remote_evidence else None
            ),
            bundle_private_keys=self.bundle_private_keys(),
        )

    def extract_risk_signals(self, session_id: str) -> list[dict[str, str]]:
        return extract_session_risk_signals(
            event_store_path=self.paths.event_store_path,
            receipts_path=self.paths.receipt_store_path,
            session_id=session_id,
        )

    def extract_risk_signal_records(self, session_id: str) -> list[RiskSignal]:
        return extract_risk_signal_records(
            event_store_path=self.paths.event_store_path,
            receipts_path=self.paths.receipt_store_path,
            session_id=session_id,
        )

    def create_protected_backup(
        self,
        *,
        source_path: Path,
        anchor: bool = True,
    ) -> ProtectedBackupResult:
        if self.protected_backup_repository is None or self.key_pair is None:
            raise RuntimeError("protected backup mode is not enabled")
        record = self.protected_backup_repository.create_backup(
            source_path=source_path,
            recipient_public_key_pem=self.key_pair.public_key_pem,
        )
        receipt = None
        if anchor and self.protected_backup_anchor_service is not None:
            receipt = self.protected_backup_anchor_service.anchor_record(record)
        return ProtectedBackupResult(record=record, receipt=receipt)

    def restore_protected_backup(
        self,
        *,
        record: ProtectedBackupRecord,
        destination_path: Path,
    ) -> Path:
        if self.protected_backup_repository is None or self.key_pair is None:
            raise RuntimeError("protected backup mode is not enabled")
        return self.protected_backup_repository.restore_backup(
            record=record,
            recipient_private_key_pem=self.key_pair.private_key_pem,
            destination_path=destination_path,
        )

    def anchor_delegation(self, certificate: DelegationCertificate) -> AnchorReceipt:
        if self.delegation_anchor_service is None:
            raise RuntimeError("delegation anchoring is not enabled")
        return self.delegation_anchor_service.anchor_certificate(certificate)

    def protect_for_risky_action(
        self,
        *,
        target_path: Path,
        tool_name: str,
        params: dict[str, object],
        sources: tuple[str, ...] | None = None,
    ) -> RecoveryProtectionBundle | None:
        if self.recovery_repository is None or self.key_pair is None:
            return None
        risky, risk_reason = looks_like_risky_action(tool_name=tool_name, params=params)
        if not risky:
            return None
        requested_sources = sources or self.config.risky_action_recovery_sources
        plans = []
        selected_sources = self._select_recovery_sources_for_target(
            target_path=target_path,
            requested_sources=requested_sources,
        )
        if "git" in selected_sources:
            git_plan = self.recovery_repository.create_git_plan(
                source_path=target_path,
                recipient_public_key_pem=self.key_pair.public_key_pem,
                risk_reason=risk_reason,
            )
            if git_plan is not None:
                plans.append(git_plan)
        if target_path.exists() and "snapshot" in selected_sources:
            snapshot_source = self._snapshot_source_for_target(target_path, risk_reason=risk_reason)
            plans.append(
                self.recovery_repository.create_snapshot_plan(
                    source_path=snapshot_source,
                    recipient_public_key_pem=self.key_pair.public_key_pem,
                    risk_reason=risk_reason,
                )
            )
        if not plans:
            return None
        return RecoveryProtectionBundle(
            target_path=target_path,
            command_preview=str(params.get("cmd")),
            plans=tuple(plans),
        )

    def plan_recovery(
        self,
        *,
        session_id: str,
        run_id: str,
        event_index: int,
        timestamp_ms: int,
        actor_id: str,
        target_path: Path,
        tool_name: str,
        params: dict[str, object],
        parent_event_hash: str | None = None,
        sources: tuple[str, ...] | None = None,
    ) -> tuple[RecoveryProtectionBundle | None, object | None, AnchorReceipt | None]:
        protection = self.protect_for_risky_action(
            target_path=target_path,
            tool_name=tool_name,
            params=params,
            sources=sources,
        )
        if protection is None:
            return None, None, None
        risk_reason = protection.plans[0].risk_reason
        event = self.adapter.recovery_planned(
            session_id=session_id,
            run_id=run_id,
            event_index=event_index,
            timestamp_ms=timestamp_ms,
            actor_id=actor_id,
            recovery_id=protection.plans[0].recovery_id,
            target_path=str(target_path),
            source_kinds=tuple(plan.source_kind for plan in protection.plans),
            risk_reason=risk_reason,
            parent_event_hash=parent_event_hash,
        )
        self.publish(event)
        receipt = None
        if self.recovery_anchor_service is not None:
            receipt = self.recovery_anchor_service.anchor_plan(
                session_id=session_id,
                plan=protection.plans[0],
            )
        return protection, event, receipt

    def execute_recovery(
        self,
        *,
        protection: RecoveryProtectionBundle,
        preferred_source: str | None = None,
        destination_path: Path | None = None,
        session_id: str | None = None,
        run_id: str | None = None,
        event_index: int | None = None,
        actor_id: str = "recovery-orchestrator",
        parent_event_hash: str | None = None,
        require_manual_approval: bool | None = None,
    ) -> Path:
        if self.recovery_repository is None or self.key_pair is None:
            raise RuntimeError("recovery mode is not enabled")
        if not protection.plans:
            raise RuntimeError("no recovery plans available")
        selected = protection.plans[0]
        if preferred_source is not None:
            for plan in protection.plans:
                if plan.source_kind == preferred_source:
                    selected = plan
                    break
        if require_manual_approval is None:
            require_manual_approval = self.recovery_requires_manual_approval(
                source_kind=selected.source_kind
            )
        if require_manual_approval:
            raise RuntimeError(f"manual approval required for recovery source {selected.source_kind}")
        started_event = None
        if session_id is not None and run_id is not None and event_index is not None:
            started_event = self.adapter.recovery_started(
                session_id=session_id,
                run_id=run_id,
                event_index=event_index,
                timestamp_ms=int(time.time() * 1000),
                actor_id=actor_id,
                recovery_id=selected.recovery_id,
                target_path=str(protection.target_path),
                source_kind=selected.source_kind,
                parent_event_hash=parent_event_hash,
            )
            self.publish(started_event)
        return self.recovery_repository.restore(
            plan=selected,
            recipient_private_key_pem=self.key_pair.private_key_pem,
            destination_path=destination_path,
        )

    def recovery_requires_manual_approval(self, *, source_kind: str) -> bool:
        if self.recovery_policy is None:
            return False
        return not self.recovery_policy.allows_auto(source_kind)

    def record_recovery_impact_set(
        self,
        *,
        session_id: str,
        target_root: Path,
        risk_reason: str,
        protections: tuple[RecoveryProtectionBundle, ...],
    ) -> RecoveryImpactSetRecord | None:
        if self.recovery_impact_set_catalog is None or not protections:
            return None
        recovery_ids: list[str] = []
        target_name_hints: list[str] = []
        for protection in protections:
            for plan in protection.plans:
                recovery_ids.append(plan.recovery_id)
                target_name_hints.append(plan.locator_record.target_name_hint)
        record = RecoveryImpactSetRecord(
            impact_set_id=f"impact-set-{int(time.time() * 1000)}",
            session_id=session_id,
            created_ts_ms=int(time.time() * 1000),
            target_root=str(target_root),
            risk_reason=risk_reason,
            recovery_ids=tuple(recovery_ids),
            target_name_hints=tuple(target_name_hints),
        )
        self.recovery_impact_set_catalog.append(record)
        return record

    def execute_recovery_with_audit(
        self,
        *,
        protection: RecoveryProtectionBundle,
        preferred_source: str | None = None,
        destination_path: Path | None = None,
        session_id: str,
        run_id: str,
        start_event_index: int,
        actor_id: str = "recovery-orchestrator",
        parent_event_hash: str | None = None,
        require_manual_approval: bool | None = None,
    ) -> tuple[Path | None, object, object | None]:
        selected = protection.plans[0]
        if preferred_source is not None:
            for plan in protection.plans:
                if plan.source_kind == preferred_source:
                    selected = plan
                    break
        started = self.adapter.recovery_started(
            session_id=session_id,
            run_id=run_id,
            event_index=start_event_index,
            timestamp_ms=int(time.time() * 1000),
            actor_id=actor_id,
            recovery_id=selected.recovery_id,
            target_path=str(protection.target_path),
            source_kind=selected.source_kind,
            parent_event_hash=parent_event_hash,
        )
        self.publish(started)
        try:
            restored = self.execute_recovery(
                protection=protection,
                preferred_source=selected.source_kind,
                destination_path=destination_path,
                require_manual_approval=(
                    self.recovery_requires_manual_approval(source_kind=selected.source_kind)
                    if require_manual_approval is None
                    else require_manual_approval
                ),
            )
        except Exception as exc:
            failed = self.adapter.recovery_failed(
                session_id=session_id,
                run_id=run_id,
                event_index=start_event_index + 1,
                timestamp_ms=int(time.time() * 1000),
                actor_id=actor_id,
                recovery_id=selected.recovery_id,
                target_path=str(protection.target_path),
                source_kind=selected.source_kind,
                error_type=type(exc).__name__,
                error_message=str(exc),
                parent_event_hash=started.event_hash,
            )
            self.publish(failed)
            return None, started, failed
        completed = self.adapter.recovery_completed(
            session_id=session_id,
            run_id=run_id,
            event_index=start_event_index + 1,
            timestamp_ms=int(time.time() * 1000),
            actor_id=actor_id,
            recovery_id=selected.recovery_id,
            target_path=str(protection.target_path),
            source_kind=selected.source_kind,
            restored_path=str(restored),
            parent_event_hash=started.event_hash,
        )
        self.publish(completed)
        return restored, started, completed

    def verify_recovery_result(
        self,
        *,
        protection: RecoveryProtectionBundle,
        restored_path: Path,
        session_id: str,
        run_id: str,
        event_index: int,
        actor_id: str = "recovery-orchestrator",
        parent_event_hash: str | None = None,
        source_kind: str | None = None,
        validators: tuple[RecoveryValidator, ...] = (),
    ) -> tuple[bool, object, AnchorReceipt | None]:
        selected = protection.plans[0]
        if source_kind is not None:
            for plan in protection.plans:
                if plan.source_kind == source_kind:
                    selected = plan
                    break
        if restored_path.is_file():
            observed_digest = sha256(restored_path.read_bytes()).hexdigest()
        else:
            observed_digest = selected.locator_record.target_digest
        validator_outcomes = list(self._default_recovery_validators(restored_path=restored_path))
        for validator in validators:
            validator_outcomes.append(validator(restored_path))
        verified = observed_digest == selected.locator_record.target_digest and all(
            outcome.ok for outcome in validator_outcomes
        )
        event = self.adapter.recovery_verified(
            session_id=session_id,
            run_id=run_id,
            event_index=event_index,
            timestamp_ms=int(time.time() * 1000),
            actor_id=actor_id,
            recovery_id=selected.recovery_id,
            target_path=str(protection.target_path),
            source_kind=selected.source_kind,
            verified=verified,
            expected_digest=selected.locator_record.target_digest,
            observed_digest=observed_digest,
            parent_event_hash=parent_event_hash,
        )
        event.payload["validation_results"] = [
            {"validator": outcome.validator, "ok": outcome.ok, "message": outcome.message}
            for outcome in validator_outcomes
        ]
        self.publish(event)
        receipt = None
        if self.recovery_anchor_service is not None:
            receipt = self.recovery_anchor_service.anchor_result(
                session_id=session_id,
                plan=selected,
                restored_digest=observed_digest,
                verified=verified,
            )
        return verified, event, receipt

    def bundle_private_keys(self) -> dict[str, str] | None:
        if self.key_pair is None:
            return None
        bundle_keys: dict[str, str] = {}
        if self.config.uses_protected_encryption:
            bundle_keys["event_batch"] = self.key_pair.private_key_pem
            bundle_keys["delegation"] = self.key_pair.private_key_pem
        if self.config.uses_protected_recovery:
            bundle_keys["backup_locator"] = self.key_pair.private_key_pem
        return bundle_keys or None

    def core_goals(self) -> ClawChainCoreGoals:
        return ClawChainCoreGoals(
            evidence_integrity=True,
            evidence_survivability=self.config.uses_remote_evidence,
            evidence_confidentiality=self.config.needs_key_pair,
            accountability=True,
            recovery_orchestration=self.config.uses_protected_recovery,
        )


__all__ = [
    "ClawChainConfig",
    "ClawChainCoreGoals",
    "ClawChainPaths",
    "ClawChainSystem",
    "ProtectedBackupResult",
    "RecoveryValidationOutcome",
]
