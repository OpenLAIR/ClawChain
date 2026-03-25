from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
from pathlib import Path
import os
import shutil
import time
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..canonical.ids import digest_text, stable_json
from ..canonical.commitments import (
    BackupLocatorCommitment,
    CommitmentEnvelope,
    CommitmentType,
    EncryptionManifest,
    EncryptionScheme,
)
from .anchor import AnchorBackend, LocalAnchorBackend
from .anchor_service_utils import build_anchor_metadata, persist_and_mirror_anchor_result
from .batching import AnchorReceipt
from .evidence_bundle import BackupLocatorBundleStore
from .sidecar import ProvenanceSidecar
from .store import JsonAnchorSubmissionStore, JsonReceiptStore


@dataclass(frozen=True)
class AsymmetricKeyPair:
    public_key_pem: str
    private_key_pem: str
    algorithm: str = "RSA-2048-OAEP-SHA256"


@dataclass(frozen=True)
class EncryptedBackupLocator:
    algorithm: str
    recipient_key_id: str
    encrypted_key_b64: str
    nonce_b64: str
    ciphertext_b64: str
    key_encryption_algorithm: str
    ciphertext_digest: str


@dataclass(frozen=True)
class ProtectedBackupRecord:
    backup_id: str
    created_ts_ms: int
    source_path_hash: str
    source_name_hint: str
    snapshot_kind: str
    snapshot_digest: str
    locator: EncryptedBackupLocator

    def encryption_manifest(self) -> EncryptionManifest:
        return EncryptionManifest(
            manifest_version="v1",
            payload_scheme=EncryptionScheme.AES_256_GCM,
            key_wrap_scheme=EncryptionScheme.RSA_OAEP_SHA256,
            recipient_set_digest=self.locator.recipient_key_id,
            access_policy_digest=digest_text("protected-backup-recovery"),
            ciphertext_digest=self.locator.ciphertext_digest,
            key_rotation_epoch=None,
        )

    def locator_commitment(self) -> BackupLocatorCommitment:
        return BackupLocatorCommitment(
            backup_id=self.backup_id,
            snapshot_digest=self.snapshot_digest,
            locator_commitment=self.anchor_commitment(),
            created_ts_ms=self.created_ts_ms,
            recovery_policy_digest=digest_text("protected-backup-recovery"),
            encryption_manifest=self.encryption_manifest(),
        )

    def to_anchor_payload(self) -> dict[str, object]:
        return {
            "backup_id": self.backup_id,
            "created_ts_ms": self.created_ts_ms,
            "source_path_hash": self.source_path_hash,
            "source_name_hint": self.source_name_hint,
            "snapshot_kind": self.snapshot_kind,
            "snapshot_digest": self.snapshot_digest,
            "locator": asdict(self.locator),
        }

    def anchor_commitment(self) -> str:
        return digest_text(stable_json(self.to_anchor_payload()))


@dataclass
class BackupCatalogStore:
    path: Path

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def append(self, record: ProtectedBackupRecord) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_anchor_payload(), ensure_ascii=True) + "\n")

    def read_all(self) -> list[dict]:
        rows: list[dict] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                rows.append(json.loads(line))
        return rows


@dataclass
class ProtectedBackupRepository:
    vault_root: Path
    catalog_store: BackupCatalogStore

    def __post_init__(self) -> None:
        self.vault_root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.vault_root, 0o700)
        except Exception:  # noqa: BLE001
            pass

    def create_backup(self, *, source_path: Path, recipient_public_key_pem: str) -> ProtectedBackupRecord:
        if not source_path.exists():
            raise FileNotFoundError(source_path)
        backup_id = f"backup-{uuid4().hex}"
        snapshot_root = self.vault_root / backup_id
        snapshot_root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(snapshot_root, 0o700)
        except Exception:  # noqa: BLE001
            pass
        payload_path = snapshot_root / source_path.name
        snapshot_kind = "directory" if source_path.is_dir() else "file"
        if source_path.is_dir():
            shutil.copytree(source_path, payload_path)
        else:
            shutil.copy2(source_path, payload_path)
        _chmod_tree_secure(payload_path)

        locator_payload = {
            "backup_id": backup_id,
            "snapshot_path": str(payload_path),
            "snapshot_kind": snapshot_kind,
        }
        locator = seal_backup_locator(locator_payload, recipient_public_key_pem)
        record = ProtectedBackupRecord(
            backup_id=backup_id,
            created_ts_ms=int(time.time() * 1000),
            source_path_hash=digest_text(str(source_path.resolve())),
            source_name_hint=source_path.name,
            snapshot_kind=snapshot_kind,
            snapshot_digest=_digest_path(payload_path),
            locator=locator,
        )
        self.catalog_store.append(record)
        return record

    def restore_backup(
        self,
        *,
        record: ProtectedBackupRecord,
        recipient_private_key_pem: str,
        destination_path: Path,
    ) -> Path:
        locator = unseal_backup_locator(record.locator, recipient_private_key_pem)
        snapshot_path = Path(str(locator["snapshot_path"]))
        snapshot_kind = str(locator["snapshot_kind"])
        if not snapshot_path.exists():
            raise FileNotFoundError(snapshot_path)
        if snapshot_kind == "directory":
            if destination_path.exists():
                shutil.rmtree(destination_path)
            shutil.copytree(snapshot_path, destination_path)
        else:
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(snapshot_path, destination_path)
        return destination_path


@dataclass
class ProtectedBackupAnchorService:
    anchor_backend: AnchorBackend = field(default_factory=LocalAnchorBackend)
    receipt_store: JsonReceiptStore | None = None
    submission_store: JsonAnchorSubmissionStore | None = None
    bundle_store: BackupLocatorBundleStore | None = None
    sidecar: ProvenanceSidecar | None = None
    session_id: str = "protected-backup"
    seq_no: int = 0

    def anchor_record(self, record: ProtectedBackupRecord) -> AnchorReceipt:
        bundle_ref: str | None = None
        encryption_manifest = record.encryption_manifest()
        if self.bundle_store is not None:
            bundle = self.bundle_store.encrypt_backup_record(
                backup_id=record.backup_id,
                created_ts_ms=record.created_ts_ms,
                source_path_hash=record.source_path_hash,
                source_name_hint=record.source_name_hint,
                snapshot_kind=record.snapshot_kind,
                snapshot_digest=record.snapshot_digest,
                locator_payload=asdict(record.locator),
            )
            encryption_manifest = bundle.manifest
            bundle_ref = str(bundle.path.relative_to(self.bundle_store.root_dir))
        locator_commitment = record.locator_commitment()
        locator_commitment = BackupLocatorCommitment(
            backup_id=locator_commitment.backup_id,
            snapshot_digest=locator_commitment.snapshot_digest,
            locator_commitment=locator_commitment.locator_commitment,
            created_ts_ms=locator_commitment.created_ts_ms,
            recovery_policy_digest=locator_commitment.recovery_policy_digest,
            encryption_manifest=encryption_manifest,
        )
        envelope = locator_commitment.to_envelope(sequence_no=self.seq_no)
        receipt = AnchorReceipt(
            session_id=self.session_id,
            batch_seq_no=self.seq_no,
            merkle_root=envelope.commitment,
            event_ids=(record.backup_id,),
            commitment_type=CommitmentType.BACKUP_LOCATOR.value,
            subject_id=record.backup_id,
            metadata=build_anchor_metadata(
                envelope=envelope,
                base_metadata={
                    "snapshot_digest": record.snapshot_digest,
                    "backup_created_ts_ms": record.created_ts_ms,
                    "recovery_policy_digest": locator_commitment.recovery_policy_digest,
                },
                manifest=encryption_manifest,
                bundle_ref=bundle_ref,
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
            bundle_ref=bundle_ref,
            bundle_root=(self.bundle_store.root_dir if self.bundle_store is not None else None),
        )
        return anchored


def generate_rsa_key_pair() -> AsymmetricKeyPair:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return AsymmetricKeyPair(public_key_pem=public_pem, private_key_pem=private_pem)


def write_rsa_key_pair(
    key_pair: AsymmetricKeyPair,
    *,
    public_key_path: Path,
    private_key_path: Path,
) -> AsymmetricKeyPair:
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.write_text(key_pair.public_key_pem, encoding="utf-8")
    private_key_path.write_text(key_pair.private_key_pem, encoding="utf-8")
    os.chmod(public_key_path, 0o600)
    os.chmod(private_key_path, 0o600)
    return key_pair


def load_rsa_key_pair(
    *,
    public_key_path: Path,
    private_key_path: Path,
) -> AsymmetricKeyPair:
    return AsymmetricKeyPair(
        public_key_pem=public_key_path.read_text(encoding="utf-8"),
        private_key_pem=private_key_path.read_text(encoding="utf-8"),
    )


def seal_backup_locator(locator_payload: dict[str, object], recipient_public_key_pem: str) -> EncryptedBackupLocator:
    public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode("utf-8"))
    plaintext = stable_json(locator_payload).encode("utf-8")
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    ciphertext_b64 = b64encode(ciphertext).decode("ascii")
    encrypted_key_b64 = b64encode(encrypted_key).decode("ascii")
    nonce_b64 = b64encode(nonce).decode("ascii")
    return EncryptedBackupLocator(
        algorithm="AES-256-GCM",
        recipient_key_id=digest_text(recipient_public_key_pem),
        encrypted_key_b64=encrypted_key_b64,
        nonce_b64=nonce_b64,
        ciphertext_b64=ciphertext_b64,
        key_encryption_algorithm="RSA-OAEP-SHA256",
        ciphertext_digest=digest_text(f"{encrypted_key_b64}:{nonce_b64}:{ciphertext_b64}"),
    )


def unseal_backup_locator(locator: EncryptedBackupLocator, recipient_private_key_pem: str) -> dict[str, object]:
    private_key = serialization.load_pem_private_key(
        recipient_private_key_pem.encode("utf-8"),
        password=None,
    )
    aes_key = private_key.decrypt(
        b64decode(locator.encrypted_key_b64.encode("ascii")),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plaintext = AESGCM(aes_key).decrypt(
        b64decode(locator.nonce_b64.encode("ascii")),
        b64decode(locator.ciphertext_b64.encode("ascii")),
        None,
    )
    return dict(json.loads(plaintext.decode("utf-8")))


def protected_backup_record_from_dict(row: dict[str, object]) -> ProtectedBackupRecord:
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
    return ProtectedBackupRecord(
        backup_id=str(row["backup_id"]),
        created_ts_ms=int(row["created_ts_ms"]),
        source_path_hash=str(row["source_path_hash"]),
        source_name_hint=str(row["source_name_hint"]),
        snapshot_kind=str(row["snapshot_kind"]),
        snapshot_digest=str(row["snapshot_digest"]),
        locator=locator,
    )


def _chmod_tree_secure(path: Path) -> None:
    try:
        if path.is_dir():
            os.chmod(path, 0o700)
            for child in path.rglob('*'):
                try:
                    os.chmod(child, 0o700 if child.is_dir() else 0o600)
                except Exception:  # noqa: BLE001
                    continue
        elif path.exists():
            os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001
        return


def _digest_path(path: Path) -> str:
    if path.is_file():
        return sha256(path.read_bytes()).hexdigest()
    entries: list[str] = []
    for child in sorted(path.rglob("*")):
        if child.is_dir():
            continue
        rel = child.relative_to(path)
        entries.append(f"{rel.as_posix()}:{sha256(child.read_bytes()).hexdigest()}")
    return digest_text("\n".join(entries))
