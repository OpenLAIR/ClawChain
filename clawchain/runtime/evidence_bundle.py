from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass
import json
from pathlib import Path
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..canonical.attestations import DelegationCertificate
from ..canonical.commitments import EncryptionManifest, EncryptionScheme
from ..canonical.events import CanonicalEvent
from ..canonical.ids import digest_text, stable_json


@dataclass(frozen=True)
class EncryptedEvidenceBundle:
    bundle_id: str
    bundle_kind: str
    subject_id: str
    path: Path
    manifest: EncryptionManifest
    encrypted_key_b64: str
    nonce_b64: str
    ciphertext_b64: str
    recipient_key_id: str
    key_encryption_algorithm: str = "RSA-OAEP-SHA256"
    payload_algorithm: str = "AES-256-GCM"

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_id": self.bundle_id,
            "bundle_kind": self.bundle_kind,
            "subject_id": self.subject_id,
            "manifest": self.manifest.summary(),
            "encrypted_key_b64": self.encrypted_key_b64,
            "nonce_b64": self.nonce_b64,
            "ciphertext_b64": self.ciphertext_b64,
            "recipient_key_id": self.recipient_key_id,
            "key_encryption_algorithm": self.key_encryption_algorithm,
            "payload_algorithm": self.payload_algorithm,
        }


@dataclass
class EncryptedEvidenceBundleStore:
    root_dir: Path
    recipient_public_key_pem: str

    def __post_init__(self) -> None:
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def encrypt_payload(
        self,
        *,
        bundle_id: str,
        bundle_kind: str,
        subject_id: str,
        relative_path: Path,
        payload: dict[str, object],
        access_policy_digest: str,
    ) -> EncryptedEvidenceBundle:
        bundle_path = self.root_dir / relative_path
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        plaintext = stable_json(payload).encode("utf-8")
        public_key = serialization.load_pem_public_key(self.recipient_public_key_pem.encode("utf-8"))
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
        encrypted_key_b64 = b64encode(encrypted_key).decode("ascii")
        nonce_b64 = b64encode(nonce).decode("ascii")
        ciphertext_b64 = b64encode(ciphertext).decode("ascii")
        manifest = EncryptionManifest(
            manifest_version="v1",
            payload_scheme=EncryptionScheme.AES_256_GCM,
            key_wrap_scheme=EncryptionScheme.RSA_OAEP_SHA256,
            recipient_set_digest=digest_text(self.recipient_public_key_pem),
            access_policy_digest=access_policy_digest,
            ciphertext_digest=digest_text(f"{encrypted_key_b64}:{nonce_b64}:{ciphertext_b64}"),
            key_rotation_epoch=None,
        )
        bundle = EncryptedEvidenceBundle(
            bundle_id=bundle_id,
            bundle_kind=bundle_kind,
            subject_id=subject_id,
            path=bundle_path,
            manifest=manifest,
            encrypted_key_b64=encrypted_key_b64,
            nonce_b64=nonce_b64,
            ciphertext_b64=ciphertext_b64,
            recipient_key_id=digest_text(self.recipient_public_key_pem),
        )
        bundle_path.write_text(json.dumps(bundle.to_dict(), ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        return bundle

    def decrypt_bundle(
        self,
        *,
        bundle_path: Path,
        recipient_private_key_pem: str,
    ) -> dict[str, object]:
        payload = json.loads(bundle_path.read_text(encoding="utf-8"))
        return decrypt_bundle_payload(payload=payload, recipient_private_key_pem=recipient_private_key_pem)


def decrypt_bundle_payload(
    *,
    payload: dict[str, object],
    recipient_private_key_pem: str,
) -> dict[str, object]:
    private_key = serialization.load_pem_private_key(
        recipient_private_key_pem.encode("utf-8"),
        password=None,
    )
    aes_key = private_key.decrypt(
        b64decode(payload["encrypted_key_b64"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plaintext = AESGCM(aes_key).decrypt(
        b64decode(payload["nonce_b64"]),
        b64decode(payload["ciphertext_b64"]),
        None,
    )
    return json.loads(plaintext.decode("utf-8"))


@dataclass
class EventBatchBundleStore:
    root_dir: Path
    recipient_public_key_pem: str

    def __post_init__(self) -> None:
        self._store = EncryptedEvidenceBundleStore(
            root_dir=self.root_dir,
            recipient_public_key_pem=self.recipient_public_key_pem,
        )

    def encrypt_batch(
        self,
        *,
        session_id: str,
        batch_seq_no: int,
        events: list[CanonicalEvent],
        event_root: str,
    ) -> EncryptedEvidenceBundle:
        return self._store.encrypt_payload(
            bundle_id=f"{session_id}:batch:{batch_seq_no}",
            bundle_kind="event_batch",
            subject_id=session_id,
            relative_path=Path(session_id) / f"batch-{batch_seq_no:06d}.bundle.json",
            payload={
                "bundle_id": f"{session_id}:batch:{batch_seq_no}",
                "session_id": session_id,
                "batch_seq_no": batch_seq_no,
                "event_root": event_root,
                "events": [event.to_dict() for event in events],
            },
            access_policy_digest=digest_text("event-batch-confidential-audit"),
        )

    def decrypt_bundle(
        self,
        *,
        bundle_path: Path,
        recipient_private_key_pem: str,
    ) -> dict[str, object]:
        return self._store.decrypt_bundle(
            bundle_path=bundle_path,
            recipient_private_key_pem=recipient_private_key_pem,
        )


@dataclass
class DelegationBundleStore:
    root_dir: Path
    recipient_public_key_pem: str

    def __post_init__(self) -> None:
        self._store = EncryptedEvidenceBundleStore(
            root_dir=self.root_dir,
            recipient_public_key_pem=self.recipient_public_key_pem,
        )

    def encrypt_certificate(self, certificate: DelegationCertificate) -> EncryptedEvidenceBundle:
        return self._store.encrypt_payload(
            bundle_id=f"delegation:{certificate.cert_id}",
            bundle_kind="delegation",
            subject_id=certificate.child_session_id,
            relative_path=Path(certificate.child_session_id) / f"delegation-{certificate.issued_ts}.bundle.json",
            payload={
                "cert_id": certificate.cert_id,
                "parent_session_id": certificate.parent_session_id,
                "child_session_id": certificate.child_session_id,
                "parent_agent_id": certificate.parent_agent_id,
                "child_agent_id": certificate.child_agent_id,
                "run_id": certificate.run_id,
                "issued_ts": certificate.issued_ts,
                "scope": {
                    "allowed_tools": list(certificate.scope.allowed_tools),
                    "denied_tools": list(certificate.scope.denied_tools),
                    "sandbox_mode": certificate.scope.sandbox_mode,
                    "sub_delegation": certificate.scope.sub_delegation,
                    "allowed_agents": list(certificate.scope.allowed_agents),
                    "max_depth": certificate.scope.max_depth,
                    "expiry_ts": certificate.scope.expiry_ts,
                },
                "signer": certificate.signer,
                "signature": certificate.signature,
            },
            access_policy_digest=digest_text("delegation-confidential-audit"),
        )

    def decrypt_bundle(
        self,
        *,
        bundle_path: Path,
        recipient_private_key_pem: str,
    ) -> dict[str, object]:
        return self._store.decrypt_bundle(
            bundle_path=bundle_path,
            recipient_private_key_pem=recipient_private_key_pem,
        )


@dataclass
class BackupLocatorBundleStore:
    root_dir: Path
    recipient_public_key_pem: str

    def __post_init__(self) -> None:
        self._store = EncryptedEvidenceBundleStore(
            root_dir=self.root_dir,
            recipient_public_key_pem=self.recipient_public_key_pem,
        )

    def encrypt_backup_record(
        self,
        *,
        backup_id: str,
        created_ts_ms: int,
        source_path_hash: str,
        source_name_hint: str,
        snapshot_kind: str,
        snapshot_digest: str,
        locator_payload: dict[str, object],
    ) -> EncryptedEvidenceBundle:
        return self._store.encrypt_payload(
            bundle_id=f"backup:{backup_id}",
            bundle_kind="backup_locator",
            subject_id=backup_id,
            relative_path=Path(backup_id) / f"backup-{created_ts_ms}.bundle.json",
            payload={
                "backup_id": backup_id,
                "created_ts_ms": created_ts_ms,
                "source_path_hash": source_path_hash,
                "source_name_hint": source_name_hint,
                "snapshot_kind": snapshot_kind,
                "snapshot_digest": snapshot_digest,
                "locator": locator_payload,
            },
            access_policy_digest=digest_text("protected-backup-recovery"),
        )

    def decrypt_bundle(
        self,
        *,
        bundle_path: Path,
        recipient_private_key_pem: str,
    ) -> dict[str, object]:
        return self._store.decrypt_bundle(
            bundle_path=bundle_path,
            recipient_private_key_pem=recipient_private_key_pem,
        )


__all__ = [
    "BackupLocatorBundleStore",
    "DelegationBundleStore",
    "EncryptedEvidenceBundle",
    "EncryptedEvidenceBundleStore",
    "EventBatchBundleStore",
    "decrypt_bundle_payload",
]
