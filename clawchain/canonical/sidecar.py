from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SidecarSecurityProfileRecord:
    profile_version: str
    service_version: str
    transport_mode: str
    auth_enabled: bool
    read_write_split: bool
    replay_protection_enabled: bool
    credential_mode: str
    max_clock_skew_ms: int
    replay_window_size: int

    def to_dict(self) -> dict[str, object]:
        return {
            "profile_version": self.profile_version,
            "service_version": self.service_version,
            "transport_mode": self.transport_mode,
            "auth_enabled": self.auth_enabled,
            "read_write_split": self.read_write_split,
            "replay_protection_enabled": self.replay_protection_enabled,
            "credential_mode": self.credential_mode,
            "max_clock_skew_ms": self.max_clock_skew_ms,
            "replay_window_size": self.replay_window_size,
        }


@dataclass(frozen=True)
class SidecarRemoteMetadataRecord:
    metadata_version: str
    service_instance_id: str
    started_at_ms: int
    security_profile: SidecarSecurityProfileRecord

    def to_dict(self) -> dict[str, object]:
        return {
            "sidecar_metadata_version": self.metadata_version,
            "sidecar_service_instance_id": self.service_instance_id,
            "sidecar_started_at_ms": self.started_at_ms,
            "sidecar_security_profile": self.security_profile.to_dict(),
        }


__all__ = ["SidecarRemoteMetadataRecord", "SidecarSecurityProfileRecord"]
