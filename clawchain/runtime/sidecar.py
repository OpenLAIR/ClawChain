from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from ..canonical.events import CanonicalEvent
from .anchor import AnchorSubmission
from .batching import AnchorReceipt
from .remote import RemoteEvidenceSink
from .sidecar_service import SidecarSecurityProfile


@dataclass
class ProvenanceSidecar:
    sink: RemoteEvidenceSink

    def mirror_event(self, event: CanonicalEvent) -> None:
        self.sink.append_event(event)

    def mirror_receipts(self, receipts: list[AnchorReceipt]) -> None:
        if receipts:
            self.sink.append_receipts(receipts)

    def mirror_submissions(self, submissions: list[AnchorSubmission]) -> None:
        if submissions:
            self.sink.append_submissions(submissions)

    def mirror_bundle(self, *, bundle_ref: str, bundle_path: Path) -> None:
        self.sink.append_bundle(
            bundle_ref,
            json.loads(bundle_path.read_text(encoding="utf-8")),
        )

    def mirror_security_profile(self, profile: SidecarSecurityProfile) -> None:
        self.sink.write_metadata({"sidecar_security_profile": profile.to_dict()})
