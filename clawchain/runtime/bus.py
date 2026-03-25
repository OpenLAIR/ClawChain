from __future__ import annotations

from dataclasses import dataclass, field

from ..canonical.events import CanonicalEvent
from .store import JsonlEventStore


@dataclass
class RuntimeEventBus:
    store: JsonlEventStore
    in_memory: list[CanonicalEvent] = field(default_factory=list)

    def publish(self, event: CanonicalEvent) -> None:
        self.in_memory.append(event)
        self.store.append(event)

    def recent_events(self, *, session_id: str | None = None) -> list[CanonicalEvent]:
        if session_id is None:
            return self.in_memory[:]
        return [event for event in self.in_memory if event.session_id == session_id]
