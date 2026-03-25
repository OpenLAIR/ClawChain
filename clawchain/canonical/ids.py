from __future__ import annotations

from hashlib import sha256
import json


def stable_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_text(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def new_event_id(*, session_id: str, event_index: int) -> str:
    return f"{session_id}:{event_index}"
