"""Event stream loading and validation (schema v1).

The tracer emits one JSON object per line; field `v` is the schema
version. This module is strict: a corrupt line (e.g. tracee output
interleaved because `-o` was not used) raises instead of letting a
broken trace look clean.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REQUIRED_FIELDS = ("v", "t", "pid", "ppid", "exe", "kind")
SCHEMA_VERSION = 1


class EventStreamError(ValueError):
    """Raised when the event stream is missing, empty, or corrupt."""


@dataclass(frozen=True)
class Event:
    t: float
    pid: int
    ppid: int
    exe: str
    kind: str
    fields: dict[str, Any] = field(default_factory=dict, compare=False)

    def get(self, key: str, default: Any = None) -> Any:
        if key in ("t", "pid", "ppid", "exe", "kind"):
            return getattr(self, key)
        return self.fields.get(key, default)


def load_events(path: str | Path) -> list[Event]:
    """Load and validate every event. Raises EventStreamError on any fault."""
    path = Path(path)
    if not path.is_file():
        raise EventStreamError(f"event stream not found: {path}")
    events: list[Event] = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise EventStreamError(
                    f"{path}:{lineno}: corrupt event line ({e}); "
                    "if the target writes to stdout, re-run with -o FILE"
                ) from e
            if not isinstance(obj, dict):
                raise EventStreamError(f"{path}:{lineno}: event is not an object")
            missing = [k for k in REQUIRED_FIELDS if k not in obj]
            if missing:
                raise EventStreamError(
                    f"{path}:{lineno}: event missing fields {missing}")
            if obj["v"] != SCHEMA_VERSION:
                raise EventStreamError(
                    f"{path}:{lineno}: unsupported schema v{obj.get('v')!r} "
                    f"(want v{SCHEMA_VERSION})")
            try:
                events.append(Event(
                    t=float(obj["t"]),
                    pid=int(obj["pid"]),
                    ppid=int(obj["ppid"]),
                    exe=str(obj["exe"]),
                    kind=str(obj["kind"]),
                    fields={k: v for k, v in obj.items()
                            if k not in REQUIRED_FIELDS},
                ))
            except (TypeError, ValueError) as e:
                raise EventStreamError(
                    f"{path}:{lineno}: bad field types ({e})") from e
    return events
