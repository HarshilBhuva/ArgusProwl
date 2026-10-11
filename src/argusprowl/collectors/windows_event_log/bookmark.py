"""Atomic, per-channel EventRecordID persistence for one Windows collector."""

import json
import threading
from pathlib import Path


class WindowsEventBookmarkStore:
    """Stores a bounded mapping of configured channels to latest record IDs."""

    def __init__(self, path: Path) -> None:
        self._path, self._lock = path, threading.Lock()

    def load(self, channel: str) -> int | None:
        with self._lock:
            try:
                value = json.loads(self._path.read_text(encoding="utf-8")).get(channel)
                return value if isinstance(value, int) and value >= 0 else None
            except (OSError, ValueError, json.JSONDecodeError):
                return None

    def save(self, channel: str, record_id: int) -> None:
        if not isinstance(record_id, int) or record_id < 0:
            raise ValueError("record_id must be a non-negative integer")
        with self._lock:
            data: dict[str, int] = {}
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    data = {
                        key: value
                        for key, value in raw.items()
                        if isinstance(key, str) and isinstance(value, int) and value >= 0
                    }
            except (OSError, ValueError, json.JSONDecodeError):
                pass
            data[channel] = record_id
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._path.with_name(f".{self._path.name}.tmp")
            temporary.write_text(json.dumps(data), encoding="utf-8")
            temporary.replace(self._path)

    def clear(self, channel: str) -> None:
        with self._lock:
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                return
            if isinstance(data, dict) and channel in data:
                del data[channel]
                temporary = self._path.with_name(f".{self._path.name}.tmp")
                temporary.write_text(json.dumps(data), encoding="utf-8")
                temporary.replace(self._path)
