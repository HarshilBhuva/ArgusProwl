"""Atomic persisted record-ID checkpoint for Sysmon collection."""

import contextlib
import json
import threading
from pathlib import Path


class SysmonBookmarkStore:
    """Stores only the latest record ID; writes are atomic and batched by caller."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def load(self) -> int | None:
        with self._lock:
            try:
                value = json.loads(self._path.read_text(encoding="utf-8")).get("record_id")
                return value if isinstance(value, int) and value >= 0 else None
            except (OSError, ValueError, json.JSONDecodeError):
                return None

    def save(self, record_id: int) -> None:
        if not isinstance(record_id, int) or record_id < 0:
            raise ValueError("record_id must be a non-negative integer")
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._path.with_name(f".{self._path.name}.tmp")
            temporary.write_text(json.dumps({"record_id": record_id}), encoding="utf-8")
            temporary.replace(self._path)

    def clear(self) -> None:
        with self._lock, contextlib.suppress(FileNotFoundError):
            self._path.unlink()
