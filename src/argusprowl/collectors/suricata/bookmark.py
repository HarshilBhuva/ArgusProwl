"""Atomic inode-and-offset persistence for Suricata EVE JSON file tailing."""

import json
import threading
from contextlib import suppress
from pathlib import Path


class SuricataBookmarkStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def load(self) -> dict[str, int] | None:
        with self._lock:
            try:
                value = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                return None
            if isinstance(value, dict) and all(
                isinstance(value.get(key), int) and value[key] >= 0 for key in ("inode", "offset")
            ):
                return {"inode": value["inode"], "offset": value["offset"]}
            return None

    def save(self, inode: int, offset: int) -> None:
        if not all(isinstance(value, int) and value >= 0 for value in (inode, offset)):
            raise ValueError("bookmark inode and offset must be non-negative integers")
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._path.with_name(f".{self._path.name}.tmp")
            temporary.write_text(json.dumps({"inode": inode, "offset": offset}), encoding="utf-8")
            temporary.replace(self._path)

    def clear(self) -> None:
        with self._lock, suppress(FileNotFoundError):
            self._path.unlink()
