"""Zeek Collector Offset Store."""

import json
import threading
from contextlib import suppress
from pathlib import Path


class ZeekOffsetStore:
    """Stores and retrieves file read offsets."""

    def __init__(self, offset_file: Path) -> None:
        self._offset_file = offset_file
        self._lock = threading.Lock()

    def get_offset(self, file_inode: int) -> int:
        """Get the last saved offset for a given file inode."""
        with self._lock:
            if not self._offset_file.exists():
                return 0
            try:
                data = json.loads(self._offset_file.read_text(encoding="utf-8"))
                offset = data.get(str(file_inode), 0)
                return offset if isinstance(offset, int) and offset >= 0 else 0
            except Exception:
                return 0

    def save_offset(self, file_inode: int, offset: int) -> None:
        """Save the current offset for a given file inode."""
        with self._lock:
            data = {}
            if self._offset_file.exists():
                with suppress(Exception):
                    data = json.loads(self._offset_file.read_text(encoding="utf-8"))

            data[str(file_inode)] = offset

            self._offset_file.parent.mkdir(parents=True, exist_ok=True)
            # Write atomically if needed, or simply overwrite
            temp_file = self._offset_file.with_name(f".{self._offset_file.name}.tmp")
            temp_file.write_text(json.dumps(data), encoding="utf-8")
            temp_file.replace(self._offset_file)
