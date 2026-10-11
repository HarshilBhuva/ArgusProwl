"""File adapter for auditd's configured audit.log output."""

from collections.abc import Iterable
from pathlib import Path

from argusprowl.collectors.linux_audit.events import (
    LinuxAuditRawRecord,
    LinuxAuditSource,
    LinuxAuditSourceError,
)


class AuditLogFileSource(LinuxAuditSource):
    """Incrementally reads a configured auditd log without invoking a shell."""

    def __init__(self, path: Path) -> None:
        self._path, self._open, self.rotations = path, False, 0

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def read(self, checkpoint: dict[str, int] | None, limit: int) -> Iterable[LinuxAuditRawRecord]:
        if not self._open:
            raise LinuxAuditSourceError("audit log source is not open")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise LinuxAuditSourceError("audit log limit is invalid")
        try:
            stat = self._path.stat()
            inode, offset = stat.st_ino, 0
            if checkpoint and checkpoint.get("inode") == inode:
                offset = checkpoint.get("offset", 0)
                if offset > stat.st_size:
                    offset = 0
            elif checkpoint:
                self.rotations += 1
            records: list[LinuxAuditRawRecord] = []
            with self._path.open("rb") as stream:
                stream.seek(offset)
                while len(records) < limit:
                    start = stream.tell()
                    line = stream.readline()
                    if not line:
                        break
                    if not line.endswith(b"\n"):
                        break
                    records.append(
                        LinuxAuditRawRecord(
                            line.decode("utf-8", errors="replace").rstrip("\n"),
                            stream.tell(),
                            inode,
                            metadata={"path": str(self._path), "line_offset": start},
                        )
                    )
            return tuple(records)
        except OSError as exc:
            raise LinuxAuditSourceError("audit log source is unavailable") from exc
