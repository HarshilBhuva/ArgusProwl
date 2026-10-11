"""File adapter for Suricata EVE JSON output log."""

from collections.abc import Iterable
from pathlib import Path

from argusprowl.collectors.suricata.events import (
    SuricataEventSource,
    SuricataRawRecord,
    SuricataSourceError,
)


class EveFileSource(SuricataEventSource):
    """Incrementally reads a configured Suricata eve.json log."""

    def __init__(self, path: Path, max_record_size: int = 10 * 1024 * 1024) -> None:
        self._path = path
        self._max_record_size = max_record_size
        self._open = False
        self.rotations = 0

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def read(self, checkpoint: dict[str, int] | None, limit: int) -> Iterable[SuricataRawRecord]:
        if not self._open:
            raise SuricataSourceError("Suricata EVE log source is not open")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise SuricataSourceError("Suricata EVE log limit is invalid")
        try:
            if not self._path.exists():
                return ()

            stat = self._path.stat()
            inode, offset = stat.st_ino, 0
            if checkpoint and checkpoint.get("inode") == inode:
                offset = checkpoint.get("offset", 0)
                if offset > stat.st_size:
                    offset = 0
            elif checkpoint:
                self.rotations += 1

            records: list[SuricataRawRecord] = []
            with self._path.open("rb") as stream:
                stream.seek(offset)
                while len(records) < limit:
                    start = stream.tell()
                    line = stream.readline()
                    if not line:
                        break
                    if not line.endswith(b"\n"):
                        # Incomplete/partial line — rewind to start of line and wait for completion
                        stream.seek(start)
                        break

                    line_str = line.decode("utf-8", errors="replace").rstrip("\r\n")
                    end_offset = stream.tell()

                    is_oversized = len(line) > self._max_record_size
                    records.append(
                        SuricataRawRecord(
                            line=line_str,
                            offset=end_offset,
                            inode=inode,
                            metadata={
                                "path": str(self._path),
                                "line_offset": start,
                                "oversized": is_oversized,
                                "raw_length": len(line),
                            },
                        )
                    )
            return tuple(records)
        except OSError as exc:
            raise SuricataSourceError("Suricata EVE log source is unavailable") from exc
