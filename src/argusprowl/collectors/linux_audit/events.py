"""Linux audit raw records, source contracts, and bounded record assembly."""

from abc import ABC, abstractmethod
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


class LinuxAuditSourceError(RuntimeError):
    """The configured Linux audit source could not be read."""


@dataclass(frozen=True, slots=True)
class LinuxAuditRawRecord:
    line: str
    offset: int | None = None
    inode: int | None = None
    source: str = "linux_audit"
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)


class LinuxAuditSource(ABC):
    @abstractmethod
    def open(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    @abstractmethod
    def read(
        self, checkpoint: dict[str, int] | None, limit: int
    ) -> Iterable[LinuxAuditRawRecord]: ...


class ReplayLinuxAuditSource(LinuxAuditSource):
    """Deterministic in-memory source for fixture replay and CI."""

    def __init__(self, records: Iterable[LinuxAuditRawRecord]) -> None:
        self._records, self._open = tuple(records), False

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def read(self, checkpoint: dict[str, int] | None, limit: int) -> Iterable[LinuxAuditRawRecord]:
        if not self._open:
            raise LinuxAuditSourceError("replay source is not open")
        offset = checkpoint.get("offset", -1) if checkpoint else -1
        return tuple(
            record for record in self._records if record.offset is None or record.offset > offset
        )[:limit]


class AuditRecordAssembler:
    """Bounded transaction assembly keyed by audit message serial."""

    _ASSEMBLED_TYPES = frozenset({"SYSCALL", "EXECVE", "PATH", "CWD", "PROCTITLE"})

    def __init__(self, timeout: float, max_groups: int) -> None:
        self.timeout, self.max_groups = timeout, max_groups
        self._groups: OrderedDict[str, tuple[float, list[LinuxAuditRawRecord]]] = OrderedDict()

    @property
    def pending_count(self) -> int:
        return len(self._groups)

    def add(
        self, serial: str | None, record_type: str | None, record: LinuxAuditRawRecord, now: float
    ) -> list[tuple[LinuxAuditRawRecord, ...]]:
        if not serial or record_type not in self._ASSEMBLED_TYPES:
            return [(record,)]
        flushed: list[tuple[LinuxAuditRawRecord, ...]] = []
        if serial not in self._groups and len(self._groups) >= self.max_groups:
            _, (_, records) = self._groups.popitem(last=False)
            flushed.append(tuple(records))
        created, records = self._groups.get(serial, (now, []))
        records.append(record)
        self._groups[serial] = (created, records)
        return flushed

    def expire(self, now: float) -> list[tuple[LinuxAuditRawRecord, ...]]:
        flushed: list[tuple[LinuxAuditRawRecord, ...]] = []
        while self._groups:
            serial, (created, records) = next(iter(self._groups.items()))
            if now - created < self.timeout:
                break
            self._groups.pop(serial)
            flushed.append(tuple(records))
        return flushed

    def flush(self) -> list[tuple[LinuxAuditRawRecord, ...]]:
        groups = [tuple(records) for _, records in self._groups.values()]
        self._groups.clear()
        return groups
