"""Source-neutral raw records and acquisition contracts for Sysmon."""

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


class SysmonSourceError(RuntimeError):
    """Windows Event Log acquisition failed."""


class StaleBookmarkError(SysmonSourceError):
    """The persisted checkpoint cannot be used against the current log."""


@dataclass(frozen=True, slots=True)
class SysmonRawRecord:
    """One acquired Sysmon XML event plus non-sensitive provenance."""

    xml: str
    record_id: int | None = None
    collector: str = "sysmon_collector"
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    bookmark: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class SysmonEventSource(ABC):
    """Acquisition boundary; production sources must return real exported XML."""

    @abstractmethod
    def open(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    @abstractmethod
    def read(self, after_record_id: int | None, limit: int) -> Iterable[SysmonRawRecord]: ...


class ReplaySysmonEventSource(SysmonEventSource):
    """Deterministic XML replay source for Linux development and tests."""

    def __init__(self, records: Iterable[SysmonRawRecord]) -> None:
        self._records = tuple(records)
        self._open = False

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def read(self, after_record_id: int | None, limit: int) -> Iterable[SysmonRawRecord]:
        if not self._open:
            raise SysmonSourceError("replay source is not open")
        return tuple(
            record
            for record in self._records
            if record.record_id is None
            or after_record_id is None
            or record.record_id > after_record_id
        )[:limit]
