"""Raw records and acquisition contracts for standard Windows Event Logs."""

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


class WindowsEventSourceError(RuntimeError):
    """A native Windows Event Log acquisition operation failed."""


class StaleWindowsBookmarkError(WindowsEventSourceError):
    """A channel's retained log can no longer satisfy its persisted bookmark."""


@dataclass(frozen=True, slots=True)
class WindowsEventRawRecord:
    xml: str
    channel: str
    record_id: int | None = None
    collector: str = "windows_event_log_collector"
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)


class WindowsEventSource(ABC):
    """Platform boundary for real Windows events and deterministic replay."""

    @abstractmethod
    def open(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    @abstractmethod
    def read(
        self, channel: str, after_record_id: int | None, limit: int
    ) -> Iterable[WindowsEventRawRecord]: ...


class ReplayWindowsEventSource(WindowsEventSource):
    """In-memory exported-XML source for Linux unit tests and development."""

    def __init__(self, records: Iterable[WindowsEventRawRecord]) -> None:
        self._records = tuple(records)
        self._open = False

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def read(
        self, channel: str, after_record_id: int | None, limit: int
    ) -> Iterable[WindowsEventRawRecord]:
        if not self._open:
            raise WindowsEventSourceError("replay source is not open")
        return tuple(
            record
            for record in self._records
            if record.channel == channel
            and (
                record.record_id is None
                or after_record_id is None
                or record.record_id > after_record_id
            )
        )[:limit]
