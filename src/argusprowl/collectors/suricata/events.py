"""Source-neutral raw records and acquisition contracts for Suricata EVE JSON."""

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


class SuricataSourceError(RuntimeError):
    """The configured Suricata EVE source could not be read."""


@dataclass(frozen=True, slots=True)
class SuricataRawRecord:
    """One acquired EVE JSON line plus non-sensitive provenance."""

    line: str
    offset: int | None = None
    inode: int | None = None
    source: str = "suricata"
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)


class SuricataEventSource(ABC):
    """Acquisition boundary for Suricata EVE JSON records."""

    @abstractmethod
    def open(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    @abstractmethod
    def read(
        self, checkpoint: dict[str, int] | None, limit: int
    ) -> Iterable[SuricataRawRecord]: ...


class ReplaySuricataEventSource(SuricataEventSource):
    """Deterministic in-memory source for fixture replay and CI."""

    def __init__(self, records: Iterable[SuricataRawRecord]) -> None:
        self._records, self._open = tuple(records), False

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def read(self, checkpoint: dict[str, int] | None, limit: int) -> Iterable[SuricataRawRecord]:
        if not self._open:
            raise SuricataSourceError("replay source is not open")
        offset = checkpoint.get("offset", -1) if checkpoint else -1
        return tuple(
            record for record in self._records if record.offset is None or record.offset > offset
        )[:limit]
