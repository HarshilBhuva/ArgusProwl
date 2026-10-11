"""Event data model.

Represents a log or telemetry event ingested into the platform.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4


@dataclass(slots=True)
class Event:
    """A single log or telemetry event.

    Attributes:
        event_id: Unique identifier.
        source: The originating log source (e.g. ``"syslog"``, ``"windows_evtx"``).
        event_type: Classification label for the event kind.
        timestamp: UTC time when the event occurred.
        raw_data: The original, unparsed event payload.
        parsed_data: Structured fields extracted by a parser.
        tags: Classification tags.
    """

    source: str
    event_type: str
    raw_data: str
    event_id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    parsed_data: dict[str, object] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate required fields."""
        if not self.source.strip():
            raise ValueError("Event source must not be empty.")
        if not self.event_type.strip():
            raise ValueError("Event event_type must not be empty.")
