"""Incident domain model reserved for a future correlation phase."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from argusprowl.constants.severity import Severity


class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class Incident:
    """A process-local investigation aggregate; no correlation policy belongs here."""

    title: str
    description: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.OPEN
    incident_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    alert_ids: tuple[UUID, ...] = ()
    tags: tuple[str, ...] = ()
    assigned_analyst: str | None = None
    investigation_notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not self.title.strip():
            raise ValueError("Incident title must not be empty.")
        if self.schema_version < 1:
            raise ValueError("Incident schema_version must be positive.")
