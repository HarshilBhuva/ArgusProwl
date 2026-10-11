"""Timeline item data model for investigation timeline.

Represents a single entry in the entity investigation timeline.
Each item has a clear source type and deterministic identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class TimelineItemType(StrEnum):
    """Type of a timeline item, corresponding to its evidence source."""

    ALERT = "ALERT"
    INCIDENT = "INCIDENT"
    ANNOTATION = "ANNOTATION"
    BEHAVIOR = "BEHAVIOR"


@dataclass(frozen=True, slots=True)
class TimelineItem:
    """Immutable read-only timeline entry.

    Attributes:
        timeline_item_id: Stable identifier derived from source identity.
            For alerts: the alert_id. For annotations: the annotation_id.
            For incidents: the incident_id. For behavior: a computed key.
        timestamp: Timezone-aware UTC timestamp from the source evidence.
        item_type: The source type (ALERT / INCIDENT / ANNOTATION / BEHAVIOR).
        title: Short human-readable summary.
        summary: Brief description or commentary.
        entity_type: The investigated entity type.
        entity_id: The investigated entity identifier.
        source_id: The originating source ID (alert_id, annotation_id, etc.).
        severity_or_priority: Severity for alerts/incidents, None for others.
        metadata: Bounded key-value context from the source (max 10 keys, 256 chars each).
    """

    timeline_item_id: str
    timestamp: datetime
    item_type: TimelineItemType
    title: str
    summary: str
    entity_type: str
    entity_id: str
    source_id: str | None = None
    severity_or_priority: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON response."""
        return {
            "timeline_item_id": self.timeline_item_id,
            "timestamp": self.timestamp.isoformat(),
            "item_type": self.item_type.value,
            "title": self.title,
            "summary": self.summary,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "source_id": self.source_id,
            "severity_or_priority": self.severity_or_priority,
            "metadata": dict(self.metadata),
        }
