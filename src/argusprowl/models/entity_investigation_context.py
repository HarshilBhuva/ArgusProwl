"""Entity investigation context data model.

Bounded, read-only evidence aggregation for analyst investigation queries.
This model provides a single, stable snapshot of available evidence for one entity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argusprowl.attck.models import AttckTechniqueSummary
    from argusprowl.models.alert import Alert
    from argusprowl.models.incident import Incident


# Hard output bounds
_MAX_ALERTS: int = 50
_MAX_ANNOTATIONS: int = 20


class SourceStatus(StrEnum):
    """Per-source availability status for investigation context.

    Each evidence source independently reports its availability state.
    This distinguishes "no evidence" from "evidence source unavailable",
    which are materially different in security investigation.

    Semantics:
        AVAILABLE: Source was queried and responded (data may still be empty).
        DEGRADED: Source responded but evidence may be incomplete or
                  durability/evidence integrity is impaired.
        UNAVAILABLE: Source could not be reached or returned a recoverable error.
        UNSUPPORTED: Source was not queried because the entity type is unsupported.

    Critical invariant:
        no query performed != query performed successfully and found nothing.
    """

    #: Source returned data (possibly empty — use count fields to distinguish)
    AVAILABLE = "AVAILABLE"
    #: Source responded but evidence may be incomplete or integrity is impaired
    DEGRADED = "DEGRADED"
    #: Source could not be reached or returned a recoverable error
    UNAVAILABLE = "UNAVAILABLE"
    #: Source was not queried because entity type is not supported
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class EntityInvestigationContext:
    """Bounded evidence aggregation for one entity.

    This is a read-only snapshot that aggregates evidence from multiple
    services without modifying any source state. It provides analysts
    with a single bounded view of all available evidence for triage.

    Attributes:
        entity_type: Type of the entity (e.g., 'host', 'user').
        entity_id: Unique identifier of the entity.
        annotation_key: Annotation-service target key (entity:{type}:{id}).
        correlation_key: Correlation/incident entity key (domain-specific format).
        recent_alerts: Recent alerts for this entity, newest-first.
            Bounded to 50.
        behavior_summary: Behavioral profile summaries for this entity.
            Bounded by AnalystBehaviorQueryService limits.
        annotations: Analyst annotations for this entity, newest-first.
            Bounded to 20.
        incident: Associated incident if one exists, None otherwise.
            At most one incident per entity.
        source_status: Per-source availability status.
            Keys: 'alerts', 'behavior', 'annotations', 'incident'.
            Values: SourceStatus values. AVAILABLE means source responded
            (data may still be empty). UNAVAILABLE means source error.
    """

    entity_type: str
    entity_id: str
    annotation_key: str
    correlation_key: str
    recent_alerts: tuple[Alert, ...] = field(default_factory=tuple)
    behavior_summary: tuple[dict, ...] = field(default_factory=tuple)
    annotations: tuple[dict, ...] = field(default_factory=tuple)
    incident: Incident | None = None
    source_status: tuple[tuple[str, SourceStatus], ...] = field(default_factory=tuple)
    attck_context: tuple[AttckTechniqueSummary, ...] = field(default_factory=tuple)

    @classmethod
    def empty(
        cls,
        entity_type: str,
        entity_id: str,
        annotation_key: str,
        correlation_key: str,
    ) -> EntityInvestigationContext:
        """Create an empty investigation context.

        Args:
            entity_type: Type of the entity.
            entity_id: Unique identifier of the entity.
            annotation_key: Annotation-service target key.
            correlation_key: Correlation/incident entity key.

        Returns:
            Empty EntityInvestigationContext with no evidence.
        """
        return cls(
            entity_type=entity_type,
            entity_id=entity_id,
            annotation_key=annotation_key,
            correlation_key=correlation_key,
        )

    @property
    def alert_count(self) -> int:
        """Number of alerts in this context."""
        return len(self.recent_alerts)

    @property
    def annotation_count(self) -> int:
        """Number of annotations in this context."""
        return len(self.annotations)

    @property
    def attck_technique_count(self) -> int:
        """Number of ATT&CK technique summaries in this context."""
        return len(self.attck_context)

    @property
    def has_evidence(self) -> bool:
        """Whether this context has any evidence at all."""
        return bool(
            self.recent_alerts
            or self.behavior_summary
            or self.annotations
            or self.incident
            or self.attck_context
        )

    def get_source_status(self, source: str) -> SourceStatus:
        """Get status for a specific source.

        Args:
            source: One of 'alerts', 'behavior', 'annotations', 'incident'.

        Returns:
            SourceStatus for the requested source.

        Raises:
            ValueError: If source is not a valid source name.
        """
        for key, status in self.source_status:
            if key == source:
                return status
        raise ValueError(
            f"Unknown source '{source}'. Valid sources: "
            f"{', '.join(k for k, _ in self.source_status)}"
        )


__all__ = [
    "_MAX_ALERTS",
    "_MAX_ANNOTATIONS",
    "EntityInvestigationContext",
    "SourceStatus",
]
