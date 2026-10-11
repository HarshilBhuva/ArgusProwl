"""Alert data model.

Represents a security alert produced by the detection pipeline.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity


@dataclass(frozen=True, slots=True)
class Alert:
    """An immutable security alert.

    Attributes:
        alert_id: Unique identifier for this alert.
        title: Short human-readable summary.
        description: Detailed explanation of the alert.
        severity: The assessed severity level.
        source: Identifier of the component that generated this alert.
        created_at: UTC timestamp of alert creation.
        tags: Arbitrary classification tags.
        metadata: Additional key-value context.
        assessment_id: UUID of the ContextualAssessment that informed this alert.
        detector_confidence: Original detector confidence from DetectionResult.
        contextual_confidence: Final confidence from ContextualAssessment.
        contextual_explanation: Analyst-facing explanation of contextual adjustments.
        supporting_evidence: Structured evidence that increased suspicion.
        contradictory_evidence: Structured evidence that decreased suspicion.
        investigation_pivots: Recommended next investigation steps.
        entity_context: Serialized entity attribution (host, process, network, user).
    """

    title: str
    description: str
    severity: Severity
    source: str
    alert_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tags: tuple[str, ...] = ()
    metadata: dict[str, object] = field(default_factory=dict)
    schema_version: int = 2
    # --- Phase 4.7.1: Contextual assessment fields (all optional) ---
    assessment_id: UUID | None = None
    detector_confidence: float | None = None
    contextual_confidence: float | None = None
    contextual_explanation: str = ""
    supporting_evidence: tuple[dict[str, Any], ...] = ()
    contradictory_evidence: tuple[dict[str, Any], ...] = ()
    investigation_pivots: tuple[str, ...] = ()
    entity_context: dict[str, Any] | None = None
    # --- Phase 4.7.4: Operational priority (derived from severity) ---
    priority: AlertPriority | None = None
    # --- Phase 4.7.5A: Alert lifecycle state ---
    lifecycle_state: AlertLifecycleState = AlertLifecycleState.OPEN
    # --- Phase 7.8: Telemetry evidence provenance ---
    detection_source_event_id: UUID | None = None
    contributing_event_ids: tuple[UUID, ...] = ()
    # --- Phase 4.8.1: Incident association (optional) ---
    incident_id: UUID | None = None

    def __post_init__(self) -> None:
        """Validate required fields after construction."""
        if not self.title.strip():
            raise ValueError("Alert title must not be empty.")
        if not self.source.strip():
            raise ValueError("Alert source must not be empty.")
        if self.schema_version < 1:
            raise ValueError("Alert schema_version must be positive.")
        if self.detector_confidence is not None and not 0.0 <= self.detector_confidence <= 1.0:
            raise ValueError(
                f"detector_confidence must be between 0.0 and 1.0, got {self.detector_confidence}"
            )
        if self.contextual_confidence is not None and not 0.0 <= self.contextual_confidence <= 1.0:
            raise ValueError(
                f"contextual_confidence must be between 0.0 and 1.0, got {self.contextual_confidence}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize alert to dictionary."""
        return {
            "alert_id": str(self.alert_id),
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name,
            "priority": self.priority.value if self.priority else None,
            "lifecycle_state": self.lifecycle_state.value,
            "source": self.source,
            "created_at": self.created_at.isoformat(),
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
            "schema_version": self.schema_version,
            "assessment_id": str(self.assessment_id) if self.assessment_id else None,
            "detector_confidence": self.detector_confidence,
            "contextual_confidence": self.contextual_confidence,
            "contextual_explanation": self.contextual_explanation,
            "supporting_evidence": list(self.supporting_evidence),
            "contradictory_evidence": list(self.contradictory_evidence),
            "investigation_pivots": list(self.investigation_pivots),
            "entity_context": dict(self.entity_context) if self.entity_context else None,
            "incident_id": str(self.incident_id) if self.incident_id else None,
            "detection_source_event_id": str(self.detection_source_event_id)
            if self.detection_source_event_id
            else None,
            "contributing_event_ids": [str(eid) for eid in self.contributing_event_ids],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        """Deserialize alert from dictionary."""
        try:
            return cls(
                alert_id=UUID(str(data["alert_id"])),
                title=str(data["title"]),
                description=str(data["description"]),
                severity=Severity.from_string(str(data["severity"])),
                source=str(data["source"]),
                created_at=datetime.fromisoformat(str(data["created_at"])),
                tags=tuple(data.get("tags", [])),
                metadata=dict(data.get("metadata", {})),
                schema_version=int(data.get("schema_version", 2)),
                assessment_id=UUID(str(data["assessment_id"]))
                if data.get("assessment_id")
                else None,
                detector_confidence=(
                    float(data["detector_confidence"])
                    if "detector_confidence" in data and data["detector_confidence"] is not None
                    else None
                ),
                contextual_confidence=(
                    float(data["contextual_confidence"])
                    if "contextual_confidence" in data and data["contextual_confidence"] is not None
                    else None
                ),
                contextual_explanation=str(data.get("contextual_explanation", "")),
                supporting_evidence=tuple(data.get("supporting_evidence", [])),
                contradictory_evidence=tuple(data.get("contradictory_evidence", [])),
                investigation_pivots=tuple(data.get("investigation_pivots", [])),
                entity_context=dict(data["entity_context"]) if data.get("entity_context") else None,
                priority=(
                    AlertPriority.from_string(str(data["priority"]))
                    if "priority" in data and data["priority"] is not None
                    else None
                ),
                lifecycle_state=(
                    AlertLifecycleState.from_string(str(data["lifecycle_state"]))
                    if "lifecycle_state" in data and data["lifecycle_state"] is not None
                    else AlertLifecycleState.OPEN
                ),
                incident_id=UUID(str(data["incident_id"])) if data.get("incident_id") else None,
                detection_source_event_id=(
                    UUID(str(data["detection_source_event_id"]))
                    if data.get("detection_source_event_id")
                    else None
                ),
                contributing_event_ids=tuple(
                    UUID(str(eid)) for eid in data.get("contributing_event_ids", ())
                ),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f"Invalid Alert mapping: {exc}") from exc
