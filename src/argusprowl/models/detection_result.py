"""Detection result data model.

Represents the outcome of running a detection rule or ML model
against an event.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from argusprowl.constants.severity import Severity


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Immutable result of a detection evaluation.

    Attributes:
        result_id: Unique identifier.
        rule_id: The rule or model identifier that triggered.
        event_id: The event that was evaluated.
        matched: Whether the detection triggered.
        severity: Assessed severity if matched.
        confidence: Confidence score in ``[0.0, 1.0]``.
        description: Human-readable explanation.
        explanation: Structured explanation of the detection.
        evidence: Supporting data extracted during evaluation.
        created_at: UTC timestamp of the evaluation.
        version: Rule version that triggered the detection.
        contributing_event_ids: Additional event identities for future
            multi-event/correlation detections; excludes the primary ``event_id``.
        metadata: Additional bounded result context. Do not store raw telemetry.
    """

    rule_id: str
    event_id: UUID
    matched: bool
    severity: Severity = Severity.INFO
    confidence: float = 0.0
    description: str = ""
    explanation: str = ""
    result_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    evidence: list[dict[str, object]] = field(default_factory=list)
    schema_version: int = 1
    version: int = 1
    contributing_event_ids: tuple[UUID, ...] = ()
    metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate constraints."""
        if not self.rule_id.strip():
            raise ValueError("DetectionResult rule_id must not be empty.")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        if self.schema_version < 1:
            raise ValueError("DetectionResult schema_version must be positive.")
        if self.version < 1:
            raise ValueError("DetectionResult version must be positive.")
        if not isinstance(self.evidence, list):
            raise ValueError("DetectionResult evidence must be a list.")
        for item in self.evidence:
            if not isinstance(item, dict):
                raise ValueError("DetectionResult evidence entries must be mappings.")
            if not {"field", "observed", "condition"}.issubset(item):
                raise ValueError(
                    "DetectionResult evidence entries require field, observed, and condition."
                )
        if any(not isinstance(event_id, UUID) for event_id in self.contributing_event_ids):
            raise ValueError("DetectionResult contributing_event_ids must contain UUIDs.")
        if not isinstance(self.metadata, dict):
            raise ValueError("DetectionResult metadata must be a mapping.")

    @property
    def detection_id(self) -> UUID:
        """Canonical identity name; ``result_id`` remains for compatibility."""
        return self.result_id

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain YAML/JSON-friendly mapping.

        The serialized form keeps event/result identities as UUIDs and
        evidence as a list of structured entries.
        """
        return {
            "result_id": str(self.result_id),
            "rule_id": self.rule_id,
            "event_id": str(self.event_id),
            "matched": self.matched,
            "severity": self.severity.name,
            "confidence": self.confidence,
            "description": self.description,
            "explanation": self.explanation,
            "created_at": self.created_at.isoformat(),
            "evidence": list(self.evidence),
            "schema_version": self.schema_version,
            "version": self.version,
            "contributing_event_ids": [str(event_id) for event_id in self.contributing_event_ids],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "DetectionResult":
        """Deserialize from a plain mapping.

        Args:
            data: Mapping with keys matching the ``to_dict()`` output.

        Returns:
            A validated :class:`DetectionResult`.

        Raises:
            ValueError: Invalid or missing fields.
        """
        try:
            return cls(
                rule_id=str(data["rule_id"]),
                event_id=UUID(str(data["event_id"])),
                matched=bool(data["matched"]),
                severity=Severity.from_string(str(data["severity"])),
                confidence=float(data["confidence"]),
                description=str(data.get("description", "")),
                explanation=str(data.get("explanation", "")),
                result_id=UUID(str(data["result_id"])),
                created_at=datetime.fromisoformat(str(data["created_at"])),
                evidence=list(data.get("evidence", [])),
                schema_version=int(data["schema_version"]),
                version=int(data["version"]),
                contributing_event_ids=tuple(
                    UUID(str(event_id)) for event_id in data.get("contributing_event_ids", ())
                ),
                metadata=dict(data.get("metadata", {})),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f"Invalid DetectionResult mapping: {exc}") from exc
