"""Evidence model for the Phase 4.1 Detection Rule Contract.

A detection must be explainable.  Evidence records what was observed at
match time — field, observed value, expected condition — plus an optional
reference to the contributing event, so multi-event detections can refer
to several NormalizedEvent identities without embedding the full
telemetry payload.

The contract explicitly avoids duplicating whole :class:`NormalizedEvent`
objects inside a detection result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final
from uuid import UUID


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """One atomic piece of evidence.

    Attributes:
        field: Telemetry field examined.
        observed: Value observed at detection time.
        condition: Short human-readable description of the expected
            condition, e.g. ``"equals powershell.exe"``.
        event_id: Optional contributing event identity.
        value: Optional expected/comparison value (mirrors condition value).
    """

    field: str
    observed: Any
    condition: str
    event_id: UUID | None = None
    value: Any = None

    def __post_init__(self) -> None:
        """Validate shape."""
        if not isinstance(self.field, str) or not self.field.strip():
            raise ValueError("EvidenceEntry field must not be empty.")
        if not isinstance(self.condition, str) or not self.condition.strip():
            raise ValueError("EvidenceEntry condition must not be empty.")
        if self.event_id is not None and not isinstance(self.event_id, UUID):
            raise ValueError("EvidenceEntry event_id must be a UUID or None.")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain mapping."""
        return {
            "field": self.field,
            "observed": self.observed,
            "condition": self.condition,
            "event_id": str(self.event_id) if self.event_id is not None else None,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class Explanation:
    """Structured, human-readable explanation of a detection.

    Attributes:
        summary: One-line summary of why the rule fired.
        reason: Longer explanation combining the matched conditions.
        evidence: List of contributing :class:`EvidenceItem` records.
        confidence: Optional explicit confidence associated with this
            explanation (usually mirrors the rule confidence).
        severity: Optional textual severity for rendering (e.g. ``"HIGH"``).
    """

    summary: str
    reason: str = ""
    evidence: tuple[EvidenceItem, ...] = field(default_factory=tuple)
    confidence: float | None = None
    severity: str | None = None

    def __post_init__(self) -> None:
        """Validate shape."""
        if not isinstance(self.summary, str) or not self.summary.strip():
            raise ValueError("Explanation summary must not be empty.")
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Explanation confidence must be within [0.0, 1.0].")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain mapping."""
        return {
            "summary": self.summary,
            "reason": self.reason,
            "evidence": [entry.to_dict() for entry in self.evidence],
            "confidence": self.confidence,
            "severity": self.severity,
        }


__all__: Final[list[str]] = ["EvidenceItem", "Explanation"]
