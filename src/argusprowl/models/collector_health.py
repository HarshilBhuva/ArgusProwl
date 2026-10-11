"""Collector health snapshot model.

Provides a typed, immutable report of a single collector's current state,
metrics, and any active error message.  Consumed by the health service and
REST/CLI status reporters.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from argusprowl.collectors.metrics import CollectorMetricsSnapshot
from argusprowl.collectors.state import CollectorState


@dataclass(frozen=True, slots=True)
class CollectorHealth:
    """Immutable health report for a single collector.

    Attributes:
        name: Unique collector identifier.
        state: Current lifecycle state.
        metrics: Frozen metrics snapshot at the time of the health check.
        error_message: Human-readable description of the most recent error,
            or an empty string when the collector is healthy.
        checked_at: UTC datetime at which this report was generated.
    """

    name: str
    state: CollectorState
    metrics: CollectorMetricsSnapshot
    error_message: str = ""
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_healthy(self) -> bool:
        """True when the collector is RUNNING with no active error."""
        return self.state == CollectorState.RUNNING and not self.error_message

    @property
    def is_degraded(self) -> bool:
        """True when the collector is PAUSED (operational but not ingesting)."""
        return self.state == CollectorState.PAUSED

    @property
    def is_failed(self) -> bool:
        """True when the collector is in FAILED state."""
        return self.state == CollectorState.FAILED

    def to_dict(self) -> dict[str, object]:
        """Serialize health report to a plain dict.

        Returns:
            Dictionary suitable for JSON serialization or health API responses.
        """
        return {
            "name": self.name,
            "state": str(self.state),
            "error_message": self.error_message,
            "is_healthy": self.is_healthy,
            "is_degraded": self.is_degraded,
            "is_failed": self.is_failed,
            "metrics": self.metrics.to_dict(),
            "checked_at": self.checked_at.isoformat(),
        }
