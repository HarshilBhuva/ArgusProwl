"""System status data model.

Used by the health-check subsystem to report on component readiness.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class HealthStatus(StrEnum):
    """Overall health states."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass(frozen=True, slots=True)
class ComponentHealth:
    """Health report for a single subsystem component.

    Attributes:
        name: Component identifier (e.g. ``"config"``, ``"event_bus"``).
        status: Current health state.
        message: Optional human-readable detail.
    """

    name: str
    status: HealthStatus
    message: str = ""


@dataclass(frozen=True, slots=True)
class SystemStatus:
    """Aggregated health status of the entire platform.

    Attributes:
        status: Roll-up health state.
        version: Application version string.
        uptime_seconds: Seconds since application start.
        checked_at: UTC timestamp of this health check.
        components: Per-component health details.
    """

    status: HealthStatus
    version: str
    uptime_seconds: float
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    components: tuple[ComponentHealth, ...] = ()
