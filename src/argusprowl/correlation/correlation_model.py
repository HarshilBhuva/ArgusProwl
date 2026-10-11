"""Correlation data models for endpoint ↔ network association.

Provides bounded in-memory state tracking that associates process identity
with network observations when the telemetry supports it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID


class NetworkDirection(Enum):
    """Network traffic direction relative to the monitored host.

    Direction is derived from available evidence, not inferred from
    arbitrary private/public IP heuristics.
    """

    OUTBOUND = "outbound"
    INBOUND = "inbound"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """Bounded process identity captured from telemetry.

    PID is scoped to a host and process lifetime.  When hostname is
    unavailable the identity is still useful for within-host correlation.
    """

    process_name: str | None = None
    pid: int | None = None
    username: str | None = None
    hostname: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    source_type: str | None = None

    @property
    def identity_key(self) -> tuple[str | None, int | None]:
        """Return (hostname, pid) for scoping.  Both may be None."""
        return (self.hostname, self.pid)

    def is_complete(self) -> bool:
        """Return True when enough identity fields are present for correlation."""
        return self.process_name is not None and self.pid is not None


@dataclass(frozen=True, slots=True)
class NetworkObservation:
    """Bounded network observation with optional process attribution.

    Mirrors the fields already tracked by TemporalObservation but adds
    direction and source provenance for correlation decisions.
    """

    event_id: UUID
    timestamp: datetime
    dst_ip: str
    dst_port: int
    src_ip: str | None = None
    src_port: int | None = None
    protocol: str | None = None
    process_name: str | None = None
    pid: int | None = None
    username: str | None = None
    hostname: str | None = None
    direction: NetworkDirection = NetworkDirection.UNKNOWN
    source_type: str | None = None
    command_line: str | None = None

    @property
    def network_key(self) -> tuple[str, int]:
        """Return (dst_ip, dst_port) for temporal engine keying."""
        return (self.dst_ip, self.dst_port)

    @property
    def process_key(self) -> tuple[str | None, int | None]:
        """Return (hostname, pid) for process identity scoping."""
        return (self.hostname, self.pid)

    def has_process_attribution(self) -> bool:
        """Return True when process identity is available."""
        return self.process_name is not None and self.pid is not None


@dataclass(frozen=True, slots=True)
class CorrelatedActivity:
    """Result of a successful endpoint ↔ network correlation.

    Represents a bounded association between a process and a network
    destination.  Does not duplicate full NormalizedEvent objects.
    """

    activity_id: UUID
    process_name: str | None
    pid: int | None
    username: str | None
    hostname: str | None
    command_line: str | None
    dst_ip: str
    dst_port: int
    protocol: str | None
    direction: NetworkDirection
    first_seen: datetime
    last_seen: datetime
    observation_count: int
    source_types: tuple[str, ...]
    event_ids: tuple[UUID, ...]
    correlation_confidence: float = 0.0

    @property
    def explanation(self) -> str:
        """Human-readable explanation of the correlation."""
        parts = []
        if self.process_name:
            parts.append(f"Process {self.process_name}")
            if self.pid is not None:
                parts[-1] += f" (PID {self.pid})"
        if self.username:
            parts.append(f"user {self.username}")
        if self.hostname:
            parts.append(f"on {self.hostname}")

        process_part = ", ".join(parts) if parts else "An unknown process"

        dest = f"{self.dst_ip}:{self.dst_port}"
        proto = f" ({self.protocol})" if self.protocol else ""

        return (
            f"{process_part} communicated with {dest}{proto} "
            f"over {self.observation_count} observation(s)."
        )

    def to_evidence(self) -> list[dict[str, object]]:
        """Serialize to DetectionResult-compatible evidence entries."""
        evidence: list[dict[str, object]] = []
        if self.process_name:
            evidence.append(
                {
                    "field": "process_name",
                    "observed": self.process_name,
                    "condition": "equals",
                }
            )
        if self.pid is not None:
            evidence.append(
                {
                    "field": "process_id",
                    "observed": self.pid,
                    "condition": "equals",
                }
            )
        if self.username:
            evidence.append(
                {
                    "field": "username",
                    "observed": self.username,
                    "condition": "equals",
                }
            )
        if self.hostname:
            evidence.append(
                {
                    "field": "hostname",
                    "observed": self.hostname,
                    "condition": "equals",
                }
            )
        evidence.append(
            {
                "field": "destination",
                "observed": self.dst_ip,
                "condition": "equals",
            }
        )
        evidence.append(
            {
                "field": "destination_port",
                "observed": self.dst_port,
                "condition": "equals",
            }
        )
        if self.protocol:
            evidence.append(
                {
                    "field": "protocol",
                    "observed": self.protocol,
                    "condition": "equals",
                }
            )
        evidence.append(
            {
                "field": "direction",
                "observed": self.direction.value,
                "condition": "equals",
            }
        )
        evidence.append(
            {
                "field": "observation_count",
                "observed": self.observation_count,
                "condition": "greater_than_or_equal",
            }
        )
        return evidence
