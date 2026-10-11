"""Immutable export format for internal platform metrics."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class MetricsSnapshot:
    uptime_seconds: float
    metrics: dict[str, dict[str, Any]]
    captured_at: datetime = field(default_factory=lambda: datetime.now(UTC))
