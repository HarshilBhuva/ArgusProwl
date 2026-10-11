"""Immutable state exposed by alert deduplication."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class DeduplicationState:
    fingerprint: str
    detector: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    cooldown_until: datetime
    alert_id: UUID
    status: str = "active"
    fingerprint_version: int = 1
