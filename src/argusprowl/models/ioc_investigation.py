"""IOC investigation result models (Phase 7.6).

Frozen, bounded data contracts for analyst-facing IOC investigation responses.
No state mutation, no external lookups, no correlation engine interaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from argusprowl.models.context import PrevalenceResult, ThreatIntelReputation


class IocType(StrEnum):
    """Supported IOC types."""

    IP = "ip"
    DOMAIN = "domain"


class IocInvestigationStatus(StrEnum):
    """Status of an IOC investigation operation."""

    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"
    EMPTY = "EMPTY"


@dataclass(frozen=True, slots=True)
class IocObservation:
    """Single observation of an IOC from retained alert evidence."""

    alert_id: str
    timestamp: datetime
    field: str
    value: str
    host: str | None
    rule_id: str | None
    severity: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": str(self.alert_id),
            "timestamp": self.timestamp.isoformat(),
            "field": self.field,
            "value": self.value,
            "host": self.host,
            "rule_id": self.rule_id,
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class RelatedIoc:
    """Another IOC co-observed in the same alert as the queried indicator."""

    indicator: str
    ioc_type: IocType
    field: str
    co_observed_in_alert_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "ioc_type": self.ioc_type.value,
            "field": self.field,
            "co_observed_in_alert_id": str(self.co_observed_in_alert_id),
        }


@dataclass(frozen=True, slots=True)
class IocTimelineItem:
    """A single item in the IOC investigation timeline."""

    timeline_item_id: str
    timestamp: str | None
    item_type: str
    title: str
    summary: str
    source_id: str | None
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timeline_item_id": self.timeline_item_id,
            "timestamp": self.timestamp,
            "item_type": self.item_type,
            "title": self.title,
            "summary": self.summary,
            "source_id": self.source_id,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class IocInvestigationResult:
    """Immutable result contract for an IOC investigation."""

    indicator: str
    ioc_type: IocType
    reputation: ThreatIntelReputation
    observations: tuple[IocObservation, ...]
    first_observed: datetime | None
    last_observed: datetime | None
    associated_alert_ids: tuple[str, ...]
    associated_hosts: tuple[str, ...]
    associated_rule_ids: tuple[str, ...]
    related_iocs: tuple[RelatedIoc, ...]
    timeline: tuple[IocTimelineItem, ...]
    prevalence: PrevalenceResult | None
    status: IocInvestigationStatus
    reason: str | None
    truncated: bool
    inspected_alert_count: int
    observation_note: str = "first observed in retained alert evidence"

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "ioc_type": self.ioc_type.value,
            "reputation": self.reputation.to_dict(),
            "observations": [obs.to_dict() for obs in self.observations],
            "first_observed": self.first_observed.isoformat() if self.first_observed else None,
            "last_observed": self.last_observed.isoformat() if self.last_observed else None,
            "associated_alert_ids": list(self.associated_alert_ids),
            "associated_hosts": list(self.associated_hosts),
            "associated_rule_ids": list(self.associated_rule_ids),
            "related_iocs": [r.to_dict() for r in self.related_iocs],
            "timeline": [item.to_dict() for item in self.timeline],
            "prevalence": self.prevalence.to_dict() if self.prevalence else None,
            "status": self.status.value,
            "reason": self.reason,
            "truncated": self.truncated,
            "inspected_alert_count": self.inspected_alert_count,
            "observation_note": self.observation_note,
        }
