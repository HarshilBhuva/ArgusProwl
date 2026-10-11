"""Unified alert search service.

Merges alerts from AlertQueue (live operational view) and AlertPersistence
durable historical view into a single bounded, deterministic search API.

ATT&CK search is a read-only filter over already-persisted/enriched
``Alert.metadata["attck_observations"]``. It never creates or updates
ATT&CK observations and never consults the ATT&CK network or knowledge store.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from argusprowl.attck.mapping_registry import MappingType
from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.lifecycle.filtering import filter_alerts
from argusprowl.lifecycle.sorting import sort_alerts
from argusprowl.models.alert import Alert

if TYPE_CHECKING:
    from argusprowl.alerting.alert_persistence import AlertPersistence
    from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
    from argusprowl.lifecycle.queue import AlertQueue

_MAX_ATTCK_OBSERVATIONS = 256
_MAX_ATTCK_FILTER_VALUE_LENGTH = 128
_MAX_ATTCK_FILTER_VALUES = 32
_MAX_ATTCK_STRING_LENGTH = 512
_OBSERVABLE_MAPPING_TYPES = frozenset(
    {MappingType.DIRECT, MappingType.SUPPORTED, MappingType.CONTEXTUAL}
)
logger = logging.getLogger(__name__)


class AlertSearchStatus(StrEnum):
    """Status of an alert search operation."""

    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"


@dataclass(frozen=True, slots=True)
class AlertSearchResult:
    """Result of an alert search operation."""

    alerts: tuple[Alert, ...]
    status: AlertSearchStatus
    reason: str | None = None


class AlertSearchService:
    """Unified search service across AlertQueue and AlertPersistence.

    ATT&CK filters use only observations already attached to each alert by
    the authoritative enrichment path. Ordinary and ATT&CK filters are ANDed.
    Multiple values supplied for one ATT&CK dimension are ORed; dimensions are
    ANDed. Matching is exact and never fuzzy.

    The queue/persistence pipeline remains bounded and unchanged:
    queue snapshot -> filter -> persistence snapshot -> filter -> merge by ID
    -> queue authoritative -> conflict detection -> deterministic sort -> limit.
    """

    def __init__(
        self,
        alert_queue: AlertQueue | None,
        alert_persistence: AlertPersistence | None,
        entity_correlation_service: EntityCorrelationService,
    ) -> None:
        self._queue = alert_queue
        self._persistence = alert_persistence
        self._ecs = entity_correlation_service

    def search(
        self,
        *,
        limit: int,
        min_priority: AlertPriority | None = None,
        min_severity: Severity | None = None,
        rule_id: str | None = None,
        host: str | None = None,
        lifecycle_state: AlertLifecycleState | None = None,
        entity_key: str | None = None,
        incident_id: str | None = None,
        technique_id: str | tuple[str, ...] | None = None,
        subtechnique_id: str | tuple[str, ...] | None = None,
        mapping_type: MappingType | str | tuple[MappingType | str, ...] | None = None,
        tactic: str | tuple[str, ...] | None = None,
    ) -> AlertSearchResult:
        """Search queue and persistence using ordinary and ATT&CK filters."""
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError(f"limit must be a positive integer, got {limit!r}")

        normalized_techniques = self._normalize_ids(technique_id, "technique_id")
        normalized_subtechniques = self._normalize_ids(subtechnique_id, "subtechnique_id")
        normalized_mapping_types = self._normalize_mapping_types(mapping_type)
        normalized_tactics = self._normalize_strings(tactic, "tactic")

        queue_alerts = self._queue.list(sort=False) if self._queue is not None else []
        persistence_alerts: list[Alert] = []
        if self._persistence is not None:
            persistence_result = self._persistence.list_all(limit=None)
            persistence_alerts = list(persistence_result.alerts)

        queue_filtered = filter_alerts(
            queue_alerts,
            min_priority=min_priority,
            min_severity=min_severity,
            rule_id=rule_id,
            host=host,
            lifecycle_state=lifecycle_state,
            entity_key=entity_key,
            incident_id=incident_id,
        )
        persistence_filtered = filter_alerts(
            persistence_alerts,
            min_priority=min_priority,
            min_severity=min_severity,
            rule_id=rule_id,
            host=host,
            lifecycle_state=lifecycle_state,
            entity_key=entity_key,
            incident_id=incident_id,
        )

        queue_by_id = {str(alert.alert_id): alert for alert in queue_filtered}
        persistence_by_id = {str(alert.alert_id): alert for alert in persistence_filtered}

        conflicts = [
            alert_id
            for alert_id in queue_by_id
            if alert_id in persistence_by_id
            and self._has_payload_conflict(queue_by_id[alert_id], persistence_by_id[alert_id])
        ]
        if conflicts:
            logger.warning("Payload conflicts detected for alerts: %s", ", ".join(conflicts))
            return AlertSearchResult(
                alerts=tuple(queue_by_id[alert_id] for alert_id in sorted(set(conflicts))),
                status=AlertSearchStatus.DEGRADED,
                reason="payload_conflict",
            )

        merged: dict[str, Alert] = dict(persistence_by_id)
        merged.update(queue_by_id)
        merged_alerts = list(merged.values())
        filtered_alerts = self._filter_attck(
            merged_alerts,
            technique_ids=normalized_techniques,
            subtechnique_ids=normalized_subtechniques,
            mapping_types=normalized_mapping_types,
            tactics=normalized_tactics,
        )

        sorted_alerts = sort_alerts(filtered_alerts)
        return AlertSearchResult(
            alerts=tuple(sorted_alerts[:limit]), status=AlertSearchStatus.AVAILABLE
        )

    @staticmethod
    def _normalize_ids(
        value: str | tuple[str, ...] | None, field_name: str
    ) -> tuple[str, ...] | None:
        if value is None:
            return None
        values = (value,) if isinstance(value, str) else value
        if not isinstance(values, tuple) or not values or len(values) > _MAX_ATTCK_FILTER_VALUES:
            raise ValueError(f"{field_name} must be a string or bounded tuple of strings")
        normalized = []
        for item in values:
            if not isinstance(item, str) or not item or len(item) > _MAX_ATTCK_FILTER_VALUE_LENGTH:
                raise ValueError(f"Invalid {field_name} filter value")
            normalized.append(item.upper())
        return tuple(sorted(set(normalized)))

    @staticmethod
    def _normalize_strings(
        value: str | tuple[str, ...] | None, field_name: str
    ) -> tuple[str, ...] | None:
        if value is None:
            return None
        values = (value,) if isinstance(value, str) else value
        if not isinstance(values, tuple) or not values or len(values) > _MAX_ATTCK_FILTER_VALUES:
            raise ValueError(f"{field_name} must be a string or bounded tuple of strings")
        normalized = []
        for item in values:
            if not isinstance(item, str) or not item or len(item) > _MAX_ATTCK_FILTER_VALUE_LENGTH:
                raise ValueError(f"Invalid {field_name} filter value")
            normalized.append(item)
        return tuple(sorted(set(normalized)))

    @staticmethod
    def _normalize_mapping_types(
        value: MappingType | str | tuple[MappingType | str, ...] | None,
    ) -> tuple[MappingType, ...] | None:
        if value is None:
            return None
        values = (value,) if isinstance(value, (MappingType, str)) else value
        if not isinstance(values, tuple) or not values or len(values) > _MAX_ATTCK_FILTER_VALUES:
            raise ValueError("mapping_type must be a valid enum value or bounded tuple")
        result = []
        for item in values:
            try:
                mapping = item if isinstance(item, MappingType) else MappingType(item.upper())
            except (AttributeError, ValueError) as exc:
                raise ValueError(f"Invalid ATT&CK mapping_type filter value: {item!r}") from exc
            if mapping not in _OBSERVABLE_MAPPING_TYPES:
                raise ValueError(
                    f"ATT&CK mapping_type {mapping.value!r} is not represented by observations"
                )
            result.append(mapping)
        return tuple(sorted(set(result), key=lambda item: item.value))

    @classmethod
    def _filter_attck(
        cls,
        alerts: list[Alert],
        *,
        technique_ids: tuple[str, ...] | None,
        subtechnique_ids: tuple[str, ...] | None,
        mapping_types: tuple[MappingType, ...] | None,
        tactics: tuple[str, ...] | None,
    ) -> list[Alert]:
        if all(
            value is None for value in (technique_ids, subtechnique_ids, mapping_types, tactics)
        ):
            return alerts
        return [
            alert
            for alert in alerts
            if cls._matches_attck_observations(
                alert.metadata.get("attck_observations"),
                technique_ids=technique_ids,
                subtechnique_ids=subtechnique_ids,
                mapping_types=mapping_types,
                tactics=tactics,
            )
        ]

    @staticmethod
    def _matches_attck_observations(
        raw_observations: object,
        *,
        technique_ids: tuple[str, ...] | None,
        subtechnique_ids: tuple[str, ...] | None,
        mapping_types: tuple[MappingType, ...] | None,
        tactics: tuple[str, ...] | None,
    ) -> bool:
        if not isinstance(raw_observations, list):
            return False
        observations = raw_observations[:_MAX_ATTCK_OBSERVATIONS]
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            if any(
                value is not None
                and not AlertSearchService._observation_field_matches(
                    observation, field_name, value
                )
                for field_name, value in (
                    ("technique_id", technique_ids),
                    ("subtechnique_id", subtechnique_ids),
                    ("mapping_type", mapping_types),
                    ("tactic", tactics),
                )
            ):
                continue
            return True
        return False

    @staticmethod
    def _observation_field_matches(
        observation: dict[object, object], field_name: str, accepted_values: tuple[object, ...]
    ) -> bool:
        value = observation.get(field_name)
        if field_name in {"technique_id", "subtechnique_id"}:
            return isinstance(value, str) and value.upper() in accepted_values
        if field_name == "mapping_type":
            if not isinstance(value, str):
                return False
            try:
                return MappingType(value.upper()) in accepted_values
            except ValueError:
                return False
        if field_name == "tactic":
            return (
                isinstance(value, str)
                and len(value) <= _MAX_ATTCK_STRING_LENGTH
                and value in accepted_values
            )
        return False

    @staticmethod
    def _canonicalize(value: Any) -> Any:
        """Normalize Alert.to_dict() values for cross-layer equality."""
        if isinstance(value, Mapping):
            return {
                str(key): AlertSearchService._canonicalize(value[key])
                for key in sorted(value, key=str)
            }
        if isinstance(value, (list, tuple)):
            return [AlertSearchService._canonicalize(item) for item in value]
        return value

    @classmethod
    def _has_payload_conflict(cls, queue_alert: Alert, persistence_alert: Alert) -> bool:
        queue_payload = cls._canonicalize(queue_alert.to_dict())
        persistence_payload = cls._canonicalize(persistence_alert.to_dict())
        queue_payload.pop("lifecycle_state", None)
        persistence_payload.pop("lifecycle_state", None)
        # Persistence reconstructs immutable tuples as lists during JSON round-trip,
        # so canonicalization must erase only representation differences, not data.
        queue_blob = json.dumps(queue_payload, sort_keys=True, separators=(",", ":"), default=str)
        persistence_blob = json.dumps(
            persistence_payload, sort_keys=True, separators=(",", ":"), default=str
        )
        return (
            hashlib.sha256(queue_blob.encode("utf-8")).digest()
            != hashlib.sha256(persistence_blob.encode("utf-8")).digest()
        )
