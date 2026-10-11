"""Investigation timeline service.

Builds a bounded, deterministic, read-only timeline of investigation evidence
for an entity by combining existing evidence sources:
- Alerts (from AlertSearchService)
- Incidents (from IncidentService, only when reliable timestamp exists)
- Annotations (from AnalystAnnotationService)
- Behavior (from AnalystBehaviorQueryService, only when temporally defensible)

This service does NOT:
- Perform detection or correlation
- Modify any source state
- Create new persistence
- Invent timestamps or entity relationships
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from argusprowl.models.timeline_item import TimelineItem, TimelineItemType

if TYPE_CHECKING:
    from argusprowl.alerting.alert_manager import AlertManager
    from argusprowl.alerting.alert_persistence import AlertPersistence
    from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
    from argusprowl.behavior.analyst_behavior_query_service import AnalystBehaviorQueryService
    from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
    from argusprowl.incident.incident_service import IncidentService
    from argusprowl.services.alert_search_service import AlertSearchService

logger = logging.getLogger(__name__)

# Bounds
_MAX_ITEMS = 200
_MAX_METADATA_KEYS = 10
_MAX_METADATA_VALUE_LENGTH = 256
_MAX_TITLE_LENGTH = 200
_MAX_SUMMARY_LENGTH = 1024
_MAX_LIMIT = 100

# Entity type validation
_ENTITY_TYPE_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]+$")
_ENTITY_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


class InvestigationTimelineService:
    """Builds a bounded, deterministic investigation timeline for an entity.

    Read-only: no state modifications.
    Bounded: maximum _MAX_ITEMS entries, configurable limit.
    Deduplicated: same source appears only once.
    Deterministic: stable sort order with tie-breaking.
    """

    def __init__(
        self,
        alert_search_service: AlertSearchService,
        incident_service: IncidentService,
        annotation_service: AnalystAnnotationService,
        behavior_query_service: AnalystBehaviorQueryService,
        entity_correlation_service: EntityCorrelationService,
        alert_manager: AlertManager | None = None,
        alert_persistence: AlertPersistence | None = None,
    ) -> None:
        self._alert_search = alert_search_service
        self._incident_service = incident_service
        self._annotation_service = annotation_service
        self._behavior_service = behavior_query_service
        self._ecs = entity_correlation_service
        self._alert_manager = alert_manager
        self._alert_persistence = alert_persistence

    def get_timeline(
        self,
        entity_type: str,
        entity_id: str,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Build investigation timeline for an entity.

        Args:
            entity_type: Entity type (e.g., 'hostname', 'dst_ip').
            entity_id: Entity identifier.
            limit: Maximum number of timeline items to return.

        Returns:
            Dictionary with timeline items and metadata.
        """
        # Validate inputs
        entity_type = self._validate_entity_type(entity_type)
        entity_id = self._validate_entity_id(entity_id)
        limit = self._validate_limit(limit)

        # Collect evidence from all sources
        items: list[TimelineItem] = []
        seen_ids: set[str] = set()

        # 1. Alerts
        alert_items = self._collect_alert_items(entity_type, entity_id, seen_ids)
        items.extend(alert_items)

        # 2. Incidents (only when reliable timestamp exists)
        incident_items = self._collect_incident_items(entity_type, entity_id, seen_ids)
        items.extend(incident_items)

        # 3. Annotations
        annotation_items = self._collect_annotation_items(entity_type, entity_id, seen_ids)
        items.extend(annotation_items)

        # 4. Behavior (only when temporally defensible)
        behavior_items = self._collect_behavior_items(entity_type, entity_id, seen_ids)
        items.extend(behavior_items)

        # Sort: timestamp DESC, then deterministic tie-breakers
        items.sort(key=self._sort_key)

        # Apply limit
        truncated = len(items) > limit
        items = items[:limit]

        # Determine correlation status
        correlation_status, correlation_note = self._get_correlation_status(entity_type, entity_id)

        return {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "items": [item.to_dict() for item in items],
            "returned_count": len(items),
            "truncated": truncated,
            "correlation_status": correlation_status,
            "correlation_note": correlation_note,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _collect_alert_items(
        self,
        entity_type: str,
        entity_id: str,
        seen_ids: set[str],
    ) -> list[TimelineItem]:
        """Collect alert timeline items for an entity."""
        items = []

        try:
            # Use existing entity correlation to find observed keys
            observed_keys = self._get_observed_correlation_keys(entity_type, entity_id)

            for key in observed_keys:
                try:
                    result = self._alert_search.search(
                        limit=_MAX_ITEMS,
                        entity_key=key,
                    )
                    for alert in result.alerts:
                        item_id = str(alert.alert_id)
                        if item_id in seen_ids:
                            continue
                        seen_ids.add(item_id)

                        ts = alert.created_at
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=UTC)

                        items.append(
                            TimelineItem(
                                timeline_item_id=item_id,
                                timestamp=ts,
                                item_type=TimelineItemType.ALERT,
                                title=alert.title,
                                summary=alert.description[:_MAX_SUMMARY_LENGTH],
                                entity_type=entity_type,
                                entity_id=entity_id,
                                source_id=item_id,
                                severity_or_priority=alert.severity.name
                                if hasattr(alert.severity, "name")
                                else str(alert.severity),
                                metadata={
                                    "source": alert.source,
                                    "rule_id": alert.metadata.get("rule_id", "")[
                                        :_MAX_METADATA_VALUE_LENGTH
                                    ],
                                },
                            )
                        )
                except Exception as e:
                    logger.debug("Failed to search alerts for key %s: %s", key, e)
        except Exception as e:
            logger.debug("Failed to collect alert items: %s", e)

        return items

    def _collect_incident_items(
        self,
        entity_type: str,
        entity_id: str,
        seen_ids: set[str],
    ) -> list[TimelineItem]:
        """Collect incident timeline items for an entity.

        Only includes incidents when a reliable timestamp exists.
        """
        items = []

        try:
            observed_keys = self._get_observed_correlation_keys(entity_type, entity_id)

            for key in observed_keys:
                try:
                    incident_id = self._incident_service.get_incident_for_entity(key)
                    if incident_id is None:
                        continue
                    incident = self._incident_service.get_incident(incident_id)
                    if incident is None:
                        continue
                    item_id = str(incident.incident_id)
                    if item_id in seen_ids:
                        continue
                    seen_ids.add(item_id)

                    ts = incident.created_at
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=UTC)

                    items.append(
                        TimelineItem(
                            timeline_item_id=item_id,
                            timestamp=ts,
                            item_type=TimelineItemType.INCIDENT,
                            title=incident.title,
                            summary=incident.description[:_MAX_SUMMARY_LENGTH],
                            entity_type=entity_type,
                            entity_id=entity_id,
                            source_id=item_id,
                            severity_or_priority=incident.severity.name
                            if hasattr(incident.severity, "name")
                            else str(incident.severity),
                            metadata={},
                        )
                    )
                except Exception as e:
                    logger.debug("Failed to get incident for key %s: %s", key, e)
        except Exception as e:
            logger.debug("Failed to collect incident items: %s", e)

        return items

    def _collect_annotation_items(
        self,
        entity_type: str,
        entity_id: str,
        seen_ids: set[str],
    ) -> list[TimelineItem]:
        """Collect annotation timeline items for an entity."""
        items = []
        target_key = f"entity:{entity_type}:{entity_id}"

        try:
            annotations = self._annotation_service.get_annotations(target_key, limit=50)
            for ann in annotations:
                item_id = str(ann.annotation_id)
                if item_id in seen_ids:
                    continue
                seen_ids.add(item_id)

                ts = ann.created_at
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)

                items.append(
                    TimelineItem(
                        timeline_item_id=item_id,
                        timestamp=ts,
                        item_type=TimelineItemType.ANNOTATION,
                        title=f"Annotation by {ann.author}",
                        summary=ann.comment[:_MAX_SUMMARY_LENGTH],
                        entity_type=entity_type,
                        entity_id=entity_id,
                        source_id=item_id,
                        severity_or_priority=None,
                        metadata={
                            "author": ann.author[:_MAX_METADATA_VALUE_LENGTH],
                            "tombstoned": str(ann.tombstoned),
                        },
                    )
                )
        except Exception as e:
            logger.debug("Failed to collect annotation items: %s", e)

        return items

    def _collect_behavior_items(
        self,
        entity_type: str,
        entity_id: str,
        seen_ids: set[str],
    ) -> list[TimelineItem]:
        """Collect behavior timeline items for an entity.

        Only includes behavior when temporally defensible (has first_seen/last_seen).
        """
        items = []

        try:
            profiles = self._behavior_service.get_entity_behavior(entity_type, entity_id)
            for profile in profiles:
                first_seen = profile.get("first_seen")
                last_seen = profile.get("last_seen")

                # Only include if we have a reliable timestamp
                if not first_seen or not last_seen:
                    continue

                # Use last_seen as the timestamp (most recent observation)
                try:
                    ts = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    continue

                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)

                dim = profile.get("dimension", "unknown")
                item_id = f"behavior:{entity_type}:{entity_id}:{dim}"
                if item_id in seen_ids:
                    continue
                seen_ids.add(item_id)

                items.append(
                    TimelineItem(
                        timeline_item_id=item_id,
                        timestamp=ts,
                        item_type=TimelineItemType.BEHAVIOR,
                        title=f"Behavior: {dim}",
                        summary=f"Observations: {profile.get('observation_count', 0)}, "
                        f"Distinct values: {profile.get('distinct_value_count', 0)}, "
                        f"Maturity: {profile.get('maturity', 'unknown')}",
                        entity_type=entity_type,
                        entity_id=entity_id,
                        source_id=item_id,
                        severity_or_priority=None,
                        metadata={},
                    )
                )
        except Exception as e:
            logger.debug("Failed to collect behavior items: %s", e)

        return items

    def _get_observed_correlation_keys(
        self,
        entity_type: str,
        entity_id: str,
    ) -> list[str]:
        """Get observed correlation keys for an entity."""
        try:
            keys = self._ecs.get_observed_correlation_keys(entity_type, entity_id)
            return list(keys) if keys else []
        except Exception:
            return []

    def _get_correlation_status(
        self,
        entity_type: str,
        entity_id: str,
    ) -> tuple[str, str]:
        """Get correlation status and note for an entity."""
        try:
            status = self._ecs.get_correlation_status(entity_type, entity_id)
            note = self._ecs.get_correlation_note(entity_type, entity_id)
            return status, note
        except Exception:
            return "PARTIAL", "Correlation status unavailable."

    def _sort_key(self, item: TimelineItem) -> tuple:
        """Deterministic sort key: timestamp DESC, then stable tie-breakers."""
        return (
            -item.timestamp.timestamp(),  # DESC by timestamp
            item.item_type.value,  # Then by type
            item.source_id or "",  # Then by source
            item.timeline_item_id,  # Then by item ID
        )

    def _validate_entity_type(self, entity_type: str) -> str:
        """Validate entity type input."""
        if not isinstance(entity_type, str) or not _ENTITY_TYPE_PATTERN.match(entity_type):
            raise ValueError(f"Invalid entity_type: {entity_type!r}")
        if len(entity_type) > 64:
            raise ValueError(f"entity_type too long: {len(entity_type)} > 64")
        return entity_type

    def _validate_entity_id(self, entity_id: str) -> str:
        """Validate entity ID input."""
        if not isinstance(entity_id, str) or not _ENTITY_ID_PATTERN.match(entity_id):
            raise ValueError(f"Invalid entity_id: {entity_id!r}")
        if len(entity_id) > 256:
            raise ValueError(f"entity_id too long: {len(entity_id)} > 256")
        return entity_id

    def _validate_limit(self, limit: int) -> int:
        """Validate limit input."""
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ValueError(f"limit must be an integer, got {type(limit).__name__}")
        if limit <= 0:
            raise ValueError(f"limit must be positive, got {limit}")
        if limit > _MAX_LIMIT:
            return _MAX_LIMIT
        return limit
