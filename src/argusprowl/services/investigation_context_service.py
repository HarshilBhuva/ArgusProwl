"""Investigation context service for entity-centric evidence aggregation.

Provides a bounded, read-only operation that assembles existing evidence
about one entity for analyst investigation.

Phase 5.3 — Entity Investigation Context:
    - Single read-only operation: get_investigation_context()
    - Reuses existing services without duplication
    - Deterministic, bounded output
    - Read-only guarantee: no state modification
    - Missing evidence is not an error

Key semantic decisions:
    - Each evidence domain has its own entity-key format. The investigation
      context exposes both keys explicitly so callers know which domain
      each key belongs to.
    - AlertQueue.list_by_entity() uses the correlation key format.
    - AnalystAnnotationService uses the annotation target-key format.
    - IncidentService uses the correlation key format.
    - AnalystBehaviorQueryService uses (entity_type, entity_id) directly.
    - Source availability is reported per-source so analysts can distinguish
      "no evidence" from "evidence source unavailable".

Entity Type Support:
    - Alert/incident lookups: ONLY 'host' entity type is supported.
      This is because EntityCorrelationService.compute_entity_key() only
      produces valid correlation keys for host-based groupings.
      For other entity types, alerts/incidents return empty with AVAILABLE
      status (no alerts exist for that entity type in the correlation model).
    - Annotation lookups: ALL entity types are supported via entity:{type}:{id}.
    - Behavior lookups: ALL entity types are supported via (entity_type, entity_id).
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
from argusprowl.behavior.analyst_behavior_query_service import AnalystBehaviorQueryService
from argusprowl.incident.incident_service import IncidentNotFoundError, IncidentService
from argusprowl.lifecycle.queue import AlertQueue, AlertQueueError
from argusprowl.models.alert import Alert
from argusprowl.models.entity_investigation_context import (
    _MAX_ALERTS,
    _MAX_ANNOTATIONS,
    EntityInvestigationContext,
    SourceStatus,
)
from argusprowl.services.attck_investigation_context_service import AttckInvestigationContextService

if TYPE_CHECKING:
    from argusprowl.alerting.alert_persistence import AlertPersistence
    from argusprowl.models.incident import Incident

logger = logging.getLogger(__name__)

# Input validation bounds
_MAX_ENTITY_TYPE_LENGTH: int = 64
_MAX_ENTITY_ID_LENGTH: int = 256

# Valid entity type pattern (alphanumeric, underscores, hyphens, dots)
_ENTITY_TYPE_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

# Supported entity types for alert/incident correlation
# Only 'host' produces valid correlation keys via EntityCorrelationService.
# Other types (src_ip, dst_ip, user, process_name) cannot correctly query
# alerts/incidents because the correlation model is host-centric.
_ALERT_INCIDENT_SUPPORTED_TYPES: frozenset[str] = frozenset({"host"})


class InvestigationContextService:
    """Read-only service for assembling entity investigation context.

    This service provides a single bounded operation that aggregates evidence
    from multiple services for analyst investigation. It does not modify any
    source state and returns a deterministic, bounded snapshot.

    Reused Services:
        - AlertQueue: For recent alerts via list_by_entity (bounded to 50)
        - AnalystBehaviorQueryService: For behavioral profiles
        - AnalystAnnotationService: For analyst annotations (bounded to 20)
        - IncidentService: For associated incident (at most one)

    Failure Semantics:
        - Missing evidence is not an error. Returns valid empty context.
        - Expected absence (ValueError from validation) returns empty results.
        - Unexpected errors propagate as-is to the caller.
        - Each source independently reports its availability via source_status.

    Key Semantic Points:
        - alert correlation uses correlation key: host:* | host:process | host:dst_ip
        - annotation lookup uses annotation key: entity:type:id
        - These are different key formats from different domains. The context
          exposes both explicitly.

    Read-Only Guarantee:
        - No alerts are created, modified, or deleted
        - No behavior profiles are modified
        - No annotations are created or tombstoned
        - No incidents are created or modified
        - No caches or background state are modified
    """

    def __init__(
        self,
        alert_queue: AlertQueue,
        behavior_query_service: AnalystBehaviorQueryService,
        annotation_service: AnalystAnnotationService,
        incident_service: IncidentService,
        alert_persistence: AlertPersistence | None = None,
    ) -> None:
        """Initialize investigation context service.

        Args:
            alert_queue: AlertQueue for alert lookups.
            behavior_query_service: AnalystBehaviorQueryService for behavior.
            annotation_service: AnalystAnnotationService for annotations.
            incident_service: IncidentService for incident lookup.
            alert_persistence: Optional AlertPersistence for historical alerts.
        """
        self._alert_queue = alert_queue
        self._behavior_service = behavior_query_service
        self._annotation_service = annotation_service
        self._incident_service = incident_service
        self._alert_persistence = alert_persistence
        self._attck_service = AttckInvestigationContextService()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_investigation_context(
        self,
        entity_type: str,
        entity_id: str,
    ) -> EntityInvestigationContext:
        """Get bounded investigation context for one entity.

        This is the primary public capability. It assembles available evidence
        from multiple services into a single read-only snapshot.

        Supported Entity Types:
            - 'host': Full support for alerts, behavior, annotations, incident
            - Other types (src_ip, dst_ip, user, etc.): behavior and annotations only
              (alerts/incident lookups return empty because the correlation model
              is host-centric; returning fabricated correlation keys would be misleading)

        Args:
            entity_type: Type of entity (e.g., 'host', 'src_ip').
            entity_id: Unique identifier of the entity.

        Returns:
            EntityInvestigationContext with aggregated evidence.

        Raises:
            ValueError: If entity_type or entity_id is invalid.
        """
        # Validate inputs
        entity_type = self._validate_entity_type(entity_type)
        entity_id = self._validate_entity_id(entity_id)

        # Compute domain-specific keys
        annotation_key = f"entity:{entity_type}:{entity_id}"

        # Alerts/incidents only supported for host entities
        # For other types, correlation key would be fabricated and misleading
        supports_alert_incident = entity_type in _ALERT_INCIDENT_SUPPORTED_TYPES
        correlation_key = f"{entity_id}:*" if supports_alert_incident else ""

        # Query all sources independently; track per-source availability
        source_status: list[tuple[str, SourceStatus]] = []

        # Alerts: only query if entity type supports alert lookup
        if supports_alert_incident:
            alerts, alerts_status = self._get_alerts_for_entity(correlation_key)
        else:
            # Entity type not supported for alert correlation - return empty with UNSUPPORTED
            # Critical: no query performed != query performed successfully and found nothing
            alerts, alerts_status = [], SourceStatus.UNSUPPORTED
            logger.debug(
                "Alert lookup skipped for entity type '%s': "
                "only 'host' entity type supports alert correlation",
                entity_type,
            )
        source_status.append(("alerts", alerts_status))

        # Behavior: uses (entity_type, entity_id) directly
        behavior, behavior_status = self._get_behavior_for_entity(entity_type, entity_id)
        source_status.append(("behavior", behavior_status))

        # Annotations: use annotation key via annotation service
        annotations, annotations_status = self._get_annotations_for_entity(annotation_key)
        source_status.append(("annotations", annotations_status))

        # Incident: only query if entity type supports incident lookup
        if supports_alert_incident:
            incident, incident_status = self._get_incident_for_entity(correlation_key)
        else:
            # Entity type not supported for incident correlation - return empty with UNSUPPORTED
            # Critical: no query performed != query performed successfully and found nothing
            incident, incident_status = None, SourceStatus.UNSUPPORTED
            logger.debug(
                "Incident lookup skipped for entity type '%s': "
                "only 'host' entity type supports incident correlation",
                entity_type,
            )
        source_status.append(("incident", incident_status))

        return EntityInvestigationContext(
            entity_type=entity_type,
            entity_id=entity_id,
            annotation_key=annotation_key,
            correlation_key=correlation_key,
            recent_alerts=tuple(alerts),
            behavior_summary=tuple(behavior),
            annotations=tuple(annotations),
            incident=incident,
            attck_context=tuple(self._aggregate_attck_context(alerts)),
            source_status=tuple(source_status),
        )

    # ATT&CK Aggregation
    # ------------------------------------------------------------------

    def _aggregate_attck_context(
        self,
        alerts: list[Alert],
    ) -> tuple:
        """Aggregate ATT&CK observations from alerts into technique summaries.

        This is a read-only operation that derives ATT&CK context from
        observations already present on the Alert objects. It does not
        perform a second alert scan, network access, or invoke enrichment.

        Args:
            alerts: List of alerts to aggregate ATT&CK observations from.

        Returns:
            Tuple of AttckTechniqueSummary instances.
        """
        try:
            return self._attck_service.aggregate(tuple(alerts))
        except Exception as exc:
            logger.warning(
                "ATT&CK aggregation failed for %d alerts: %s",
                len(alerts),
                exc,
            )
            return ()

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # Input Validation
    # ------------------------------------------------------------------

    def _validate_entity_type(self, entity_type: str) -> str:
        """Validate entity_type parameter.

        Args:
            entity_type: The entity type to validate.

        Returns:
            Validated entity_type.

        Raises:
            ValueError: If validation fails.
        """
        if not isinstance(entity_type, str):
            raise ValueError("entity_type must be a string.")
        if not entity_type:
            raise ValueError("entity_type must not be empty.")
        if len(entity_type) > _MAX_ENTITY_TYPE_LENGTH:
            raise ValueError(f"entity_type exceeds maximum length of {_MAX_ENTITY_TYPE_LENGTH}.")
        # Validate against pattern
        if not _ENTITY_TYPE_PATTERN.match(entity_type):
            raise ValueError(
                "entity_type must contain only alphanumeric characters, "
                "underscores, hyphens, and dots."
            )
        return entity_type.lower()

    def _validate_entity_id(self, entity_id: str) -> str:
        """Validate entity_id parameter.

        Args:
            entity_id: The entity ID to validate.

        Returns:
            Validated entity_id.

        Raises:
            ValueError: If validation fails.
        """
        if not isinstance(entity_id, str):
            raise ValueError("entity_id must be a string.")
        if not entity_id:
            raise ValueError("entity_id must not be empty.")
        if len(entity_id) > _MAX_ENTITY_ID_LENGTH:
            raise ValueError(f"entity_id exceeds maximum length of {_MAX_ENTITY_ID_LENGTH}.")
        return entity_id

    # ------------------------------------------------------------------
    # Alert Lookup
    # ------------------------------------------------------------------

    def _get_alerts_for_entity(
        self,
        correlation_key: str,
    ) -> tuple[list[Alert], SourceStatus]:
        """Get recent alerts for an entity using correlation key.

        Queries both AlertQueue (in-memory) and AlertPersistence (historical)
        and deduplicates by alert_id.

        Source failure semantics:
            - AlertQueueError (queue full, not found, corrupted): UNAVAILABLE
            - AlertPersistence failures: logged, status reflects persistence state
            - Unexpected errors (RuntimeError, etc.): propagate

        Args:
            correlation_key: Correlation-format entity key (e.g., 'host:*').

        Returns:
            Tuple of (list of alerts, source status).
        """
        try:
            queue_alerts = self._alert_queue.list_by_entity(correlation_key, sort=True)
            queue_failed = False
        except AlertQueueError as exc:
            logger.warning(
                "AlertQueue source failure for entity '%s': %s",
                correlation_key,
                exc,
            )
            queue_alerts = []
            queue_failed = True

        persistence_alerts: list[Alert] = []
        persistence_status = SourceStatus.AVAILABLE

        if self._alert_persistence is not None:
            try:
                result = self._alert_persistence.list_by_entity(correlation_key, limit=_MAX_ALERTS)
                persistence_alerts = list(result.alerts)
                # Map persistence status to SourceStatus
                from argusprowl.alerting.alert_persistence import AlertPersistenceStatus

                if result.status == AlertPersistenceStatus.UNAVAILABLE:
                    persistence_status = SourceStatus.UNAVAILABLE
                elif result.status == AlertPersistenceStatus.DEGRADED:
                    persistence_status = SourceStatus.DEGRADED
                else:
                    persistence_status = SourceStatus.AVAILABLE
            except Exception as exc:
                logger.warning(
                    "AlertPersistence source failure for entity '%s': %s",
                    correlation_key,
                    exc,
                )
                persistence_status = SourceStatus.UNAVAILABLE
                persistence_alerts = []
        else:
            # No persistence layer configured - if queue failed, status is UNAVAILABLE
            if queue_failed:
                persistence_status = SourceStatus.UNAVAILABLE

        # Deduplicate by alert_id, preferring queue alerts (most recent state)
        seen_ids: set[str] = set()
        all_alerts: list[Alert] = []

        for alert in queue_alerts:
            alert_id_str = str(alert.alert_id)
            if alert_id_str not in seen_ids:
                seen_ids.add(alert_id_str)
                all_alerts.append(alert)

        for alert in persistence_alerts:
            alert_id_str = str(alert.alert_id)
            if alert_id_str not in seen_ids:
                seen_ids.add(alert_id_str)
                all_alerts.append(alert)

        # Determine overall status
        if queue_failed:
            if persistence_status == SourceStatus.DEGRADED:
                overall_status = SourceStatus.DEGRADED
            else:
                overall_status = SourceStatus.UNAVAILABLE
        elif persistence_status == SourceStatus.UNAVAILABLE:
            overall_status = SourceStatus.UNAVAILABLE
        elif persistence_status == SourceStatus.DEGRADED:
            overall_status = SourceStatus.DEGRADED
        else:
            overall_status = SourceStatus.AVAILABLE

        return all_alerts[:_MAX_ALERTS], overall_status

    # ------------------------------------------------------------------
    # Behavior Lookup
    # ------------------------------------------------------------------

    def _get_behavior_for_entity(
        self,
        entity_type: str,
        entity_id: str,
    ) -> tuple[list[dict[str, Any]], SourceStatus]:
        """Get behavioral summary for an entity.

        Reuses AnalystBehaviorQueryService which provides bounded output.

        Source failure semantics:
            - ValueError (invalid input): propagate immediately (caller error)
            - Unexpected errors: propagate

        Note: AnalystBehaviorQueryService only raises ValueError for input
        validation. No other recoverable error types exist, so any exception
        is a programming error that should propagate.

        Args:
            entity_type: Entity type.
            entity_id: Entity ID.

        Returns:
            Tuple of (list of behavior summaries, source status).
        """
        try:
            behavior = self._behavior_service.get_entity_behavior(
                entity_type=entity_type,
                entity_id=entity_id,
            )
            return behavior, SourceStatus.AVAILABLE
        except ValueError:
            # Input validation errors from service should propagate to caller
            raise
        except Exception as exc:
            # Unexpected errors from behavior service propagate
            logger.warning(
                "Unexpected error from behavior service for %s:%s: %s",
                entity_type,
                entity_id,
                exc,
            )
            raise

    # ------------------------------------------------------------------
    # Annotation Lookup
    # ------------------------------------------------------------------

    def _get_annotations_for_entity(
        self,
        annotation_key: str,
    ) -> tuple[list[dict[str, Any]], SourceStatus]:
        """Get annotations for an entity.

        Reuses AnalystAnnotationService with bounded output.

        Source failure semantics:
            - ValueError (invalid input): propagate immediately (caller error)
            - RuntimeError (annotation limit exceeded): UNAVAILABLE
            - Unexpected errors: propagate

        Note: AnalystAnnotationService catches internal exceptions and only
        propagates ValueError (input validation) or RuntimeError (capacity).
        Any other exception indicates a programming error.

        Args:
            annotation_key: Annotation target key (entity:{type}:{id}).

        Returns:
            Tuple of (list of annotation dicts, source status).
        """
        try:
            annotations = self._annotation_service.get_annotations_by_target(
                target_key=annotation_key,
                include_tombstoned=False,
                limit=_MAX_ANNOTATIONS,
            )
            return annotations[:_MAX_ANNOTATIONS], SourceStatus.AVAILABLE
        except ValueError:
            # Input validation errors from service should propagate to caller
            raise
        except RuntimeError as exc:
            # Capacity/limit errors are recoverable source failures
            logger.warning(
                "Annotation service capacity error for target '%s': %s",
                annotation_key,
                exc,
            )
            return [], SourceStatus.UNAVAILABLE
        except Exception as exc:
            # Unexpected errors propagate
            logger.warning(
                "Unexpected error from annotation service for target '%s': %s",
                annotation_key,
                exc,
            )
            raise

    # ------------------------------------------------------------------
    # Incident Lookup
    # ------------------------------------------------------------------

    def _get_incident_for_entity(
        self,
        correlation_key: str,
    ) -> tuple[Incident | None, SourceStatus]:
        """Get incident for an entity using correlation key.

        Uses IncidentService.get_incident_for_entity() which stores incidents
        indexed by the correlation key format (host:* | host:process | etc.).

        Source failure semantics:
            - IncidentNotFoundError (not a failure, just absent): AVAILABLE
            - Unexpected errors: propagate

        Args:
            correlation_key: Correlation-format entity key.

        Returns:
            Tuple of (incident or None, source status).
        """
        try:
            incident_id = self._incident_service.get_incident_for_entity(correlation_key)
            if incident_id is None:
                return None, SourceStatus.AVAILABLE

            incident = self._incident_service.get_incident(incident_id)
            return incident, SourceStatus.AVAILABLE
        except IncidentNotFoundError:
            # Incident not found is expected absence, not a source failure
            return None, SourceStatus.AVAILABLE
        except Exception as exc:
            # Unexpected errors from incident service propagate
            logger.warning(
                "Unexpected error from incident service for entity '%s': %s",
                correlation_key,
                exc,
            )
            raise


__all__ = [
    "InvestigationContextService",
]
