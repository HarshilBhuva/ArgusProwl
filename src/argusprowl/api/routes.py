"""API routes for the HTTP layer.

Thin API layer that delegates to existing ArgusProwl services.
The API layer MUST NOT implement detection, correlation, or security decisions.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from argusprowl.alerting.alert_manager import AlertManager
from argusprowl.alerting.alert_persistence import AlertPersistence
from argusprowl.api.response_models import (
    AlertResponse,
    AlertSearchResponse,
    AnnotationCreateRequest,
    AnnotationResponse,
    AttckInvestigationResponse,
    AttckMappingResponse,
    AttckOverviewResponse,
    AttckTechniqueSummaryResponse,
    EntityDetailResponse,
    EntityItemResponse,
    EntityListResponse,
    EvidenceDetailResponse,
    EvidenceEventResponse,
    EvidenceRecordResponse,
    EvidenceSearchResponse,
    EvidenceStatsResponse,
    HealthComponent,
    HealthResponse,
    IncidentListResponse,
    IncidentResponse,
    IocInvestigationResponse,
    IocObservationResponse,
    IocTimelineItemResponse,
    LifecycleActionResponse,
    MetricItem,
    MetricsResponse,
    RelatedIocResponse,
    RuleDetailResponse,
    RuleItemResponse,
    RuleListResponse,
    TimelineResponse,
)
from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.lifecycle.queue import AlertQueue

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["argusprowl API"])

# Operational health endpoint (no prefix, for compatibility)
operational_router = APIRouter(tags=["Operational"])


def _build_health_response(status) -> HealthResponse:
    """Build a structured health response from SystemStatus."""
    from argusprowl.models.system_status import SystemStatus

    if not isinstance(status, SystemStatus):
        # Fallback for unexpected types
        return HealthResponse(
            status="unhealthy",
            version="unknown",
            uptime_seconds=0.0,
            checked_at=datetime.now(UTC),
            components=[],
        )

    components = [
        HealthComponent(
            name=comp.name,
            status=comp.status.value if hasattr(comp.status, "value") else str(comp.status),
            message=comp.message,
        )
        for comp in status.components
    ]

    return HealthResponse(
        status=status.status.value if hasattr(status.status, "value") else str(status.status),
        version=status.version,
        uptime_seconds=status.uptime_seconds,
        checked_at=status.checked_at,
        components=components,
    )


def _build_metrics_response(snapshot) -> MetricsResponse:
    """Build a structured metrics response from MetricsSnapshot."""
    from argusprowl.models.metrics_snapshot import MetricsSnapshot

    if not isinstance(snapshot, MetricsSnapshot):
        return MetricsResponse(
            uptime_seconds=0.0,
            captured_at=datetime.now(UTC),
            metrics=[],
        )

    metrics = []
    for name, metric_data in snapshot.metrics.items():
        if isinstance(metric_data, dict):
            metrics.append(
                MetricItem(
                    name=name,
                    description=metric_data.get("description", ""),
                    value=metric_data.get("value", 0),
                )
            )
        else:
            metrics.append(MetricItem(name=name, value=metric_data))

    return MetricsResponse(
        uptime_seconds=snapshot.uptime_seconds,
        captured_at=snapshot.captured_at,
        metrics=metrics,
    )


def _build_alert_response(alert) -> AlertResponse:
    """Build an AlertResponse from an Alert domain object."""
    from argusprowl.models.alert import Alert

    if not isinstance(alert, Alert):
        # Fallback for unexpected types
        return AlertResponse(
            alert_id="unknown",
            title="Unknown",
            description="Invalid alert object",
            severity="INFO",
            lifecycle_state="OPEN",
            source="unknown",
            created_at="",
        )

    return AlertResponse(
        alert_id=str(alert.alert_id),
        title=alert.title,
        description=alert.description,
        severity=alert.severity.name if hasattr(alert.severity, "name") else str(alert.severity),
        priority=alert.priority.value if alert.priority else None,
        lifecycle_state=alert.lifecycle_state.value
        if hasattr(alert.lifecycle_state, "value")
        else str(alert.lifecycle_state),
        source=alert.source,
        created_at=alert.created_at.isoformat(),
        tags=list(alert.tags),
        metadata=dict(alert.metadata),
        schema_version=alert.schema_version,
        assessment_id=str(alert.assessment_id) if alert.assessment_id else None,
        detector_confidence=alert.detector_confidence,
        contextual_confidence=alert.contextual_confidence,
        contextual_explanation=alert.contextual_explanation,
        supporting_evidence=list(alert.supporting_evidence),
        contradictory_evidence=list(alert.contradictory_evidence),
        investigation_pivots=list(alert.investigation_pivots),
        entity_context=dict(alert.entity_context) if alert.entity_context else None,
        incident_id=str(alert.incident_id) if alert.incident_id else None,
        detection_source_event_id=str(alert.detection_source_event_id)
        if alert.detection_source_event_id
        else None,
        contributing_event_ids=[str(eid) for eid in alert.contributing_event_ids],
        contributing_event_status=_resolve_contributing_event_status(alert.contributing_event_ids),
    )


def _resolve_contributing_event_status(
    contributing_event_ids: tuple[UUID, ...],
) -> dict[str, str]:
    """Resolve per-event availability status from the evidence store.

    Returns a mapping from event ID string to 'AVAILABLE' or 'EVICTED'.
    Never fabricates telemetry; only reports what the evidence store knows.
    """
    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService

    status: dict[str, str] = {}
    if not contributing_event_ids:
        return status

    container = ServiceContainer.get_instance()
    if not container.is_registered(TelemetryEvidenceService):
        return status

    try:
        evidence_service = container.resolve(TelemetryEvidenceService)
        resolved = evidence_service.resolve_referenced_status(contributing_event_ids)
        return {str(eid): value for eid, value in resolved.items()}
    except Exception:
        # Evidence service failures must never break alert projection.
        pass

    return status


# ---------------------------------------------------------------------------
# Incident endpoints
# ---------------------------------------------------------------------------


def _build_incident_response(incident) -> IncidentResponse:
    """Build an IncidentResponse from an Incident domain object."""
    from argusprowl.models.incident import Incident

    if not isinstance(incident, Incident):
        return IncidentResponse(
            incident_id="unknown",
            title="Unknown",
            description="Invalid incident object",
            severity="INFO",
            status="open",
            created_at="",
            updated_at="",
        )

    return IncidentResponse(
        incident_id=str(incident.incident_id),
        title=incident.title,
        description=incident.description,
        severity=incident.severity.name
        if hasattr(incident.severity, "name")
        else str(incident.severity),
        status=incident.status.value if hasattr(incident.status, "value") else str(incident.status),
        created_at=incident.created_at.isoformat(),
        updated_at=incident.updated_at.isoformat(),
        alert_ids=list(map(str, incident.alert_ids)),
        tags=list(incident.tags),
        metadata=dict(incident.metadata),
    )


@router.get("/incidents", summary="List incidents", response_model=IncidentListResponse)
async def list_incidents(
    status: str | None = Query(None, description="Filter by incident status."),
    severity: str | None = Query(None, description="Filter by severity."),
) -> IncidentListResponse:
    """List incidents with optional filters."""
    from argusprowl.constants.severity import Severity
    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.incident.incident_service import IncidentService
    from argusprowl.models.incident import IncidentStatus

    container = ServiceContainer.get_instance()
    if not container.is_registered(IncidentService):
        raise HTTPException(status_code=503, detail="Incident service not available")

    service = container.resolve(IncidentService)

    # Parse filters
    parsed_status = None
    if status:
        try:
            parsed_status = IncidentStatus(status)
        except ValueError:
            return JSONResponse(
                content={
                    "detail": f"Invalid status. Valid values: {', '.join(s.value for s in IncidentStatus)}"
                },
                status_code=422,
            )

    parsed_severity = None
    if severity:
        try:
            parsed_severity = Severity.from_string(severity)
        except ValueError:
            return JSONResponse(
                content={
                    "detail": f"Invalid severity. Valid values: {', '.join(s.name for s in Severity)}"
                },
                status_code=422,
            )

    incidents = service.list_incidents(status=parsed_status, severity=parsed_severity)
    responses = [_build_incident_response(inc) for inc in incidents]

    return IncidentListResponse(
        incidents=responses,
        total_count=len(responses),
    )


@router.get(
    "/incidents/{incident_id}", summary="Get incident detail", response_model=IncidentResponse
)
async def get_incident_detail(incident_id: str) -> IncidentResponse:
    """Get detailed information for a single incident."""
    import uuid

    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.incident.incident_service import IncidentService

    try:
        parsed_id = uuid.UUID(incident_id)
    except (ValueError, AttributeError) as err:
        raise HTTPException(status_code=404, detail="Incident not found") from err

    container = ServiceContainer.get_instance()
    if not container.is_registered(IncidentService):
        raise HTTPException(status_code=503, detail="Incident service not available")

    service = container.resolve(IncidentService)
    incident = service.get_incident(parsed_id)

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    return _build_incident_response(incident)


@router.get("/incidents/{incident_id}/alerts", summary="Get constituent alerts for incident")
async def get_incident_alerts(incident_id: str) -> dict[str, Any]:
    """Get constituent alerts for an incident through AlertSearchService.

    Returns bounded alert data with explicit degraded state if alerts
    cannot be fully retrieved.
    """
    import uuid

    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.incident.incident_service import IncidentService
    from argusprowl.services.alert_search_service import AlertSearchService

    try:
        parsed_id = uuid.UUID(incident_id)
    except (ValueError, AttributeError) as err:
        raise HTTPException(status_code=404, detail="Incident not found") from err

    container = ServiceContainer.get_instance()
    if not container.is_registered(IncidentService):
        raise HTTPException(status_code=503, detail="Incident service not available")

    service = container.resolve(IncidentService)
    incident = service.get_incident(parsed_id)

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Retrieve constituent alerts through AlertSearchService
    alerts_data: list[dict[str, Any]] = []
    missing_count = 0
    degraded = False

    if container.is_registered(AlertSearchService):
        search_service = container.resolve(AlertSearchService)
        for alert_id in incident.alert_ids:
            try:
                alert = search_service.get_alert(alert_id)
                if alert is not None:
                    alerts_data.append(_build_alert_response(alert).model_dump())
                else:
                    missing_count += 1
            except (ValueError, AttributeError):
                missing_count += 1
    else:
        degraded = True

    return {
        "incident_id": str(incident.incident_id),
        "total_alerts": len(incident.alert_ids),
        "retrieved_count": len(alerts_data),
        "missing_count": missing_count,
        "degraded": degraded or missing_count > 0,
        "alerts": alerts_data,
    }


@router.get("/incidents/{incident_id}/timeline", summary="Get incident investigation timeline")
async def get_incident_timeline(
    incident_id: str,
    limit: int = Query(50, ge=1, le=100, description="Maximum timeline items to return."),
) -> dict[str, Any]:
    """Get investigation timeline for an incident by extracting entity keys from constituent alerts."""
    import uuid

    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.incident.incident_service import IncidentService
    from argusprowl.services.investigation_timeline_service import InvestigationTimelineService

    try:
        parsed_id = uuid.UUID(incident_id)
    except (ValueError, AttributeError) as err:
        raise HTTPException(status_code=404, detail="Incident not found") from err

    container = ServiceContainer.get_instance()
    if not container.is_registered(IncidentService):
        raise HTTPException(status_code=503, detail="Incident service not available")

    service = container.resolve(IncidentService)
    incident = service.get_incident(parsed_id)

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Extract host entities from constituent alerts
    host_entities: set[str] = set()

    # Search AlertQueue (in-memory) first, then fall back to AlertPersistence
    # We avoid AlertSearchService here because it only supports bulk search, not single lookup.
    for alert_uuid in incident.alert_ids[:20]:  # Bound to 20 alerts for timeline
        alert = None
        if container.is_registered(AlertQueue):
            try:
                alert_queue = container.resolve(AlertQueue)
                alert = alert_queue.get(alert_uuid)
            except Exception:
                pass
        if alert is None and container.is_registered(AlertPersistence):
            try:
                alert_persistence = container.resolve(AlertPersistence)
                alert = alert_persistence.load_alert(alert_uuid)
            except Exception:
                pass
        if alert and alert.entity_context and alert.entity_context.get("host"):
            host_entities.add(alert.entity_context["host"])

    if not host_entities:
        return {
            "incident_id": str(incident.incident_id),
            "items": [],
            "returned_count": 0,
            "truncated": False,
            "correlation_status": "EMPTY",
            "correlation_note": "No host entities found in constituent alerts.",
        }

    # Use first host entity for timeline (incidents are host-centric)
    primary_host = sorted(host_entities)[0]

    if container.is_registered(InvestigationTimelineService):
        try:
            timeline_service = container.resolve(InvestigationTimelineService)
            result = timeline_service.get_timeline("hostname", primary_host, limit=limit)
            return {
                "incident_id": str(incident.incident_id),
                "primary_entity": f"hostname:{primary_host}",
                **result,
            }
        except Exception as exc:
            logger.warning("Failed to build incident timeline: %s", exc)

    return {
        "incident_id": str(incident.incident_id),
        "primary_entity": f"hostname:{primary_host}",
        "items": [],
        "returned_count": 0,
        "truncated": False,
        "correlation_status": "DEGRADED",
        "correlation_note": "Timeline service unavailable.",
    }


@router.get("/incidents/{incident_id}/annotations", summary="Get incident annotations")
async def get_incident_annotations(incident_id: str) -> list[AnnotationResponse]:
    """Get annotations for an incident."""
    import uuid

    from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.incident.incident_service import IncidentService

    try:
        parsed_id = uuid.UUID(incident_id)
    except (ValueError, AttributeError) as err:
        raise HTTPException(status_code=404, detail="Incident not found") from err

    container = ServiceContainer.get_instance()
    if not container.is_registered(IncidentService):
        raise HTTPException(status_code=503, detail="Incident service not available")

    service = container.resolve(IncidentService)
    incident = service.get_incident(parsed_id)

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    if not container.is_registered(AnalystAnnotationService):
        return []

    ann_service = container.resolve(AnalystAnnotationService)
    target_key = f"entity:incident:{incident.incident_id!s}"

    try:
        raw_anns = ann_service.get_annotations_by_target(target_key)
        return [
            AnnotationResponse(
                annotation_id=a["annotation_id"],
                target_key=a["target_key"],
                author=a["author"],
                created_at=a["created_at"],
                comment=a["comment"],
                tombstoned=a["tombstoned"],
            )
            for a in raw_anns
        ]
    except Exception as exc:
        logger.warning("Failed to fetch incident annotations: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@router.post("/incidents/{incident_id}/annotations", summary="Create incident annotation")
async def create_incident_annotation(
    incident_id: str,
    body: AnnotationCreateRequest,
) -> AnnotationResponse:
    """Create a new annotation for an incident."""
    import uuid

    from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.incident.incident_service import IncidentService

    try:
        parsed_id = uuid.UUID(incident_id)
    except (ValueError, AttributeError) as err:
        raise HTTPException(status_code=404, detail="Incident not found") from err

    container = ServiceContainer.get_instance()
    if not container.is_registered(IncidentService):
        raise HTTPException(status_code=503, detail="Incident service not available")

    service = container.resolve(IncidentService)
    incident = service.get_incident(parsed_id)

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    if not container.is_registered(AnalystAnnotationService):
        raise HTTPException(status_code=503, detail="Annotation service not available")

    ann_service = container.resolve(AnalystAnnotationService)
    target_key = f"entity:incident:{incident.incident_id!s}"

    try:
        created = ann_service.create_annotation(
            target_key=target_key,
            author=body.author,
            comment=body.comment,
        )
        return AnnotationResponse(
            annotation_id=str(created.annotation_id),
            target_key=created.target_key,
            author=created.author,
            created_at=created.created_at.isoformat(),
            comment=created.comment,
            tombstoned=created.tombstoned,
        )
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err
    except RuntimeError as err:
        raise HTTPException(status_code=422, detail=str(err)) from err
    except Exception as err:
        logger.warning("Failed to create incident annotation: %s", err)
        raise HTTPException(status_code=500, detail="Internal server error") from err


@router.post(
    "/incidents/{incident_id}/close",
    summary="Close an incident",
    response_model=LifecycleActionResponse,
)
async def close_incident(incident_id: str) -> LifecycleActionResponse:
    """Close an incident (marks status as CLOSED)."""
    import uuid

    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.incident.incident_service import IncidentService
    from argusprowl.models.incident import IncidentStatus

    try:
        parsed_id = uuid.UUID(incident_id)
    except (ValueError, AttributeError) as err:
        raise HTTPException(status_code=404, detail="Incident not found") from err

    container = ServiceContainer.get_instance()
    if not container.is_registered(IncidentService):
        raise HTTPException(status_code=503, detail="Incident service not available")

    service = container.resolve(IncidentService)
    incident = service.get_incident(parsed_id)

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    previous_state = incident.status.value

    try:
        updated_incident = service.update_status(parsed_id, IncidentStatus.CLOSED)
    except Exception as err:
        if isinstance(err, HTTPException):
            raise
        raise HTTPException(status_code=400, detail=str(err)) from err

    return LifecycleActionResponse(
        alert_id=str(updated_incident.incident_id),
        previous_state=previous_state,
        current_state=updated_incident.status.value,
    )


@router.post(
    "/incidents/{incident_id}/transition",
    summary="Transition incident status",
    response_model=LifecycleActionResponse,
)
async def transition_incident(
    incident_id: str, status: str = Query(..., description="The target status for the transition")
) -> LifecycleActionResponse:
    """Update incident status with authoritative lifecycle validation."""
    import uuid

    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.incident.incident_service import IncidentService
    from argusprowl.models.incident import IncidentStatus

    try:
        parsed_id = uuid.UUID(incident_id)
    except (ValueError, AttributeError) as err:
        raise HTTPException(status_code=404, detail="Incident not found") from err

    try:
        target_status = IncidentStatus(status)
    except ValueError as err:
        raise HTTPException(status_code=422, detail=f"Invalid status value: {status}") from err

    container = ServiceContainer.get_instance()
    if not container.is_registered(IncidentService):
        raise HTTPException(status_code=503, detail="Incident service not available")

    service = container.resolve(IncidentService)
    incident = service.get_incident(parsed_id)

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    previous_state = incident.status.value

    try:
        updated_incident = service.update_status(parsed_id, target_status)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err)) from err

    return LifecycleActionResponse(
        alert_id=str(updated_incident.incident_id),
        previous_state=previous_state,
        current_state=updated_incident.status.value,
    )


# ---------------------------------------------------------------------------


@router.get("/health", summary="System health check", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return system health status.

    Exposes existing HealthService without duplicating health logic.
    Returns structured status without leaking internal details.
    """
    try:
        from argusprowl.dependency_injection.container import ServiceContainer
        from argusprowl.services.health_service import HealthService

        container = ServiceContainer.get_instance()
        if container.is_registered(HealthService):
            health_service = container.resolve(HealthService)
            status = health_service.check_health()
            return _build_health_response(status)
        else:
            # Service not registered (e.g., application not started)
            return JSONResponse(
                content={
                    "status": "unhealthy",
                    "version": "unknown",
                    "uptime_seconds": 0.0,
                    "checked_at": "",
                    "components": [],
                },
                status_code=503,
            )
    except Exception as exc:
        logger.warning("Health check failed: %s", exc)
        return JSONResponse(
            content={
                "status": "unhealthy",
                "version": "unknown",
                "uptime_seconds": 0.0,
                "checked_at": "",
                "components": [],
            },
            status_code=503,
        )


# ---------------------------------------------------------------------------
# Operational Health endpoint (no prefix)
# ---------------------------------------------------------------------------


@operational_router.get("/health", summary="Operational health check")
async def operational_health_check() -> JSONResponse:
    """Return system health status at operational root path.

    Provides operational compatibility endpoint without API version prefix.
    """
    try:
        from argusprowl.dependency_injection.container import ServiceContainer
        from argusprowl.services.health_service import HealthService

        container = ServiceContainer.get_instance()
        if container.is_registered(HealthService):
            health_service = container.resolve(HealthService)
            status = health_service.check_health()
            response = _build_health_response(status)
            return JSONResponse(content=response.model_dump(mode="json"), status_code=200)
        else:
            return JSONResponse(
                content={
                    "status": "unhealthy",
                    "version": "unknown",
                    "uptime_seconds": 0.0,
                    "checked_at": "",
                    "components": [],
                },
                status_code=503,
            )
    except Exception as exc:
        logger.warning("Operational health check failed: %s", exc)
        return JSONResponse(
            content={
                "status": "unhealthy",
                "version": "unknown",
                "uptime_seconds": 0.0,
                "checked_at": "",
                "components": [],
            },
            status_code=503,
        )


# ---------------------------------------------------------------------------
# Alert detail endpoint
# ---------------------------------------------------------------------------


@router.get("/alerts/{alert_id}", summary="Get alert detail", response_model=AlertResponse)
async def get_alert_detail(alert_id: str) -> AlertResponse:
    """Get detailed information for a single alert.

    Lookup semantics:
    1. Search AlertQueue (in-memory) first
    2. Fall back to AlertPersistence if persistence is enabled
    3. Return 404 if not found in either

    Args:
        alert_id: The alert ID to look up (as string).
    """
    import uuid

    from argusprowl.dependency_injection.container import ServiceContainer

    # Validate UUID format
    try:
        parsed_alert_id = uuid.UUID(alert_id)
    except (ValueError, AttributeError) as err:
        raise HTTPException(status_code=404, detail="Alert not found") from err

    container = ServiceContainer.get_instance()
    alert = None

    # 1. Check queue first
    if container.is_registered(AlertQueue):
        try:
            alert_queue = container.resolve(AlertQueue)
            alert = alert_queue.get(parsed_alert_id)
        except Exception:
            pass

    # 2. Fall back to persistence
    if alert is None and container.is_registered(AlertPersistence):
        try:
            alert_persistence = container.resolve(AlertPersistence)
            alert = alert_persistence.load_alert(parsed_alert_id)
        except Exception:
            pass

    # 3. Return 404 if not found
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Build and return response
    response = _build_alert_response(alert)
    # Ensure alert_id is included in response
    response.alert_id = str(alert.alert_id)
    return response


# ---------------------------------------------------------------------------
# Lifecycle action endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/alerts/{alert_id}/acknowledge",
    summary="Acknowledge an alert",
    response_model=LifecycleActionResponse,
)
async def acknowledge_alert(alert_id: str) -> LifecycleActionResponse:
    """Acknowledge an alert (OPEN -> ACKNOWLEDGED).

    Args:
        alert_id: The alert ID to acknowledge.
    """
    import uuid

    from argusprowl.dependency_injection.container import ServiceContainer

    # Validate UUID format
    try:
        parsed_alert_id = uuid.UUID(alert_id)
    except (ValueError, AttributeError) as err:
        raise HTTPException(status_code=404, detail="Alert not found") from err

    container = ServiceContainer.get_instance()

    # Resolve AlertManager
    if not container.is_registered(AlertManager):
        raise HTTPException(status_code=503, detail="Alert manager not available")

    alert_manager = container.resolve(AlertManager)

    try:
        # Get the current alert to preserve its state
        # We need to find it in the queue first
        if not container.is_registered(AlertQueue):
            raise HTTPException(status_code=503, detail="Alert queue not available")

        alert_queue = container.resolve(AlertQueue)
        existing_alert = alert_queue.get(parsed_alert_id)

        if existing_alert is None:
            # Check persistence as fallback
            if container.is_registered(AlertPersistence):
                alert_persistence = container.resolve(AlertPersistence)
                existing_alert = alert_persistence.load_alert(parsed_alert_id)

            if existing_alert is None:
                raise HTTPException(status_code=404, detail="Alert not found")

        previous_state = existing_alert.lifecycle_state.value

        # Dry-run the transition to validate it before touching persistence.
        # Raises ValueError for invalid transitions (e.g. ACKNOWLEDGED -> ACKNOWLEDGED).
        from argusprowl.lifecycle.transition import transition_lifecycle

        try:
            updated_alert = transition_lifecycle(existing_alert, AlertLifecycleState.ACKNOWLEDGED)
        except ValueError as exc:
            raise HTTPException(
                status_code=409, detail="Invalid alert lifecycle transition"
            ) from exc

        # Persist first so a failed HTTP request never leaves an unexplained
        # in-memory mutation behind a failed request.
        if container.is_registered(AlertPersistence):
            alert_persistence = container.resolve(AlertPersistence)
            try:
                success = alert_persistence.update_lifecycle(
                    parsed_alert_id, AlertLifecycleState.ACKNOWLEDGED.value
                )
            except Exception as exc:
                logger.warning("Error persisting lifecycle update for alert %s: %s", alert_id, exc)
                raise HTTPException(
                    status_code=503,
                    detail="Failed to persist lifecycle update",
                ) from exc
            if not success:
                logger.warning("Failed to persist lifecycle update for alert %s", alert_id)
                raise HTTPException(
                    status_code=503,
                    detail="Failed to persist lifecycle update",
                )

        if alert_queue.get(parsed_alert_id) is not None:
            updated_alert = alert_manager.acknowledge_alert(parsed_alert_id)

        return LifecycleActionResponse(
            alert_id=str(updated_alert.alert_id),
            previous_state=previous_state,
            current_state=updated_alert.lifecycle_state.value,
        )
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise
        logger.warning("Failed to acknowledge alert %s: %s", alert_id, exc)
        raise HTTPException(status_code=500, detail="Failed to acknowledge alert") from exc


@router.post(
    "/alerts/{alert_id}/close", summary="Close an alert", response_model=LifecycleActionResponse
)
async def close_alert(alert_id: str) -> LifecycleActionResponse:
    """Close an alert (OPEN -> CLOSED or ACKNOWLEDGED -> CLOSED).

    Args:
        alert_id: The alert ID to close.
    """
    import uuid

    from argusprowl.dependency_injection.container import ServiceContainer

    # Validate UUID format
    try:
        parsed_alert_id = uuid.UUID(alert_id)
    except (ValueError, AttributeError) as err:
        raise HTTPException(status_code=404, detail="Alert not found") from err

    container = ServiceContainer.get_instance()

    # Resolve AlertManager
    if not container.is_registered(AlertManager):
        raise HTTPException(status_code=503, detail="Alert manager not available")

    alert_manager = container.resolve(AlertManager)

    try:
        # Get the current alert to preserve its state
        if not container.is_registered(AlertQueue):
            raise HTTPException(status_code=503, detail="Alert queue not available")

        alert_queue = container.resolve(AlertQueue)
        existing_alert = alert_queue.get(parsed_alert_id)

        if existing_alert is None:
            # Check persistence as fallback
            if container.is_registered(AlertPersistence):
                alert_persistence = container.resolve(AlertPersistence)
                existing_alert = alert_persistence.load_alert(parsed_alert_id)

            if existing_alert is None:
                raise HTTPException(status_code=404, detail="Alert not found")

        previous_state = existing_alert.lifecycle_state.value

        # Dry-run the transition to validate it before touching persistence.
        # Raises ValueError for invalid transitions (e.g. CLOSED -> CLOSED).
        from argusprowl.lifecycle.transition import transition_lifecycle

        try:
            updated_alert = transition_lifecycle(existing_alert, AlertLifecycleState.CLOSED)
        except ValueError as exc:
            raise HTTPException(
                status_code=409, detail="Invalid alert lifecycle transition"
            ) from exc

        # Persist first so a failed HTTP request never leaves an unexplained
        # in-memory mutation behind a failed request.
        if container.is_registered(AlertPersistence):
            alert_persistence = container.resolve(AlertPersistence)
            try:
                success = alert_persistence.update_lifecycle(
                    parsed_alert_id, AlertLifecycleState.CLOSED.value
                )
            except Exception as exc:
                logger.warning("Error persisting lifecycle update for alert %s: %s", alert_id, exc)
                raise HTTPException(
                    status_code=503,
                    detail="Failed to persist lifecycle update",
                ) from exc
            if not success:
                logger.warning("Failed to persist lifecycle update for alert %s", alert_id)
                raise HTTPException(
                    status_code=503,
                    detail="Failed to persist lifecycle update",
                )

        if alert_queue.get(parsed_alert_id) is not None:
            updated_alert = alert_manager.close_alert(parsed_alert_id)

        return LifecycleActionResponse(
            alert_id=str(updated_alert.alert_id),
            previous_state=previous_state,
            current_state=updated_alert.lifecycle_state.value,
        )
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise
        logger.warning("Failed to close alert %s: %s", alert_id, exc)
        raise HTTPException(status_code=500, detail="Failed to close alert") from exc


# ---------------------------------------------------------------------------
# Metrics endpoint
# ---------------------------------------------------------------------------


@router.get("/metrics", summary="Application metrics snapshot", response_model=MetricsResponse)
async def get_metrics() -> MetricsResponse:
    """Return metrics snapshot from MetricsCollector.

    Preserves existing bounded metrics behavior.
    No new metrics engine is created.
    """
    try:
        from argusprowl.dependency_injection.container import ServiceContainer
        from argusprowl.metrics.collector import MetricsCollector

        container = ServiceContainer.get_instance()
        if container.is_registered(MetricsCollector):
            metrics_collector = container.resolve(MetricsCollector)
            snapshot = metrics_collector.snapshot()
            return _build_metrics_response(snapshot)
        else:
            return JSONResponse(
                content={
                    "uptime_seconds": 0.0,
                    "captured_at": "",
                    "metrics": [],
                },
                status_code=503,
            )
    except Exception as exc:
        logger.warning("Metrics collection failed: %s", exc)
        return JSONResponse(
            content={
                "uptime_seconds": 0.0,
                "captured_at": "",
                "metrics": [],
            },
            status_code=503,
        )


# ---------------------------------------------------------------------------
# Alerts endpoint
# ---------------------------------------------------------------------------


@router.get("/alerts", summary="Search alerts", response_model=AlertSearchResponse)
async def search_alerts(
    limit: int = Query(
        20, ge=1, le=100, description="Maximum number of alerts to return. Bounded to [1, 100]."
    ),
    min_priority: str | None = Query(None, description="Keep alerts with priority >= this value."),
    min_severity: str | None = Query(None, description="Keep alerts with severity >= this value."),
    rule_id: str | None = Query(
        None, max_length=128, description="Keep alerts whose metadata contains this rule_id."
    ),
    host: str | None = Query(
        None, max_length=256, description="Keep alerts whose entity_context.host matches."
    ),
    lifecycle_state: str | None = Query(None, description="Keep alerts with this lifecycle state."),
    entity_key: str | None = Query(
        None, max_length=256, description="Keep alerts whose canonical entity key matches."
    ),
    incident_id: str | None = Query(
        None, max_length=36, description="Keep alerts whose incident_id matches (as string)."
    ),
) -> AlertSearchResponse:
    """Search alerts using existing AlertSearchService.

    Exposes the existing AlertSearchService.search() with bounded parameters.
    Only supports filters already implemented in the backend.
    """
    # Parse enum values with validation
    parsed_priority = None
    if min_priority is not None:
        try:
            parsed_priority = AlertPriority.from_string(min_priority)
        except ValueError:
            valid = ", ".join(m.value for m in AlertPriority)
            return JSONResponse(
                content={"detail": f"Invalid min_priority. Valid values: {valid}"},
                status_code=422,
            )

    parsed_severity = None
    if min_severity is not None:
        try:
            parsed_severity = Severity.from_string(min_severity)
        except ValueError:
            valid = ", ".join(m.name for m in Severity)
            return JSONResponse(
                content={"detail": f"Invalid min_severity. Valid values: {valid}"},
                status_code=422,
            )

    parsed_lifecycle = None
    if lifecycle_state is not None:
        try:
            parsed_lifecycle = AlertLifecycleState.from_string(lifecycle_state)
        except ValueError:
            valid = ", ".join(m.value for m in AlertLifecycleState)
            return JSONResponse(
                content={"detail": f"Invalid lifecycle_state. Valid values: {valid}"},
                status_code=422,
            )

    # Validate string lengths
    if rule_id is not None and len(rule_id) > 128:
        return JSONResponse(
            content={"detail": "rule_id must be at most 128 characters"},
            status_code=422,
        )
    if host is not None and len(host) > 256:
        return JSONResponse(
            content={"detail": "host must be at most 256 characters"},
            status_code=422,
        )
    if entity_key is not None and len(entity_key) > 256:
        return JSONResponse(
            content={"detail": "entity_key must be at most 256 characters"},
            status_code=422,
        )
    if incident_id is not None and len(incident_id) > 36:
        return JSONResponse(
            content={"detail": "incident_id must be at most 36 characters"},
            status_code=422,
        )

    # Validate UUID format for incident_id if provided
    if incident_id is not None:
        import uuid

        try:
            uuid.UUID(incident_id)
        except ValueError:
            return JSONResponse(
                content={"detail": "Invalid incident_id format. Expected UUID."},
                status_code=422,
            )

    try:
        from argusprowl.dependency_injection.container import ServiceContainer
        from argusprowl.services.alert_search_service import AlertSearchService

        container = ServiceContainer.get_instance()
        if not container.is_registered(AlertSearchService):
            return JSONResponse(
                content={"detail": "Alert search service not available"},
                status_code=503,
            )

        search_service = container.resolve(AlertSearchService)
        result = search_service.search(
            limit=limit,
            min_priority=parsed_priority,
            min_severity=parsed_severity,
            rule_id=rule_id,
            host=host,
            lifecycle_state=parsed_lifecycle,
            entity_key=entity_key,
            incident_id=incident_id,
        )

        alerts = [_build_alert_response(alert) for alert in result.alerts]

        return AlertSearchResponse(
            alerts=alerts,
            status=result.status.value if hasattr(result.status, "value") else str(result.status),
            reason=result.reason,
            total_count=len(alerts),
        )

    except ValueError as exc:
        logger.debug("Alert search validation error: %s", exc)
        return JSONResponse(
            content={"detail": str(exc)},
            status_code=400,
        )
    except Exception as exc:
        logger.warning("Alert search failed: %s", exc)
        return JSONResponse(
            content={"detail": "Internal server error"},
            status_code=500,
        )


# ---------------------------------------------------------------------------
# Entity investigation endpoints (Phase 7.3)
# ---------------------------------------------------------------------------

_SUPPORTED_CORRELATION_TYPES = frozenset({"hostname", "dst_ip", "process"})


@router.get("/entities", summary="List behavioral entities", response_model=EntityListResponse)
async def list_entities(
    entity_type: str | None = Query(
        None, max_length=64, description="Optional entity type filter."
    ),
    limit: int = Query(100, ge=1, le=100, description="Maximum entities to return."),
) -> EntityListResponse:
    """Return bounded behavioral entity list representing entity identities."""
    from argusprowl.behavior.analyst_behavior_query_service import AnalystBehaviorQueryService
    from argusprowl.dependency_injection.container import ServiceContainer

    container = ServiceContainer.get_instance()
    if not container.is_registered(AnalystBehaviorQueryService):
        raise HTTPException(status_code=503, detail="Behavior query service not available")

    behavior_service = container.resolve(AnalystBehaviorQueryService)

    try:
        raw_entities = behavior_service.list_entities(
            entity_type=entity_type,
            limit=limit,
        )

        # Deduplicate per (entity_type, entity_id) since behavior service
        # returns one row per dimension.
        seen: set[tuple[str, str]] = set()
        entities: list[EntityItemResponse] = []
        for e in raw_entities:
            e_type = e.get("entity_type", "")
            e_id = e.get("entity_id", "")
            if (e_type, e_id) in seen:
                continue
            seen.add((e_type, e_id))
            has_corr = e_type in _SUPPORTED_CORRELATION_TYPES
            entities.append(
                EntityItemResponse(
                    entity_type=e_type,
                    entity_id=e_id,
                    has_correlation_support=has_corr,
                    maturity=e.get("maturity", "empty"),
                    observation_count=e.get("observation_count", 0),
                    last_seen=e.get("last_seen"),
                )
            )

        return EntityListResponse(
            entities=entities,
            total_count=len(entities),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning("Failed to list entities: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@router.get(
    "/entities/{entity_type}/{entity_id}",
    summary="Get entity investigation detail",
    response_model=EntityDetailResponse,
)
async def get_entity_detail(
    entity_type: str,
    entity_id: str,
) -> EntityDetailResponse:
    """Get entity detail preserving clear distinction between entity identity and correlation keys."""
    if len(entity_type) > 64 or len(entity_id) > 256:
        raise HTTPException(
            status_code=400, detail="Entity type or ID parameter exceeds maximum length"
        )

    from argusprowl.alerting.alert_persistence import AlertPersistence
    from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
    from argusprowl.behavior.analyst_behavior_query_service import AnalystBehaviorQueryService
    from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.incident.incident_service import IncidentService
    from argusprowl.lifecycle.queue import AlertQueue
    from argusprowl.services.alert_search_service import AlertSearchService

    container = ServiceContainer.get_instance()

    # The behavioral query service is required to determine entity existence.
    # Distinguish a missing backend (503) from an unknown entity (404).
    if not container.is_registered(AnalystBehaviorQueryService):
        raise HTTPException(status_code=503, detail="Behavior query service not available")

    # 1. Behavior
    behavior: list[dict[str, Any]] = []
    if container.is_registered(AnalystBehaviorQueryService):
        try:
            b_service = container.resolve(AnalystBehaviorQueryService)
            behavior = b_service.get_entity_behavior(entity_type, entity_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            logger.warning("Failed to fetch entity behavior: %s", exc)

    # 2. Annotations
    annotations: list[dict[str, Any]] = []
    if container.is_registered(AnalystAnnotationService):
        try:
            ann_service = container.resolve(AnalystAnnotationService)
            target_key = f"entity:{entity_type}:{entity_id}"
            annotations = ann_service.get_annotations_by_target(target_key)
        except Exception as exc:
            logger.warning("Failed to fetch entity annotations: %s", exc)

    # 3. Correlation & Alerts
    has_correlation_support = entity_type in _SUPPORTED_CORRELATION_TYPES

    if not has_correlation_support:
        # Unsupported correlation does not imply the identity exists. Return
        # the explanatory detail shape only when behavior or annotations
        # provide independent evidence that this entity is known.
        if not behavior and not annotations:
            raise HTTPException(status_code=404, detail="Entity not found")

        return EntityDetailResponse(
            entity_type=entity_type,
            entity_id=entity_id,
            observed_correlation_keys=[],
            correlation_status="UNSUPPORTED",
            correlation_note=f"Alert correlation is unsupported for entity type '{entity_type}'. No canonical correlation keys exist.",
            behavior=behavior,
            alerts={},
            annotations=annotations,
            incidents=[],
            incident_status="UNSUPPORTED",
            incident_note=f"Incident correlation is unsupported for entity type '{entity_type}'.",
        )

    # For supported types: hostname, dst_ip, process
    # Inspect actual candidate alerts from queue and persistence
    ecs = (
        container.resolve(EntityCorrelationService)
        if container.is_registered(EntityCorrelationService)
        else EntityCorrelationService()
    )
    search_service = (
        container.resolve(AlertSearchService)
        if container.is_registered(AlertSearchService)
        else None
    )

    # Collect candidate alerts to discover actual matching entity_context
    candidate_alerts = []
    if container.is_registered(AlertQueue):
        try:
            q = container.resolve(AlertQueue)
            candidate_alerts.extend(q.list(sort=False))
        except Exception:
            pass

    if container.is_registered(AlertPersistence):
        try:
            p = container.resolve(AlertPersistence)
            p_res = p.list_all(limit=None)
            candidate_alerts.extend(p_res.alerts)
        except Exception:
            pass

    # Deduplicate candidates by alert_id
    unique_candidates = {}
    for a in candidate_alerts:
        unique_candidates[str(a.alert_id)] = a

    # Filter candidates matching entity identity & collect observed keys
    observed_keys_set: set[str] = set()
    for a in unique_candidates.values():
        ctx = a.entity_context or {}
        matches = False

        if entity_type == "hostname":
            if ctx.get("host") == entity_id:
                matches = True
        elif entity_type == "dst_ip":
            if ctx.get("dst_ip") == entity_id:
                matches = True
        elif entity_type == "process" and ctx.get("process_name") == entity_id and ctx.get("host"):
            # Host context required for valid process correlation
            matches = True

        if matches:
            key = ecs.compute_entity_key(a)
            if not key.startswith("unknown:"):
                observed_keys_set.add(key)

    sorted_observed_keys = sorted(observed_keys_set)

    # An entity may be known through behavioral profiles, annotations, or
    # observed alert context. If none of those sources knows it, don't return
    # an empty shell that makes a nonexistent entity look valid.
    if not behavior and not annotations and not sorted_observed_keys:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Search alerts per observed correlation key using AlertSearchService
    alerts_by_key: dict[str, list[AlertResponse]] = {}
    seen_alert_ids: set[str] = set()

    if search_service and sorted_observed_keys:
        for key in sorted_observed_keys:
            alerts_for_key: list[AlertResponse] = []
            try:
                s_res = search_service.search(limit=100, entity_key=key)
                for alert_obj in s_res.alerts:
                    aid_str = str(alert_obj.alert_id)
                    if aid_str not in seen_alert_ids:
                        seen_alert_ids.add(aid_str)
                        alerts_for_key.append(_build_alert_response(alert_obj))
            except Exception as exc:
                logger.warning("Failed to search alerts for entity key %s: %s", key, exc)

            alerts_by_key[key] = alerts_for_key

    # Resolve incidents for observed correlation keys
    incidents_list: list[dict[str, Any]] = []
    incident_service = (
        container.resolve(IncidentService) if container.is_registered(IncidentService) else None
    )

    if incident_service and sorted_observed_keys:
        seen_incident_ids: set[str] = set()
        for key in sorted_observed_keys:
            try:
                inc_id = incident_service.get_incident_for_entity(key)
                if inc_id is not None:
                    inc_str = str(inc_id)
                    if inc_str not in seen_incident_ids:
                        seen_incident_ids.add(inc_str)
                        inc_obj = incident_service.get_incident(inc_id)
                        incidents_list.append(
                            {
                                "incident_id": inc_str,
                                "correlation_key": key,
                                "title": inc_obj.title,
                                "severity": inc_obj.severity.name
                                if hasattr(inc_obj.severity, "name")
                                else str(inc_obj.severity),
                                "status": inc_obj.status.value
                                if hasattr(inc_obj.status, "value")
                                else str(inc_obj.status),
                            }
                        )
            except Exception as exc:
                logger.warning("Failed to resolve incident for key %s: %s", key, exc)

    return EntityDetailResponse(
        entity_type=entity_type,
        entity_id=entity_id,
        observed_correlation_keys=sorted_observed_keys,
        correlation_status="PARTIAL",
        correlation_note="Alerts are grouped by observed canonical correlation keys. Additional alerts may exist under other keys.",
        behavior=behavior,
        alerts=alerts_by_key,
        annotations=annotations,
        incidents=incidents_list,
        incident_status="PARTIAL",
        incident_note="Incident relationships are resolved from observed canonical correlation keys and may be affected by in-memory LRU eviction.",
    )


@router.get(
    "/entities/{entity_type}/{entity_id}/annotations",
    summary="Get entity annotations",
    response_model=list[AnnotationResponse],
)
async def get_entity_annotations(
    entity_type: str,
    entity_id: str,
) -> list[AnnotationResponse]:
    """Read annotations for entity identity target (entity:{entity_type}:{entity_id})."""
    if len(entity_type) > 64 or len(entity_id) > 256:
        raise HTTPException(
            status_code=400, detail="Entity type or ID parameter exceeds maximum length"
        )

    from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
    from argusprowl.dependency_injection.container import ServiceContainer

    container = ServiceContainer.get_instance()
    if not container.is_registered(AnalystAnnotationService):
        raise HTTPException(status_code=503, detail="Annotation service not available")

    ann_service = container.resolve(AnalystAnnotationService)
    target_key = f"entity:{entity_type}:{entity_id}"

    try:
        raw_anns = ann_service.get_annotations_by_target(target_key)
        return [
            AnnotationResponse(
                annotation_id=a["annotation_id"],
                target_key=a["target_key"],
                author=a["author"],
                created_at=a["created_at"],
                comment=a["comment"],
                tombstoned=a["tombstoned"],
            )
            for a in raw_anns
        ]
    except Exception as exc:
        logger.warning("Failed to fetch annotations: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error") from exc


@router.post(
    "/entities/{entity_type}/{entity_id}/annotations",
    summary="Create entity annotation",
    response_model=AnnotationResponse,
)
async def create_entity_annotation(
    entity_type: str,
    entity_id: str,
    body: AnnotationCreateRequest,
) -> AnnotationResponse:
    """Create a new annotation for entity identity target (entity:{entity_type}:{entity_id})."""
    if len(entity_type) > 64 or len(entity_id) > 256:
        raise HTTPException(
            status_code=400, detail="Entity type or ID parameter exceeds maximum length"
        )

    from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
    from argusprowl.dependency_injection.container import ServiceContainer

    container = ServiceContainer.get_instance()
    if not container.is_registered(AnalystAnnotationService):
        raise HTTPException(status_code=503, detail="Annotation service not available")

    ann_service = container.resolve(AnalystAnnotationService)
    target_key = f"entity:{entity_type}:{entity_id}"

    try:
        created = ann_service.create_annotation(
            target_key=target_key,
            author=body.author,
            comment=body.comment,
        )
        return AnnotationResponse(
            annotation_id=str(created.annotation_id),
            target_key=created.target_key,
            author=created.author,
            created_at=created.created_at.isoformat(),
            comment=created.comment,
            tombstoned=created.tombstoned,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning("Failed to create annotation: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error") from exc


# ---------------------------------------------------------------------------
# Investigation Timeline endpoint (Phase 7.4)
# ---------------------------------------------------------------------------


@router.get(
    "/entities/{entity_type}/{entity_id}/timeline",
    summary="Get entity investigation timeline",
    response_model=TimelineResponse,
)
async def get_entity_timeline(
    entity_type: str,
    entity_id: str,
    limit: int = Query(
        50, ge=1, le=100, description="Maximum timeline items to return. Bounded to [1, 100]."
    ),
) -> TimelineResponse:
    """Get a bounded, deterministic investigation timeline for an entity.

    Combines evidence from alerts, incidents, annotations, and behavior
    into a single chronological view. Does NOT modify any source state.
    """
    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.services.investigation_timeline_service import InvestigationTimelineService

    container = ServiceContainer.get_instance()

    try:
        service = container.resolve(InvestigationTimelineService)
        result = service.get_timeline(entity_type, entity_id, limit=limit)
        return TimelineResponse(
            entity_type=result["entity_type"],
            entity_id=result["entity_id"],
            items=result["items"],
            returned_count=result["returned_count"],
            truncated=result["truncated"],
            correlation_status=result["correlation_status"],
            correlation_note=result["correlation_note"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning("Failed to build timeline: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error") from exc


# ---------------------------------------------------------------------------
# Detection Rule endpoints (Phase 7.5)
# ---------------------------------------------------------------------------


def _sanitize_dict(data: dict) -> dict:
    """Coerce dictionary values to JSON-safe primitives."""
    from datetime import timedelta
    from pathlib import Path

    safe_data = {}
    for k, v in data.items():
        if isinstance(v, dict):
            safe_data[k] = _sanitize_dict(v)
        elif isinstance(v, list):
            safe_data[k] = [str(x) if isinstance(x, (Path, timedelta)) else x for x in v]
        elif isinstance(v, (Path, timedelta)):
            safe_data[k] = str(v)
        elif isinstance(v, (int, float, str, bool, type(None))):
            safe_data[k] = v
        else:
            safe_data[k] = str(v)
    return safe_data


@router.get("/rules", summary="List detection rules", response_model=RuleListResponse)
async def list_rules(
    enabled: bool | None = Query(None, description="Filter rules by enabled status."),
    detector_class: str | None = Query(None, description="Filter rules by detector class name."),
) -> RuleListResponse:
    """Get a read-only list of loaded detection rules from the registry."""
    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.detection.detection_manager import DetectionManager

    container = ServiceContainer.get_instance()
    if not container.is_registered(DetectionManager):
        raise HTTPException(status_code=503, detail="Detection manager not available")

    manager = container.resolve(DetectionManager)
    registry = manager.get_registry()

    detectors = registry.get_all()

    filtered_detectors = []
    for name, detector in detectors.items():
        if enabled is not None and detector.is_enabled() != enabled:
            continue
        det_class = type(detector).__name__
        if detector_class is not None and det_class != detector_class:
            continue
        filtered_detectors.append((name, detector))

    # Deterministic sorting by name/rule_id
    filtered_detectors.sort(key=lambda x: x[0])

    items = []
    for name, detector in filtered_detectors:
        items.append(
            RuleItemResponse(
                rule_id=name,
                name=detector.name,
                description=detector.description,
                enabled=detector.is_enabled(),
                detector_class=type(detector).__name__,
                version=detector.version,
                confidence=detector.confidence,
            )
        )

    return RuleListResponse(rules=items, total_count=len(items))


@router.get(
    "/rules/{rule_id}", summary="Get detection rule detail", response_model=RuleDetailResponse
)
async def get_rule_detail(
    rule_id: str,
) -> RuleDetailResponse:
    """Get read-only details of a specific detection rule, including ATT&CK mappings."""
    if len(rule_id) > 128:
        raise HTTPException(status_code=400, detail="rule_id parameter exceeds maximum length")

    from argusprowl.attck.mapping_registry import AttckMappingRegistry
    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.detection.detection_manager import DetectionManager

    container = ServiceContainer.get_instance()
    if not container.is_registered(DetectionManager):
        raise HTTPException(status_code=503, detail="Detection manager not available")

    manager = container.resolve(DetectionManager)
    registry = manager.get_registry()

    try:
        detector = registry.get(rule_id)
    except KeyError as err:
        raise HTTPException(status_code=404, detail="Rule not found") from err

    # Fetch ATT&CK mappings if available
    attck_mappings = []
    if container.is_registered(AttckMappingRegistry):
        attck_registry = container.resolve(AttckMappingRegistry)
        import pydantic

        try:
            mappings = attck_registry.get_for_rule(rule_id)
            for m in mappings:
                attck_mappings.append(
                    AttckMappingResponse(
                        technique_id=m.technique_id,
                        mapping_type=m.mapping_type.value
                        if hasattr(m.mapping_type, "value")
                        else str(m.mapping_type),
                        subtechnique_id=m.subtechnique_id,
                        rationale=m.rationale,
                    )
                )
        except pydantic.ValidationError:
            pass
        except ValueError:
            pass

    safe_params = _sanitize_dict(detector._config if hasattr(detector, "_config") else {})

    return RuleDetailResponse(
        rule_id=rule_id,
        name=detector.name,
        description=detector.description,
        enabled=detector.is_enabled(),
        detector_class=type(detector).__name__,
        version=detector.version,
        confidence=detector.confidence,
        parameters=safe_params,
        attck_mappings=attck_mappings,
    )


# ---------------------------------------------------------------------------
# IOC Investigation endpoint (Phase 7.6)
# ---------------------------------------------------------------------------


@router.get(
    "/iocs/{indicator}", summary="Investigate an IOC", response_model=IocInvestigationResponse
)
async def investigate_ioc(indicator: str) -> IocInvestigationResponse:
    """Investigate an IP or domain indicator against threat intelligence and retained alerts."""
    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.services.ioc_investigation_service import IocInvestigationService

    if not indicator or not indicator.strip():
        raise HTTPException(status_code=400, detail="Indicator must be a non-empty string.")
    if len(indicator) > 256:
        raise HTTPException(
            status_code=400, detail="Indicator exceeds maximum length of 256 characters."
        )

    container = ServiceContainer.get_instance()
    if not container.is_registered(IocInvestigationService):
        raise HTTPException(status_code=503, detail="IOC investigation service not available")

    service = container.resolve(IocInvestigationService)

    try:
        result = service.investigate(indicator)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return IocInvestigationResponse(
        indicator=result.indicator,
        ioc_type=result.ioc_type.value,
        reputation=result.reputation.to_dict(),
        observations=[
            IocObservationResponse(
                alert_id=obs.alert_id,
                timestamp=obs.timestamp.isoformat(),
                field=obs.field,
                value=obs.value,
                host=obs.host,
                rule_id=obs.rule_id,
                severity=obs.severity,
            )
            for obs in result.observations
        ],
        first_observed=result.first_observed.isoformat() if result.first_observed else None,
        last_observed=result.last_observed.isoformat() if result.last_observed else None,
        associated_alert_ids=list(result.associated_alert_ids),
        associated_hosts=list(result.associated_hosts),
        associated_rule_ids=list(result.associated_rule_ids),
        related_iocs=[
            RelatedIocResponse(
                indicator=rel.indicator,
                ioc_type=rel.ioc_type.value,
                field=rel.field,
                co_observed_in_alert_id=rel.co_observed_in_alert_id,
            )
            for rel in result.related_iocs
        ],
        timeline=[
            IocTimelineItemResponse(
                timeline_item_id=item.timeline_item_id,
                timestamp=item.timestamp,
                item_type=item.item_type,
                title=item.title,
                summary=item.summary,
                source_id=item.source_id,
                metadata=dict(item.metadata),
            )
            for item in result.timeline
        ],
        prevalence=result.prevalence.to_dict() if result.prevalence else None,
        status=result.status.value,
        reason=result.reason,
        truncated=result.truncated,
        inspected_alert_count=result.inspected_alert_count,
        observation_note=result.observation_note,
    )


# ---------------------------------------------------------------------------
# Telemetry Evidence endpoints (Phase 7.8)
# ---------------------------------------------------------------------------


@router.get("/evidence", summary="Search telemetry evidence")
async def search_evidence(
    limit: int = Query(50, ge=1, le=500, description="Maximum evidence records to return."),
    event_id: str | None = Query(None, description="Exact event ID lookup."),
    start_time: str | None = Query(None, description="ISO 8601 start timestamp (inclusive)."),
    end_time: str | None = Query(None, description="ISO 8601 end timestamp (inclusive)."),
    entity_type: str | None = Query(
        None,
        max_length=64,
        description="Entity type filter (hostname, src_ip, dst_ip, process, user).",
    ),
    entity_id: str | None = Query(None, max_length=256, description="Entity ID filter."),
    src_ip: str | None = Query(None, max_length=64, description="Source IP filter."),
    dst_ip: str | None = Query(None, max_length=64, description="Destination IP filter."),
    domain: str | None = Query(None, max_length=256, description="Domain name filter."),
    event_type: str | None = Query(None, max_length=128, description="Event type filter."),
    source_type: str | None = Query(
        None, max_length=128, description="Source type filter (e.g. zeek, sysmon)."
    ),
) -> dict[str, Any]:
    """Search telemetry evidence with bounded filters.

    All filters are ANDed. Results are sorted by timestamp then event_id.
    """
    import uuid
    from datetime import datetime

    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService

    container = ServiceContainer.get_instance()
    if not container.is_registered(TelemetryEvidenceService):
        return JSONResponse(
            content={"detail": "Telemetry evidence service not available"},
            status_code=503,
        )

    # Validate optional UUID
    parsed_event_id = None
    if event_id is not None:
        try:
            parsed_event_id = uuid.UUID(event_id)
        except ValueError:
            return JSONResponse(
                content={"detail": "Invalid event_id format. Expected UUID."},
                status_code=422,
            )

    # Validate optional timestamps
    parsed_start_time = None
    parsed_end_time = None
    if start_time is not None:
        try:
            parsed_start_time = datetime.fromisoformat(start_time)
        except ValueError:
            return JSONResponse(
                content={"detail": "Invalid start_time format. Expected ISO 8601."},
                status_code=422,
            )
    if end_time is not None:
        try:
            parsed_end_time = datetime.fromisoformat(end_time)
        except ValueError:
            return JSONResponse(
                content={"detail": "Invalid end_time format. Expected ISO 8601."},
                status_code=422,
            )

    # Validate string lengths
    if entity_id is not None and len(entity_id) > 256:
        return JSONResponse(
            content={"detail": "entity_id must be at most 256 characters"},
            status_code=422,
        )
    if src_ip is not None and len(src_ip) > 64:
        return JSONResponse(
            content={"detail": "src_ip must be at most 64 characters"},
            status_code=422,
        )
    if dst_ip is not None and len(dst_ip) > 64:
        return JSONResponse(
            content={"detail": "dst_ip must be at most 64 characters"},
            status_code=422,
        )
    if domain is not None and len(domain) > 256:
        return JSONResponse(
            content={"detail": "domain must be at most 256 characters"},
            status_code=422,
        )
    if event_type is not None and len(event_type) > 128:
        return JSONResponse(
            content={"detail": "event_type must be at most 128 characters"},
            status_code=422,
        )
    if source_type is not None and len(source_type) > 128:
        return JSONResponse(
            content={"detail": "source_type must be at most 128 characters"},
            status_code=422,
        )

    service = container.resolve(TelemetryEvidenceService)
    try:
        result = service.search(
            limit=limit,
            event_id=parsed_event_id,
            start_time=parsed_start_time,
            end_time=parsed_end_time,
            entity_type=entity_type,
            entity_id=entity_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            domain=domain,
            event_type=event_type,
            source_type=source_type,
        )
    except ValueError as exc:
        return JSONResponse(
            content={"detail": str(exc)},
            status_code=400,
        )

    records = [
        EvidenceRecordResponse(
            event_id=str(r.event_id),
            provenance=r.provenance,
            detection_result_id=str(r.detection_result_id) if r.detection_result_id else None,
            contributing_event_ids=[str(eid) for eid in r.contributing_event_ids],
        )
        for r in result.records
    ]

    events: dict[str, EvidenceEventResponse] = {}
    for eid, event in result.events.items():
        events[str(eid)] = EvidenceEventResponse(
            event_id=str(event.event_id),
            timestamp=event.timestamp.isoformat(),
            source_type=event.source_type,
            event_type=event.event_type,
            hostname=event.hostname,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            process_name=event.process_name,
            username=event.username,
        )

    return EvidenceSearchResponse(
        records=records,
        events=events,
        status=result.status,
        reason=result.reason,
        truncated=result.truncated,
        total_count=result.total_count,
        returned_count=result.returned_count,
    ).model_dump()


@router.get("/evidence/stats", summary="Telemetry evidence store stats")
async def get_evidence_stats() -> dict[str, Any]:
    """Return telemetry evidence store statistics."""
    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService

    container = ServiceContainer.get_instance()
    if not container.is_registered(TelemetryEvidenceService):
        raise HTTPException(status_code=503, detail="Telemetry evidence service not available")

    service = container.resolve(TelemetryEvidenceService)
    stats = service.get_stats()

    return EvidenceStatsResponse(
        retained_events=stats["retained_events"],
        max_retained_events=stats["max_retained_events"],
        eviction_count=stats["eviction_count"],
        capacity_used_pct=stats["capacity_used_pct"],
    ).model_dump()


@router.get("/evidence/{event_id}", summary="Get single evidence record")
async def get_evidence_detail(event_id: str) -> dict[str, Any]:
    """Get a single telemetry evidence record by event ID."""
    import uuid

    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService

    container = ServiceContainer.get_instance()
    if not container.is_registered(TelemetryEvidenceService):
        raise HTTPException(status_code=503, detail="Telemetry evidence service not available")

    # Dependency availability takes precedence over ID validation so clients
    # get a service-unavailable response when the evidence backend is offline.
    try:
        parsed_id = uuid.UUID(event_id)
    except (ValueError, AttributeError) as err:
        raise HTTPException(status_code=404, detail="Event not found") from err

    service = container.resolve(TelemetryEvidenceService)
    detail = service.get_detail(parsed_id)

    if detail is None:
        raise HTTPException(status_code=404, detail="Event not found")

    event_response = None
    if detail.event is not None:
        event = detail.event
        event_response = EvidenceEventResponse(
            event_id=str(event.event_id),
            timestamp=event.timestamp.isoformat(),
            source_type=event.source_type,
            event_type=event.event_type,
            hostname=event.hostname,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            process_name=event.process_name,
            username=event.username,
        )

    record_response = None
    if detail.record is not None:
        record = detail.record
        record_response = EvidenceRecordResponse(
            event_id=str(record.event_id),
            provenance=record.provenance,
            detection_result_id=str(record.detection_result_id)
            if record.detection_result_id
            else None,
            contributing_event_ids=[str(eid) for eid in record.contributing_event_ids],
        )

    return EvidenceDetailResponse(
        event_id=str(detail.event_id),
        status=detail.status,
        reason=detail.reason,
        event=event_response,
        record=record_response,
    ).model_dump()


# ---------------------------------------------------------------------------
# ATT&CK Investigation (Phase 6.5)
# ---------------------------------------------------------------------------


@router.get(
    "/attck/overview",
    summary="ATT&CK knowledge status and technique coverage",
    response_model=AttckOverviewResponse,
)
async def get_attck_overview() -> AttckOverviewResponse:
    """Return global ATT&CK knowledge status and mapping coverage summary."""
    from argusprowl.attck.knowledge_service import AttckKnowledgeService
    from argusprowl.attck.mapping_registry import AttckMappingRegistry
    from argusprowl.dependency_injection.container import ServiceContainer

    container = ServiceContainer.get_instance()
    if not container.is_registered(AttckKnowledgeService):
        raise HTTPException(status_code=503, detail="ATT&CK knowledge service not available")

    knowledge = container.resolve(AttckKnowledgeService)
    status = knowledge.get_status()

    mapping_count = 0
    mapped_technique_ids: set[str] = set()
    if container.is_registered(AttckMappingRegistry):
        registry = container.resolve(AttckMappingRegistry)
        mappings = registry.get_all()
        mapping_count = len(mappings)
        mapped_technique_ids = {m.technique_id for m in mappings}

    return AttckOverviewResponse(
        knowledge_status=status.value,
        attck_version=knowledge.get_version(),
        total_techniques=knowledge.get_metadata().technique_count
        if knowledge.get_metadata()
        else 0,
        total_tactics=knowledge.get_metadata().tactic_count if knowledge.get_metadata() else 0,
        mapping_count=mapping_count,
        mapped_technique_ids=sorted(mapped_technique_ids),
    )


@router.get(
    "/attck/investigation",
    summary="ATT&CK investigation for a set of alerts",
    response_model=AttckInvestigationResponse,
)
async def get_attck_investigation(
    alert_ids: str = Query(
        ...,
        description="Comma-separated alert IDs to investigate for ATT&CK observations.",
        max_length=4096,
    ),
) -> AttckInvestigationResponse:
    """Aggregate ATT&CK technique summaries for a set of alert IDs."""
    from argusprowl.dependency_injection.container import ServiceContainer
    from argusprowl.services.attck_investigation_context_service import (
        AttckInvestigationContextService,
    )

    container = ServiceContainer.get_instance()

    ids = [a.strip() for a in alert_ids.split(",") if a.strip()]
    if not ids:
        raise HTTPException(status_code=400, detail="No alert IDs provided.")
    if len(ids) > 256:
        raise HTTPException(status_code=400, detail="Maximum 256 alert IDs per request.")

    import uuid

    alerts = []
    not_found = []
    for aid in ids:
        parsed = None
        try:
            parsed = uuid.UUID(aid)
        except (ValueError, AttributeError):
            not_found.append(aid)
            continue

        alert = None
        if container.is_registered(AlertQueue):
            with contextlib.suppress(Exception):
                alert = container.resolve(AlertQueue).get(parsed)
        if alert is None and container.is_registered(AlertPersistence):
            with contextlib.suppress(Exception):
                alert = container.resolve(AlertPersistence).load_alert(parsed)
        if alert is not None:
            alerts.append(alert)
        else:
            not_found.append(aid)

    if not alerts and not_found:
        raise HTTPException(status_code=404, detail="No matching alerts found.")

    context_service = AttckInvestigationContextService()
    summaries = context_service.aggregate(tuple(alerts))

    technique_responses = [
        AttckTechniqueSummaryResponse(
            technique_id=s.technique_id,
            mapping_type=s.mapping_type,
            technique_name=s.technique_name,
            tactic=s.tactic,
            version=s.version,
            source_alert_ids=list(s.source_alert_ids),
            evidence_refs=list(s.evidence_refs),
            rationale=s.rationale,
        )
        for s in summaries
    ]

    return AttckInvestigationResponse(
        alert_count=len(alerts),
        techniques=technique_responses,
    )
