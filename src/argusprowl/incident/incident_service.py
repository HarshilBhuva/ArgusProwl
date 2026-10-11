"""Incident service for entity-centric alert correlation.

Manages incident lifecycle: creation, association, retrieval, and listing.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from threading import RLock
from uuid import UUID

from argusprowl.constants.severity import Severity
from argusprowl.models.alert import Alert
from argusprowl.models.incident import Incident, IncidentStatus


class IncidentServiceError(Exception):
    """Base error for incident service operational failures."""


class IncidentNotFoundError(IncidentServiceError):
    """Raised when an incident is not found."""


class IncidentService:
    """In-memory incident management service.

    Provides deterministic incident creation and alert association.
    State is process-local and bounded.

    Authoritative owner of entity-to-incident relationships.
    """

    def __init__(self, max_incidents: int = 1000) -> None:
        """Initialize incident service.

        Args:
            max_incidents: Maximum number of incidents to track.
        """
        if not isinstance(max_incidents, int) or max_incidents <= 0:
            raise ValueError(f"max_incidents must be a positive integer, got {max_incidents!r}")
        self._max_incidents = max_incidents
        self._incidents: dict[UUID, Incident] = {}
        self._entity_incident_map: dict[str, UUID] = {}  # entity_key -> incident_id
        self._lock = RLock()

    @property
    def max_incidents(self) -> int:
        """Maximum number of incidents."""
        return self._max_incidents

    def create_incident(
        self,
        alerts: Sequence[Alert],
        title: str | None = None,
        description: str | None = None,
        severity: Severity | None = None,
        tags: tuple[str, ...] | None = None,
    ) -> Incident:
        """Create a new incident from alerts.

        Args:
            alerts: Sequence of alerts to associate with the incident.
            title: Optional incident title. Generated if not provided.
            description: Optional incident description. Generated if not provided.
            severity: Optional severity. Derived from alerts if not provided.
            tags: Optional tags.

        Returns:
            Created incident.

        Raises:
            ValueError: If alerts is empty.
        """
        if not alerts:
            raise ValueError("Cannot create incident from empty alert sequence.")

        # Derive severity from highest-severity alert if not provided
        if severity is None:
            severity = self._derive_severity(alerts)

        # Generate title if not provided
        if title is None:
            title = self._generate_title(alerts)

        # Generate description if not provided
        if description is None:
            description = self._generate_description(alerts)

        now = datetime.now(UTC)
        alert_ids = tuple(a.alert_id for a in alerts)

        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            status=IncidentStatus.OPEN,
            alert_ids=alert_ids,
            tags=tags or (),
            metadata={
                "alert_count": len(alerts),
                "created_at": now.isoformat(),
            },
            created_at=now,
            updated_at=now,
        )

        with self._lock:
            # Evict oldest if at capacity
            if len(self._incidents) >= self._max_incidents:
                oldest_id = next(iter(self._incidents))
                self._evict_incident(oldest_id)
            self._incidents[incident.incident_id] = incident

        return incident

    def _evict_incident(self, incident_id: UUID) -> None:
        """Evict an incident and clean up any entity mappings pointing to it.

        Args:
            incident_id: ID of the incident to evict.
        """
        # Remove entity mappings pointing to this incident
        keys_to_remove = [
            key for key, iid in self._entity_incident_map.items() if iid == incident_id
        ]
        for key in keys_to_remove:
            del self._entity_incident_map[key]
        del self._incidents[incident_id]

    def get_or_create_incident_for_entity(
        self,
        entity_key: str,
        alerts: Sequence[Alert],
    ) -> UUID:
        """Get existing incident for entity or create new one.

        This is the authoritative method for entity-to-incident mapping.
        It ensures a single source of truth for entity relationships.

        Args:
            entity_key: Deterministic entity key from EntityCorrelationService.
            alerts: Sequence of alerts to associate (first alert creates incident).

        Returns:
            Incident ID for the entity.

        Raises:
            ValueError: If alerts is empty.
        """
        with self._lock:
            # Check if we have an existing incident for this entity
            incident_id = self._entity_incident_map.get(entity_key)
            if incident_id is not None:
                incident = self._incidents.get(incident_id)
                if incident is not None:
                    # Re-associate the new alert with existing incident
                    self._associate_alert_internal(incident_id, alerts[-1])
                    return incident_id

            # Create new incident
            incident = self._create_incident_internal(alerts)
            self._entity_incident_map[entity_key] = incident.incident_id
            return incident.incident_id

    def get_incident_for_entity(self, entity_key: str) -> UUID | None:
        """Get incident ID for an entity key, if one exists.

        Args:
            entity_key: Deterministic entity key.

        Returns:
            Incident ID if exists, None otherwise.
        """
        with self._lock:
            return self._entity_incident_map.get(entity_key)

    def _create_incident_internal(self, alerts: Sequence[Alert]) -> Incident:
        """Internal incident creation without lock (caller must hold lock)."""
        if not alerts:
            raise ValueError("Cannot create incident from empty alert sequence.")

        severity = self._derive_severity(alerts)
        title = self._generate_title(alerts)
        description = self._generate_description(alerts)

        now = datetime.now(UTC)
        alert_ids = tuple(a.alert_id for a in alerts)

        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            status=IncidentStatus.OPEN,
            alert_ids=alert_ids,
            tags=(),
            metadata={
                "alert_count": len(alerts),
                "created_at": now.isoformat(),
            },
            created_at=now,
            updated_at=now,
        )

        # Evict oldest if at capacity (cleaning up entity mappings)
        if len(self._incidents) >= self._max_incidents:
            oldest_id = next(iter(self._incidents))
            self._evict_incident(oldest_id)

        self._incidents[incident.incident_id] = incident
        return incident

    def _associate_alert_internal(self, incident_id: UUID, alert: Alert) -> None:
        """Internal alert association without lock (caller must hold lock)."""
        incident = self._incidents.get(incident_id)
        if incident is None:
            raise IncidentNotFoundError(f"Incident {incident_id} not found")

        updated_alert_ids = (*incident.alert_ids, alert.alert_id)
        now = datetime.now(UTC)
        updated_incident = Incident(
            title=incident.title,
            description=incident.description,
            severity=incident.severity,
            status=incident.status,
            incident_id=incident.incident_id,
            created_at=incident.created_at,
            updated_at=now,
            alert_ids=updated_alert_ids,
            tags=incident.tags,
            metadata={
                **incident.metadata,
                "alert_count": len(updated_alert_ids),
                "last_associated": now.isoformat(),
            },
        )
        self._incidents[incident_id] = updated_incident

    def associate_alert(
        self,
        incident_id: UUID,
        alert: Alert,
    ) -> Incident:
        """Associate an alert with an existing incident.

        Args:
            incident_id: ID of the incident to associate with.
            alert: Alert to associate.

        Returns:
            Updated incident.

        Raises:
            IncidentNotFoundError: If incident_id not found.
        """
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident is None:
                raise IncidentNotFoundError(f"Incident {incident_id} not found")

            # Create new incident with updated alert_ids
            updated_alert_ids = (*incident.alert_ids, alert.alert_id)
            now = datetime.now(UTC)
            updated_incident = Incident(
                title=incident.title,
                description=incident.description,
                severity=incident.severity,
                status=incident.status,
                incident_id=incident.incident_id,
                created_at=incident.created_at,
                updated_at=now,
                alert_ids=updated_alert_ids,
                tags=incident.tags,
                metadata={
                    **incident.metadata,
                    "alert_count": len(updated_alert_ids),
                    "last_associated": now.isoformat(),
                },
            )
            self._incidents[incident_id] = updated_incident
            return updated_incident

    def list_incidents(
        self,
        status: IncidentStatus | None = None,
        severity: Severity | None = None,
    ) -> Sequence[Incident]:
        """List incidents with optional filters, sorted by created_at descending."""
        with self._lock:
            incidents = list(self._incidents.values())

            if status is not None:
                incidents = [inc for inc in incidents if inc.status == status]

            if severity is not None:
                incidents = [inc for inc in incidents if inc.severity == severity]

            # Sort by created_at descending (most recent first)
            incidents.sort(key=lambda x: x.created_at, reverse=True)
            return incidents

    def get_incident(self, incident_id: UUID) -> Incident | None:
        """Get incident by ID.

        Args:
            incident_id: ID of the incident to retrieve.

        Returns:
            Incident if found, None otherwise.
        """
        with self._lock:
            return self._incidents.get(incident_id)

    def update_status(
        self,
        incident_id: UUID,
        new_status: IncidentStatus,
    ) -> Incident:
        """Update the status of an incident with transition validation.

        Args:
            incident_id: ID of the incident to update.
            new_status: New status to set.

        Returns:
            Updated incident.

        Raises:
            IncidentNotFoundError: If incident_id not found.
            ValueError: If the transition is invalid.
        """
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident is None:
                raise IncidentNotFoundError(f"Incident {incident_id} not found")

            current = incident.status
            if current == new_status:
                return incident

            if current == IncidentStatus.CLOSED:
                raise ValueError("Cannot change status of a CLOSED incident.")

            # Strict linear lifecycle: OPEN -> INVESTIGATING -> RESOLVED -> CLOSED
            if current == IncidentStatus.OPEN:
                valid_transitions = {IncidentStatus.INVESTIGATING}
            elif current == IncidentStatus.INVESTIGATING:
                valid_transitions = {IncidentStatus.RESOLVED}
            elif current == IncidentStatus.RESOLVED:
                valid_transitions = {IncidentStatus.CLOSED}
            else:
                # CLOSED is terminal (also catches CLOSED in the check above)
                valid_transitions = set()

            if new_status not in valid_transitions:
                raise ValueError(f"Invalid transition: {current.value} -> {new_status.value}")

            now = datetime.now(UTC)
            updated_incident = Incident(
                title=incident.title,
                description=incident.description,
                severity=incident.severity,
                status=new_status,
                incident_id=incident.incident_id,
                created_at=incident.created_at,
                updated_at=now,
                alert_ids=incident.alert_ids,
                tags=incident.tags,
                metadata={
                    **incident.metadata,
                    f"status_changed_to_{new_status.value}": now.isoformat(),
                },
            )
            self._incidents[incident_id] = updated_incident
            return updated_incident

    @staticmethod
    def _derive_severity(alerts: Sequence[Alert]) -> Severity:
        """Derive incident severity from highest-severity alert.

        Args:
            alerts: Sequence of alerts.

        Returns:
            Highest severity among alerts.
        """
        severity_order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return max(alerts, key=lambda a: severity_order.get(a.severity, 0)).severity

    @staticmethod
    def _generate_title(alerts: Sequence[Alert]) -> str:
        """Generate incident title from alerts.

        Args:
            alerts: Sequence of alerts.

        Returns:
            Generated title.
        """
        # Use first alert's title as base
        base_title = alerts[0].title if alerts else "Correlated Alerts"
        return f"{base_title} ({len(alerts)} alerts)"

    @staticmethod
    def _generate_description(alerts: Sequence[Alert]) -> str:
        """Generate incident description from alerts.

        Args:
            alerts: Sequence of alerts.

        Returns:
            Generated description.
        """
        descriptions = [a.description for a in alerts if a.description]
        if not descriptions:
            return f"Correlated incident with {len(alerts)} alerts"
        return (
            f"Correlated incident containing {len(alerts)} alerts. First alert: {descriptions[0]}"
        )
