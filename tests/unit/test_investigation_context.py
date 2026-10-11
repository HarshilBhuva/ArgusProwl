"""Tests for InvestigationContextService (Phase 5.3).

Focused tests covering the bounded, read-only evidence aggregation API.
Hardened per architecture review: domain-specific entity keys are explicit,
source status distinguishes absence from unavailability, and unexpected
errors are not silently converted to empty results.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
from argusprowl.behavior.analyst_behavior_query_service import AnalystBehaviorQueryService
from argusprowl.constants.severity import Severity
from argusprowl.incident.incident_service import IncidentService
from argusprowl.lifecycle.queue import AlertQueue
from argusprowl.models.alert import Alert
from argusprowl.models.entity_investigation_context import (
    _MAX_ALERTS,
    _MAX_ANNOTATIONS,
    EntityInvestigationContext,
    SourceStatus,
)
from argusprowl.models.incident import Incident, IncidentStatus
from argusprowl.services.investigation_context_service import InvestigationContextService

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_alert_queue() -> MagicMock:
    """Create a mock AlertQueue."""
    return MagicMock(spec=AlertQueue)


@pytest.fixture
def mock_behavior_service() -> MagicMock:
    """Create a mock AnalystBehaviorQueryService."""
    return MagicMock(spec=AnalystBehaviorQueryService)


@pytest.fixture
def mock_annotation_service() -> MagicMock:
    """Create a mock AnalystAnnotationService."""
    return MagicMock(spec=AnalystAnnotationService)


@pytest.fixture
def mock_incident_service() -> MagicMock:
    """Create a mock IncidentService."""
    return MagicMock(spec=IncidentService)


@pytest.fixture
def service(
    mock_alert_queue: MagicMock,
    mock_behavior_service: MagicMock,
    mock_annotation_service: MagicMock,
    mock_incident_service: MagicMock,
) -> InvestigationContextService:
    """Create an InvestigationContextService with mocked dependencies."""
    return InvestigationContextService(
        alert_queue=mock_alert_queue,
        behavior_query_service=mock_behavior_service,
        annotation_service=mock_annotation_service,
        incident_service=mock_incident_service,
    )


def make_alert(
    alert_id: UUID | None = None,
    title: str = "Test Alert",
    host: str | None = None,
    created_at: datetime | None = None,
) -> Alert:
    """Create a test alert."""
    return Alert(
        alert_id=alert_id or uuid4(),
        title=title,
        description="Test description",
        severity=Severity.MEDIUM,
        source="test",
        created_at=created_at or datetime.now(UTC),
        entity_context={"host": host} if host else None,
    )


def make_incident(
    incident_id: UUID | None = None,
    title: str = "Test Incident",
) -> Incident:
    """Create a test incident."""
    return Incident(
        incident_id=incident_id or uuid4(),
        title=title,
        description="Test incident description",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


# ── Test: Empty Entity ───────────────────────────────────────────────────────


class TestEmptyEntity:
    """Tests for entities with no evidence."""

    def test_empty_entity_returns_valid_context(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Empty entity returns a valid context with no evidence."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "unknown-host")

        assert context.entity_type == "host"
        assert context.entity_id == "unknown-host"
        assert context.annotation_key == "entity:host:unknown-host"
        assert context.correlation_key == "unknown-host:*"
        assert context.recent_alerts == ()
        assert context.behavior_summary == ()
        assert context.annotations == ()
        assert context.incident is None
        assert context.alert_count == 0
        assert context.annotation_count == 0
        assert context.has_evidence is False

    def test_empty_context_properties(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Empty context has correct property values."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("user", "unknown-user")

        assert context.alert_count == 0
        assert context.annotation_count == 0
        assert context.has_evidence is False


# ── Test: Entity Key Format ─────────────────────────────────────────────────


class TestEntityKeyFormats:
    """Tests verifying domain-specific entity key formats are explicit."""

    def test_annotation_key_uses_annotation_format(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Annotation key follows entity:{type}:{id} format."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        assert context.annotation_key == "entity:host:server01"

    def test_correlation_key_uses_correlation_format(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Correlation key uses host:* format for host entities."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        assert context.correlation_key == "server01:*"

    def test_keys_are_distinct(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Annotation and correlation keys are different formats."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        assert context.annotation_key != context.correlation_key
        assert context.annotation_key == "entity:host:server01"
        assert context.correlation_key == "server01:*"

    def test_entity_type_normalization(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Entity type is normalized to lowercase in both keys."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("HOST", "Server01")

        assert context.entity_type == "host"
        assert context.annotation_key == "entity:host:Server01"
        assert context.correlation_key == "Server01:*"


# ── Test: Entity with Alerts ─────────────────────────────────────────────────


class TestEntityWithAlerts:
    """Tests for entities with alerts."""

    def test_entity_with_alerts(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Entity with alerts returns alerts in context."""
        alert1 = make_alert(host="server01")
        alert2 = make_alert(host="server01")
        mock_alert_queue.list_by_entity.return_value = [alert1, alert2]
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        assert context.alert_count == 2
        assert context.recent_alerts == (alert1, alert2)
        assert context.has_evidence is True

    def test_alert_result_capped_at_50(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Alert results are capped at 50."""
        alerts = [make_alert(host="server01") for _ in range(60)]
        mock_alert_queue.list_by_entity.return_value = alerts
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        assert len(context.recent_alerts) == _MAX_ALERTS
        assert context.alert_count == _MAX_ALERTS

    def test_deterministic_alert_ordering(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Alert ordering is deterministic based on existing sort_alerts."""
        alert1 = make_alert(host="server01")
        alert2 = make_alert(host="server01")
        mock_alert_queue.list_by_entity.return_value = [alert1, alert2]
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context1 = service.get_investigation_context("host", "server01")
        context2 = service.get_investigation_context("host", "server01")

        assert context1.recent_alerts == context2.recent_alerts

    def test_alert_lookup_uses_correlation_key(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Alert lookup uses correlation key via list_by_entity."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        service.get_investigation_context("host", "server01")

        mock_alert_queue.list_by_entity.assert_called_once_with("server01:*", sort=True)


# ── Test: Entity with Behavior ──────────────────────────────────────────────


class TestEntityWithBehavior:
    """Tests for entities with behavioral summaries."""

    def test_entity_with_behavior(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Entity with behavior returns behavior summary."""
        behavior = [
            {
                "dimension": "process_name",
                "top_values": [("powershell.exe", 10), ("cmd.exe", 5)],
            }
        ]
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = behavior
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        assert len(context.behavior_summary) == 1
        assert context.behavior_summary[0]["dimension"] == "process_name"
        assert context.has_evidence is True

    def test_behavior_absence_returns_empty(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """No behavior returns empty tuple (not error)."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "new-host")

        assert context.behavior_summary == ()
        assert context.has_evidence is False


# ── Test: Entity with Annotations ──────────────────────────────────────────


class TestEntityWithAnnotations:
    """Tests for entities with analyst annotations."""

    def test_entity_with_annotations(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Entity with annotations returns annotations."""
        annotations = [
            {
                "annotation_id": str(uuid4()),
                "target_key": "entity:host:server01",
                "author": "analyst1",
                "created_at": datetime.now(UTC).isoformat(),
                "comment": "Known monitoring server",
                "tombstoned": False,
            }
        ]
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = annotations
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        assert context.annotation_count == 1
        assert context.annotations[0]["comment"] == "Known monitoring server"

    def test_annotation_result_capped(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Annotation results are capped at 20."""
        annotations = [
            {
                "annotation_id": str(uuid4()),
                "target_key": "entity:host:server01",
                "author": f"analyst{i}",
                "created_at": datetime.now(UTC).isoformat(),
                "comment": f"Comment {i}",
                "tombstoned": False,
            }
            for i in range(30)
        ]
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = annotations
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        assert len(context.annotations) == _MAX_ANNOTATIONS

    def test_annotations_are_decision_neutral(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Annotations do not affect decision logic - just returned as-is."""
        annotations = [
            {
                "annotation_id": str(uuid4()),
                "target_key": "entity:host:server01",
                "author": "analyst1",
                "created_at": datetime.now(UTC).isoformat(),
                "comment": "Ignore all alerts for this host",
                "tombstoned": False,
            }
        ]
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = annotations
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        assert context.annotations[0]["comment"] == "Ignore all alerts for this host"

    def test_annotation_lookup_uses_annotation_key(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Annotation lookup uses annotation key, not correlation key."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        service.get_investigation_context("host", "server01")

        mock_annotation_service.get_annotations_by_target.assert_called_once_with(
            target_key="entity:host:server01",
            include_tombstoned=False,
            limit=_MAX_ANNOTATIONS,
        )


# ── Test: Entity with Incident ──────────────────────────────────────────────


class TestEntityWithIncident:
    """Tests for entities with associated incidents."""

    def test_entity_with_incident(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Entity with incident returns the incident."""
        incident = make_incident(title="Suspicious Activity")
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = incident.incident_id
        mock_incident_service.get_incident.return_value = incident

        context = service.get_investigation_context("host", "server01")

        assert context.incident is not None
        assert context.incident.title == "Suspicious Activity"
        assert context.has_evidence is True

    def test_no_incident_returns_none(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """No incident returns None, not an error."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        assert context.incident is None

    def test_incident_lookup_uses_correlation_key(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Incident lookup uses correlation key, not annotation key."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        service.get_investigation_context("host", "server01")

        mock_incident_service.get_incident_for_entity.assert_called_once_with("server01:*")


# ── Test: Entity with All Evidence ─────────────────────────────────────────


class TestEntityWithAllEvidence:
    """Tests for entities with all evidence types."""

    def test_entity_with_all_evidence(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Entity with all evidence types returns complete context."""
        alert = make_alert(host="server01")
        behavior = [{"dimension": "process_name", "top_values": [("powershell.exe", 5)]}]
        annotations = [
            {
                "annotation_id": str(uuid4()),
                "target_key": "entity:host:server01",
                "author": "analyst1",
                "created_at": datetime.now(UTC).isoformat(),
                "comment": "Test comment",
                "tombstoned": False,
            }
        ]
        incident = make_incident()

        mock_alert_queue.list_by_entity.return_value = [alert]
        mock_behavior_service.get_entity_behavior.return_value = behavior
        mock_annotation_service.get_annotations_by_target.return_value = annotations
        mock_incident_service.get_incident_for_entity.return_value = incident.incident_id
        mock_incident_service.get_incident.return_value = incident

        context = service.get_investigation_context("host", "server01")

        assert context.alert_count == 1
        assert len(context.behavior_summary) == 1
        assert context.annotation_count == 1
        assert context.incident is not None
        assert context.has_evidence is True


# ── Test: Source Status ────────────────────────────────────────────────────


class TestSourceStatus:
    """Tests for per-source availability reporting."""

    def test_source_status_reported_for_all_sources(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """All four sources report status."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        sources = {k for k, _ in context.source_status}
        assert sources == {"alerts", "behavior", "annotations", "incident"}

    def test_empty_results_report_available(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Empty results are AVAILABE, not UNAVAILABLE."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        for source, status in context.source_status:
            assert status == SourceStatus.AVAILABLE, (
                f"Source '{source}' should be AVAILABLE but was {status}"
            )

    def test_get_source_status_helper(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """get_source_status helper returns correct status per source."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        assert context.get_source_status("alerts") == SourceStatus.AVAILABLE
        assert context.get_source_status("behavior") == SourceStatus.AVAILABLE
        assert context.get_source_status("annotations") == SourceStatus.AVAILABLE
        assert context.get_source_status("incident") == SourceStatus.AVAILABLE

    def test_get_source_status_unknown_source_raises_value_error(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Unknown source key raises ValueError."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("host", "server01")

        with pytest.raises(ValueError, match="Unknown source"):
            context.get_source_status("invalid_source")

    def test_source_status_distinguishes_absence_from_unavailability(
        self,
    ) -> None:
        """AVAILABLE with count=0 is materially different from UNAVAILABLE."""
        # AVAILABLE: source responded, no data exists
        available_context = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
            source_status=(
                ("alerts", SourceStatus.AVAILABLE),
                ("behavior", SourceStatus.AVAILABLE),
                ("annotations", SourceStatus.AVAILABLE),
                ("incident", SourceStatus.AVAILABLE),
            ),
        )
        # Check: AVAILABLE sources can have empty data
        assert available_context.recent_alerts == ()
        assert available_context.get_source_status("alerts") == SourceStatus.AVAILABLE

        # Note: Full UNAVAILABLE test would require injecting unexpected errors.
        # The service passes through unexpected errors rather than swallowing them,
        # so an UNAVAILABLE status in production means the source raised an
        # unexpected error that was caught at a higher level (or would propagate).
        # In unit tests with mocks, UNAVAILABLE requires special injection.

    def test_empty_and_unavailable_are_distinct(
        self,
    ) -> None:
        """AVAILABLE(empty) and UNAVAILABLE produce different context objects."""
        # Both contexts have empty alerts
        available = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
            source_status=(("alerts", SourceStatus.AVAILABLE),),
        )
        unavailable = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
            source_status=(("alerts", SourceStatus.UNAVAILABLE),),
        )

        # Both have zero alerts
        assert available.alert_count == 0
        assert unavailable.alert_count == 0

        # But different source status
        assert available.get_source_status("alerts") == SourceStatus.AVAILABLE
        assert unavailable.get_source_status("alerts") == SourceStatus.UNAVAILABLE


# ── Test: Unexpected Error Propagation ─────────────────────────────────────


class TestUnexpectedErrorPropagation:
    """Tests verifying unexpected errors are not silently swallowed."""

    def test_unexpected_alert_error_propagates(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Unexpected errors from AlertQueue are not caught."""
        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        # Unexpected error (not ValueError)
        mock_alert_queue.list_by_entity.side_effect = RuntimeError("queue corrupted")
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        with pytest.raises(RuntimeError, match="queue corrupted"):
            service.get_investigation_context("host", "server01")

    def test_unexpected_behavior_error_propagates(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Unexpected errors from behavior service are not caught."""
        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        mock_alert_queue.list_by_entity.return_value = []
        # Unexpected error (not ValueError)
        mock_behavior_service.get_entity_behavior.side_effect = RuntimeError("DB error")
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        with pytest.raises(RuntimeError, match="DB error"):
            service.get_investigation_context("host", "server01")

    def test_annotation_runtime_error_returns_unavailable(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """RuntimeError from annotation service returns UNAVAILABLE (recoverable failure).

        RuntimeError is used by AnalystAnnotationService for capacity/limit errors,
        which are considered recoverable source-access failures, not programming errors.
        """
        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        # RuntimeError from annotation service indicates capacity/limit issues
        mock_annotation_service.get_annotations_by_target.side_effect = RuntimeError(
            "persistence error"
        )
        mock_incident_service.get_incident_for_entity.return_value = None

        # Should NOT raise - RuntimeError is caught as recoverable source failure
        context = service.get_investigation_context("host", "server01")

        # Annotations source is unavailable
        assert context.get_source_status("annotations") == SourceStatus.UNAVAILABLE
        # Other sources are still available
        assert context.get_source_status("alerts") == SourceStatus.AVAILABLE
        assert context.get_source_status("behavior") == SourceStatus.AVAILABLE
        assert context.get_source_status("incident") == SourceStatus.AVAILABLE

    def test_unexpected_error_propagates(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Unexpected errors (not ValueError, not RuntimeError) propagate."""
        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        # KeyError is not a classified exception type - should propagate
        mock_annotation_service.get_annotations_by_target.side_effect = KeyError(
            "unexpected key error"
        )
        mock_incident_service.get_incident_for_entity.return_value = None

        with pytest.raises(KeyError, match="unexpected key error"):
            service.get_investigation_context("host", "server01")


# ── Test: Input Validation ──────────────────────────────────────────────────


class TestInputValidation:
    """Tests for input validation."""

    def test_invalid_entity_type_empty(self, service: InvestigationContextService) -> None:
        """Empty entity_type raises ValueError."""
        with pytest.raises(ValueError, match="entity_type must not be empty"):
            service.get_investigation_context("", "some-id")

    def test_invalid_entity_type_too_long(self, service: InvestigationContextService) -> None:
        """entity_type exceeding max length raises ValueError."""
        long_type = "a" * 100
        with pytest.raises(ValueError, match="exceeds maximum length"):
            service.get_investigation_context(long_type, "some-id")

    def test_invalid_entity_id_empty(self, service: InvestigationContextService) -> None:
        """Empty entity_id raises ValueError."""
        with pytest.raises(ValueError, match="entity_id must not be empty"):
            service.get_investigation_context("host", "")

    def test_invalid_entity_id_too_long(self, service: InvestigationContextService) -> None:
        """entity_id exceeding max length raises ValueError."""
        long_id = "b" * 300
        with pytest.raises(ValueError, match="exceeds maximum length"):
            service.get_investigation_context("host", long_id)

    def test_invalid_entity_type_special_chars(self, service: InvestigationContextService) -> None:
        """entity_type with invalid characters raises ValueError."""
        with pytest.raises(ValueError, match="must contain only alphanumeric"):
            service.get_investigation_context("host@invalid!", "some-id")

    def test_valid_entity_types(self, service: InvestigationContextService) -> None:
        """Valid entity types are accepted."""
        mock_alert_queue = MagicMock(spec=AlertQueue)
        mock_behavior_service = MagicMock(spec=AnalystBehaviorQueryService)
        mock_annotation_service = MagicMock(spec=AnalystAnnotationService)
        mock_incident_service = MagicMock(spec=IncidentService)

        # Inject mocks
        service._alert_queue = mock_alert_queue
        service._behavior_service = mock_behavior_service
        service._annotation_service = mock_annotation_service
        service._incident_service = mock_incident_service

        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        # These should not raise
        for entity_type in ["host", "src_ip", "dst_ip", "user", "process_name", "some-type"]:
            context = service.get_investigation_context(entity_type, "some-id")
            assert context.entity_type == entity_type.lower()


# ── Test: No Source Mutation ────────────────────────────────────────────────


class TestNoSourceMutation:
    """Tests verifying the read-only guarantee."""

    def test_alert_queue_not_modified(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """AlertQueue is not modified during context retrieval."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        service.get_investigation_context("host", "server01")

        # Verify no mutation methods were called
        mock_alert_queue.enqueue.assert_not_called()
        mock_alert_queue.get.assert_not_called()

    def test_annotation_service_not_modified(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """AnnotationService is not modified during context retrieval."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        service.get_investigation_context("host", "server01")

        # Verify no mutation methods were called
        mock_annotation_service.create_annotation.assert_not_called()
        mock_annotation_service.tombstone_annotation.assert_not_called()

    def test_incident_service_not_modified(
        self,
        service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """IncidentService is not modified during context retrieval."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        service.get_investigation_context("host", "server01")

        # Verify no mutation methods were called
        mock_incident_service.create_incident.assert_not_called()
        mock_incident_service.associate_alert.assert_not_called()


# ── Test: Context Model ─────────────────────────────────────────────────────


class TestEntityInvestigationContextModel:
    """Tests for the EntityInvestigationContext model."""

    def test_context_is_immutable(
        self,
    ) -> None:
        """Context fields are read-only after construction."""
        context = EntityInvestigationContext.empty(
            "host", "server01", "entity:host:server01", "server01:*"
        )

        with pytest.raises(AttributeError):
            context.entity_type = "user"

        with pytest.raises(AttributeError):
            context.recent_alerts = ()

    def test_empty_context_factory(
        self,
    ) -> None:
        """empty() factory creates valid empty context."""
        context = EntityInvestigationContext.empty(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
        )

        assert context.entity_type == "host"
        assert context.entity_id == "server01"
        assert context.annotation_key == "entity:host:server01"
        assert context.correlation_key == "server01:*"
        assert context.recent_alerts == ()
        assert context.behavior_summary == ()
        assert context.annotations == ()
        assert context.incident is None
        assert context.has_evidence is False

    def test_context_with_incident_has_evidence(
        self,
    ) -> None:
        """Context with incident has_evidence is True."""
        incident = make_incident()
        context = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
            incident=incident,
        )

        assert context.has_evidence is True

    def test_source_status_tuple_format(
        self,
    ) -> None:
        """source_status is a tuple of (source, status) tuples."""
        context = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
            source_status=(
                ("alerts", SourceStatus.AVAILABLE),
                ("behavior", SourceStatus.AVAILABLE),
            ),
        )

        assert isinstance(context.source_status, tuple)
        assert all(isinstance(item, tuple) for item in context.source_status)
        assert all(
            isinstance(k, str) and isinstance(v, SourceStatus) for k, v in context.source_status
        )

    def test_source_status_enum_values(
        self,
    ) -> None:
        """SourceStatus enum has correct string values."""
        assert SourceStatus.AVAILABLE.value == "AVAILABLE"
        assert SourceStatus.UNAVAILABLE.value == "UNAVAILABLE"


# ── Test: Partial Context (Source Failures) ─────────────────────────────────


class TestPartialContextBehavior:
    """Tests for partial context when one or more sources fail.

    These tests verify that when exactly one source becomes unavailable:
    - The other available sources are still returned
    - The failed source is represented as UNAVAILABLE
    - Empty data from a healthy source remains AVAILABLE
    - The service does not confuse "no evidence" with "source unavailable"

    Source failure classification:
        - AlertQueueError → UNAVAILABLE (recoverable)
        - RuntimeError from annotations → UNAVAILABLE (recoverable capacity error)
        - RuntimeError from behavior → propagate (unexpected)
        - RuntimeError from incident → propagate (unexpected)
        - Other exceptions → propagate (unexpected)
    """

    def test_alerts_unavailable_other_sources_work(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """When alert source is unavailable (AlertQueueError), other sources still return data."""
        from argusprowl.lifecycle.queue import AlertQueueError

        # Inject actual alert data
        make_alert(host="server01")
        behavior = [{"dimension": "process_name", "top_values": [("cmd.exe", 5)]}]
        annotations = [
            {
                "annotation_id": str(uuid4()),
                "target_key": "entity:host:server01",
                "author": "analyst1",
                "created_at": datetime.now(UTC).isoformat(),
                "comment": "Test",
                "tombstoned": False,
            }
        ]
        incident = make_incident()

        mock_alert_queue.list_by_entity.side_effect = AlertQueueError("queue corrupted")
        mock_behavior_service.get_entity_behavior.return_value = behavior
        mock_annotation_service.get_annotations_by_target.return_value = annotations
        mock_incident_service.get_incident_for_entity.return_value = incident.incident_id
        mock_incident_service.get_incident.return_value = incident

        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        context = service.get_investigation_context("host", "server01")

        # Alerts source is unavailable
        assert context.get_source_status("alerts") == SourceStatus.UNAVAILABLE
        assert context.recent_alerts == ()

        # Other sources are still available with data
        assert context.get_source_status("behavior") == SourceStatus.AVAILABLE
        assert context.behavior_summary == tuple(behavior)

        assert context.get_source_status("annotations") == SourceStatus.AVAILABLE
        assert len(context.annotations) == 1

        assert context.get_source_status("incident") == SourceStatus.AVAILABLE
        assert context.incident is not None

        # has_evidence is True because other sources have data
        assert context.has_evidence is True

    def test_annotations_unavailable_other_sources_work(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """When annotation source is unavailable (RuntimeError), other sources still return data."""
        alert = make_alert(host="server01")
        behavior = [{"dimension": "process_name", "top_values": [("powershell.exe", 10)]}]

        mock_alert_queue.list_by_entity.return_value = [alert]
        mock_behavior_service.get_entity_behavior.return_value = behavior
        # RuntimeError from annotations is caught as recoverable capacity error
        mock_annotation_service.get_annotations_by_target.side_effect = RuntimeError(
            "annotation limit exceeded"
        )
        mock_incident_service.get_incident_for_entity.return_value = None

        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        context = service.get_investigation_context("host", "server01")

        # Annotations source is unavailable
        assert context.get_source_status("annotations") == SourceStatus.UNAVAILABLE
        assert context.annotations == ()

        # Other sources are available
        assert context.get_source_status("alerts") == SourceStatus.AVAILABLE
        assert context.get_source_status("behavior") == SourceStatus.AVAILABLE
        assert context.get_source_status("incident") == SourceStatus.AVAILABLE

    def test_all_sources_unavailable(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """When all recoverable sources are unavailable, context still returns with UNAVAILABLE."""
        from argusprowl.lifecycle.queue import AlertQueueError

        mock_alert_queue.list_by_entity.side_effect = AlertQueueError("queue down")
        mock_annotation_service.get_annotations_by_target.side_effect = RuntimeError("storage down")
        mock_incident_service.get_incident_for_entity.return_value = None

        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        context = service.get_investigation_context("host", "server01")

        # Recoverable sources are unavailable
        assert context.get_source_status("alerts") == SourceStatus.UNAVAILABLE
        assert context.get_source_status("annotations") == SourceStatus.UNAVAILABLE

        # Behavior and incident are still queried (no error, returns empty)
        assert context.get_source_status("behavior") == SourceStatus.AVAILABLE
        assert context.get_source_status("incident") == SourceStatus.AVAILABLE

        # But context is still valid and has basic fields
        assert context.entity_type == "host"
        assert context.entity_id == "server01"
        assert context.has_evidence is False

    def test_healthy_empty_source_remains_available(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """No evidence is AVAILABE, not UNAVAILABLE - these are distinct."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        context = service.get_investigation_context("host", "new-host")

        # All sources are AVAILABLE (no data, but sources are healthy)
        for source, status in context.source_status:
            assert status == SourceStatus.AVAILABLE, f"{source} should be AVAILABLE"

        # No evidence
        assert context.has_evidence is False

    def test_unrelated_unexpected_error_still_propagates(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Unexpected error types propagate even if other sources work."""
        mock_alert_queue.list_by_entity.return_value = []
        mock_behavior_service.get_entity_behavior.return_value = []
        # KeyError is not classified - should propagate
        mock_annotation_service.get_annotations_by_target.side_effect = KeyError("unexpected")
        mock_incident_service.get_incident_for_entity.return_value = None

        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        with pytest.raises(KeyError):
            service.get_investigation_context("host", "server01")


# ── Test: Non-Host Entity Types ────────────────────────────────────────────


class TestNonHostEntityTypes:
    """Tests for non-host entity types.

    Only 'host' entity type supports alert/incident correlation.
    Other entity types (src_ip, dst_ip, user, etc.) should:
    - Return empty alerts/incident (no fabricated correlation keys)
    - Return annotations and behavior normally
    - Mark alerts/incident sources as AVAILABLE with empty data
    """

    def test_non_host_entity_skips_alert_lookup(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Non-host entity types do not query alerts (correlation model is host-centric)."""
        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("src_ip", "192.168.1.100")

        # Alert queue should NOT be called for non-host entities
        mock_alert_queue.list_by_entity.assert_not_called()

        # Alerts are empty and marked UNSUPPORTED (no query performed)
        assert context.recent_alerts == ()
        assert context.get_source_status("alerts") == SourceStatus.UNSUPPORTED

        # Behavior and annotations are still queried
        mock_behavior_service.get_entity_behavior.assert_called_once()
        mock_annotation_service.get_annotations_by_target.assert_called_once()

    def test_non_host_entity_skips_incident_lookup(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Non-host entity types do not query incidents (correlation model is host-centric)."""
        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        context = service.get_investigation_context("dst_ip", "10.0.0.1")

        # Incident service should NOT be called for non-host entities
        mock_incident_service.get_incident_for_entity.assert_not_called()

        # Incident is None and marked UNSUPPORTED (no query performed)
        assert context.incident is None
        assert context.get_source_status("incident") == SourceStatus.UNSUPPORTED

    def test_non_host_entity_returns_annotation_key(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Non-host entities still use annotation key format for annotation lookup."""
        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []

        context = service.get_investigation_context("user", "admin")

        # Annotation key uses the correct format
        assert context.annotation_key == "entity:user:admin"

        # Correlation key is empty for non-host entities (no alert/incident support)
        assert context.correlation_key == ""

        # Alert and incident are UNSUPPORTED (no query performed)
        assert context.get_source_status("alerts") == SourceStatus.UNSUPPORTED
        assert context.get_source_status("incident") == SourceStatus.UNSUPPORTED

        # Annotation service is called with correct key
        mock_annotation_service.get_annotations_by_target.assert_called_once_with(
            target_key="entity:user:admin",
            include_tombstoned=False,
            limit=_MAX_ANNOTATIONS,
        )

    def test_non_host_entity_behavior_works(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Non-host entities can still query behavior data."""
        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        behavior = [{"dimension": "src_ip", "top_values": [("192.168.1.100", 50)]}]
        mock_behavior_service.get_entity_behavior.return_value = behavior
        mock_annotation_service.get_annotations_by_target.return_value = []

        context = service.get_investigation_context("src_ip", "192.168.1.100")

        # Behavior is queried and returned
        mock_behavior_service.get_entity_behavior.assert_called_once_with(
            entity_type="src_ip",
            entity_id="192.168.1.100",
        )
        assert context.behavior_summary == tuple(behavior)
        assert context.get_source_status("behavior") == SourceStatus.AVAILABLE

    def test_non_host_entity_annotation_works(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Non-host entities can still query annotation data."""
        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        annotations = [
            {
                "annotation_id": str(uuid4()),
                "target_key": "entity:user:admin",
                "author": "analyst1",
                "created_at": datetime.now(UTC).isoformat(),
                "comment": "Known admin account",
                "tombstoned": False,
            }
        ]
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = annotations

        context = service.get_investigation_context("user", "admin")

        # Annotations are queried and returned
        assert context.annotation_count == 1
        assert context.annotations[0]["comment"] == "Known admin account"
        assert context.get_source_status("annotations") == SourceStatus.AVAILABLE

    def test_host_entity_has_full_support(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Host entity type has full support for all evidence types."""
        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        alert = make_alert(host="server01")
        behavior = [{"dimension": "process_name", "top_values": [("powershell.exe", 10)]}]
        annotations = [
            {
                "annotation_id": str(uuid4()),
                "target_key": "entity:host:server01",
                "author": "analyst",
                "created_at": datetime.now(UTC).isoformat(),
                "comment": "Test",
                "tombstoned": False,
            }
        ]
        incident = make_incident()

        mock_alert_queue.list_by_entity.return_value = [alert]
        mock_behavior_service.get_entity_behavior.return_value = behavior
        mock_annotation_service.get_annotations_by_target.return_value = annotations
        mock_incident_service.get_incident_for_entity.return_value = incident.incident_id
        mock_incident_service.get_incident.return_value = incident

        context = service.get_investigation_context("host", "server01")

        # All sources are queried
        mock_alert_queue.list_by_entity.assert_called_once()
        mock_incident_service.get_incident_for_entity.assert_called_once()

        # Correlation key is set for host entities
        assert context.correlation_key == "server01:*"

        # All evidence types are returned
        assert context.alert_count == 1
        assert len(context.behavior_summary) == 1
        assert context.annotation_count == 1
        assert context.incident is not None
        assert context.has_evidence is True


# ── Test: Deterministic and Immutable Output ───────────────────────────────


class TestDeterministicImmutableOutput:
    """Tests for deterministic and immutable output."""

    def test_context_deterministic(
        self,
        mock_alert_queue: MagicMock,
        mock_behavior_service: MagicMock,
        mock_annotation_service: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Context output is deterministic - same query returns same result."""
        alert = make_alert(host="server01")
        mock_alert_queue.list_by_entity.return_value = [alert]
        mock_behavior_service.get_entity_behavior.return_value = []
        mock_annotation_service.get_annotations_by_target.return_value = []
        mock_incident_service.get_incident_for_entity.return_value = None

        service = InvestigationContextService(
            alert_queue=mock_alert_queue,
            behavior_query_service=mock_behavior_service,
            annotation_service=mock_annotation_service,
            incident_service=mock_incident_service,
        )

        context1 = service.get_investigation_context("host", "server01")
        context2 = service.get_investigation_context("host", "server01")

        assert context1.entity_type == context2.entity_type
        assert context1.entity_id == context2.entity_id
        assert context1.recent_alerts == context2.recent_alerts
        assert context1.source_status == context2.source_status

    def test_context_immutable_fields(
        self,
    ) -> None:
        """Context fields cannot be modified after construction."""
        context = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
        )

        # Cannot modify entity_type
        with pytest.raises(AttributeError):
            context.entity_type = "user"

        # Cannot modify recent_alerts
        with pytest.raises(AttributeError):
            context.recent_alerts = ()

        # Cannot modify source_status
        with pytest.raises(AttributeError):
            context.source_status = (("alerts", SourceStatus.AVAILABLE),)

    def test_source_status_tuple_immutable(
        self,
    ) -> None:
        """source_status tuple itself cannot be modified."""
        context = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
            source_status=(("alerts", SourceStatus.AVAILABLE),),
        )

        # Cannot modify the tuple
        with pytest.raises(TypeError):
            context.source_status[0] = ("behavior", SourceStatus.AVAILABLE)

    def test_source_status_enum_values(self) -> None:
        """SourceStatus enum has correct string values."""
        assert SourceStatus.AVAILABLE.value == "AVAILABLE"
        assert SourceStatus.UNAVAILABLE.value == "UNAVAILABLE"
        assert SourceStatus.UNSUPPORTED.value == "UNSUPPORTED"

    def test_get_source_status_raises_for_unknown_source(self) -> None:
        """Unknown source names raise ValueError, not silently return UNAVAILABLE."""
        context = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
            source_status=(
                ("alerts", SourceStatus.AVAILABLE),
                ("behavior", SourceStatus.AVAILABLE),
                ("annotations", SourceStatus.AVAILABLE),
                ("incident", SourceStatus.AVAILABLE),
            ),
        )

        # Valid sources work
        assert context.get_source_status("alerts") == SourceStatus.AVAILABLE
        assert context.get_source_status("behavior") == SourceStatus.AVAILABLE
        assert context.get_source_status("annotations") == SourceStatus.AVAILABLE
        assert context.get_source_status("incident") == SourceStatus.AVAILABLE

        # Unknown source raises ValueError
        with pytest.raises(ValueError, match="Unknown source 'invalid_source'"):
            context.get_source_status("invalid_source")

    def test_unsupported_status_for_non_host_alerts(self) -> None:
        """Non-host entities get UNSUPPORTED for alerts (no query performed)."""
        context = EntityInvestigationContext(
            entity_type="src_ip",
            entity_id="192.168.1.100",
            annotation_key="entity:src_ip:192.168.1.100",
            correlation_key="",
            source_status=(
                ("alerts", SourceStatus.UNSUPPORTED),
                ("behavior", SourceStatus.AVAILABLE),
                ("annotations", SourceStatus.AVAILABLE),
                ("incident", SourceStatus.UNSUPPORTED),
            ),
        )

        assert context.get_source_status("alerts") == SourceStatus.UNSUPPORTED
        assert context.get_source_status("incident") == SourceStatus.UNSUPPORTED
        assert context.get_source_status("behavior") == SourceStatus.AVAILABLE
        assert context.get_source_status("annotations") == SourceStatus.AVAILABLE

    def test_unsupported_status_distinguishes_from_available(self) -> None:
        """UNSUPPORTED is distinct from AVAILABLE - no query vs empty query."""
        # UNSUPPORTED: no query performed (entity type not supported)
        unsupported = EntityInvestigationContext(
            entity_type="src_ip",
            entity_id="192.168.1.100",
            annotation_key="entity:src_ip:192.168.1.100",
            correlation_key="",
            source_status=(
                ("alerts", SourceStatus.UNSUPPORTED),
                ("behavior", SourceStatus.AVAILABLE),
                ("annotations", SourceStatus.AVAILABLE),
                ("incident", SourceStatus.UNSUPPORTED),
            ),
        )

        # AVAILABLE: query performed, no data found
        available = EntityInvestigationContext(
            entity_type="host",
            entity_id="unknown-host",
            annotation_key="entity:host:unknown-host",
            correlation_key="unknown-host:*",
            source_status=(
                ("alerts", SourceStatus.AVAILABLE),
                ("behavior", SourceStatus.AVAILABLE),
                ("annotations", SourceStatus.AVAILABLE),
                ("incident", SourceStatus.AVAILABLE),
            ),
        )

        # Both have empty alerts
        assert unsupported.recent_alerts == ()
        assert available.recent_alerts == ()

        # But different status
        assert unsupported.get_source_status("alerts") == SourceStatus.UNSUPPORTED
        assert available.get_source_status("alerts") == SourceStatus.AVAILABLE

        # Critical invariant: no query != empty query
        assert unsupported.get_source_status("alerts") != available.get_source_status("alerts")

    def test_degraded_status_exists_in_enum(self) -> None:
        """SourceStatus.DEGRADED exists and has correct value."""
        assert hasattr(SourceStatus, "DEGRADED")
        assert SourceStatus.DEGRADED.value == "DEGRADED"

    def test_degraded_status_distinguishes_from_available(self) -> None:
        """DEGRADED is distinct from AVAILABLE - partial evidence vs complete."""
        degraded = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
            source_status=(
                ("alerts", SourceStatus.DEGRADED),
                ("behavior", SourceStatus.AVAILABLE),
                ("annotations", SourceStatus.AVAILABLE),
                ("incident", SourceStatus.AVAILABLE),
            ),
        )
        available = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
            source_status=(
                ("alerts", SourceStatus.AVAILABLE),
                ("behavior", SourceStatus.AVAILABLE),
                ("annotations", SourceStatus.AVAILABLE),
                ("incident", SourceStatus.AVAILABLE),
            ),
        )

        # Both can have alerts
        assert degraded.get_source_status("alerts") == SourceStatus.DEGRADED
        assert available.get_source_status("alerts") == SourceStatus.AVAILABLE
        assert degraded.get_source_status("alerts") != available.get_source_status("alerts")
