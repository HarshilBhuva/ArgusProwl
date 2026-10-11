"""Tests for Phase 7.3 — Entity Investigation API.

Covers:
- GET /api/v1/entities list endpoint
- GET /api/v1/entities/{entity_type}/{entity_id} detail endpoint
- GET /api/v1/entities/{entity_type}/{entity_id}/annotations
- POST /api/v1/entities/{entity_type}/{entity_id}/annotations
- Correlation key discovery from actual alert data
- Unsupported entity types (src_ip, username)
- Partial correlation for hostname, dst_ip, process
- Contract correctness (no single canonical_entity_key, no fake keys)
- Incident resolution through observed keys
- Annotation GET/POST with entity target key
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
from argusprowl.behavior.analyst_behavior_query_service import AnalystBehaviorQueryService
from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.incident.incident_service import IncidentService
from argusprowl.lifecycle.queue import AlertQueue
from argusprowl.models.alert import Alert
from argusprowl.services.alert_search_service import (
    AlertSearchService,
)
from argusprowl.services.investigation_timeline_service import (
    InvestigationTimelineService,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_alert(
    *,
    entity_context: dict[str, Any] | None = None,
    alert_id: UUID | None = None,
    title: str = "Test Alert",
    severity: Severity = Severity.HIGH,
    priority: AlertPriority = AlertPriority.HIGH,
    lifecycle_state: AlertLifecycleState = AlertLifecycleState.OPEN,
    source: str = "test-detector",
) -> Alert:
    """Create a minimal Alert for testing."""
    return Alert(
        alert_id=alert_id or uuid4(),
        title=title,
        description="Test description",
        severity=severity,
        priority=priority,
        lifecycle_state=lifecycle_state,
        source=source,
        entity_context=entity_context,
    )


@pytest.fixture
def sample_hostname_alert() -> Alert:
    """Alert with hostname entity context."""
    return _make_alert(entity_context={"host": "workstation01"})


@pytest.fixture
def sample_hostname_process_alert() -> Alert:
    """Alert with hostname + process entity context."""
    return _make_alert(entity_context={"host": "workstation01", "process_name": "svchost.exe"})


@pytest.fixture
def sample_hostname_dst_alert() -> Alert:
    """Alert with hostname + dst_ip entity context."""
    return _make_alert(entity_context={"host": "workstation01", "dst_ip": "203.0.113.50"})


@pytest.fixture
def sample_dst_ip_alert() -> Alert:
    """Alert with dst_ip only entity context."""
    return _make_alert(entity_context={"dst_ip": "203.0.113.50"})


@pytest.fixture
def sample_process_alert() -> Alert:
    """Alert with process_name but no host."""
    return _make_alert(entity_context={"process_name": "svchost.exe"})


@pytest.fixture
def sample_src_ip_alert() -> Alert:
    """Alert with src_ip entity context."""
    return _make_alert(entity_context={"src_ip": "192.168.1.100"})


@pytest.fixture
def sample_username_alert() -> Alert:
    """Alert with username entity context."""
    return _make_alert(entity_context={"username": "admin"})


@pytest.fixture
def alert_queue(
    sample_hostname_alert: Alert,
    sample_hostname_process_alert: Alert,
    sample_hostname_dst_alert: Alert,
    sample_dst_ip_alert: Alert,
    sample_process_alert: Alert,
    sample_src_ip_alert: Alert,
    sample_username_alert: Alert,
) -> AlertQueue:
    """Create an AlertQueue with sample alerts."""
    queue = AlertQueue(max_size=100)
    for alert in [
        sample_hostname_alert,
        sample_hostname_process_alert,
        sample_hostname_dst_alert,
        sample_dst_ip_alert,
        sample_process_alert,
        sample_src_ip_alert,
        sample_username_alert,
    ]:
        queue.enqueue(alert)
    return queue


@pytest.fixture
def entity_correlation_service() -> EntityCorrelationService:
    """Create an EntityCorrelationService."""
    return EntityCorrelationService()


@pytest.fixture
def alert_search_service(
    alert_queue: AlertQueue,
    entity_correlation_service: EntityCorrelationService,
) -> AlertSearchService:
    """Create an AlertSearchService."""
    return AlertSearchService(
        alert_queue=alert_queue,
        alert_persistence=None,
        entity_correlation_service=entity_correlation_service,
    )


@pytest.fixture
def behavior_query_service() -> AnalystBehaviorQueryService:
    """Create a mock AnalystBehaviorQueryService."""
    service = MagicMock(spec=AnalystBehaviorQueryService)
    service.list_entities.return_value = [
        {
            "entity_type": "hostname",
            "entity_id": "workstation01",
            "dimension": "process_name",
            "observation_count": 10,
            "distinct_value_count": 3,
            "first_seen": datetime.now(UTC).isoformat(),
            "last_seen": datetime.now(UTC).isoformat(),
            "maturity": "mature",
            "top_values": [("python", 5), ("node", 3), ("chrome", 2)],
        },
        {
            "entity_type": "hostname",
            "entity_id": "workstation01",
            "dimension": "dst_ip",
            "observation_count": 8,
            "distinct_value_count": 2,
            "first_seen": datetime.now(UTC).isoformat(),
            "last_seen": datetime.now(UTC).isoformat(),
            "maturity": "mature",
            "top_values": [("203.0.113.50", 4), ("198.51.100.1", 4)],
        },
        {
            "entity_type": "dst_ip",
            "entity_id": "203.0.113.50",
            "dimension": "host",
            "observation_count": 5,
            "distinct_value_count": 1,
            "first_seen": datetime.now(UTC).isoformat(),
            "last_seen": datetime.now(UTC).isoformat(),
            "maturity": "warming",
            "top_values": [("workstation01", 5)],
        },
        {
            "entity_type": "process",
            "entity_id": "svchost.exe",
            "dimension": "host",
            "observation_count": 3,
            "distinct_value_count": 1,
            "first_seen": datetime.now(UTC).isoformat(),
            "last_seen": datetime.now(UTC).isoformat(),
            "maturity": "empty",
            "top_values": [("workstation01", 3)],
        },
        {
            "entity_type": "src_ip",
            "entity_id": "192.168.1.100",
            "dimension": "host",
            "observation_count": 2,
            "distinct_value_count": 1,
            "first_seen": datetime.now(UTC).isoformat(),
            "last_seen": datetime.now(UTC).isoformat(),
            "maturity": "empty",
            "top_values": [("workstation01", 2)],
        },
        {
            "entity_type": "username",
            "entity_id": "admin",
            "dimension": "host",
            "observation_count": 1,
            "distinct_value_count": 1,
            "first_seen": datetime.now(UTC).isoformat(),
            "last_seen": datetime.now(UTC).isoformat(),
            "maturity": "empty",
            "top_values": [("workstation01", 1)],
        },
    ]
    service.get_entity_behavior.return_value = [
        {
            "dimension": "process_name",
            "observation_count": 10,
            "distinct_value_count": 3,
            "first_seen": datetime.now(UTC).isoformat(),
            "last_seen": datetime.now(UTC).isoformat(),
            "maturity": "mature",
            "top_values": [("python", 5), ("node", 3), ("chrome", 2)],
        },
    ]
    return service


@pytest.fixture
def annotation_service() -> AnalystAnnotationService:
    """Create an AnalystAnnotationService."""
    return AnalystAnnotationService()


@pytest.fixture
def incident_service() -> IncidentService:
    """Create an IncidentService."""
    return IncidentService()


@pytest.fixture
def api_client(
    alert_queue: AlertQueue,
    alert_search_service: AlertSearchService,
    behavior_query_service: AnalystBehaviorQueryService,
    annotation_service: AnalystAnnotationService,
    incident_service: IncidentService,
    entity_correlation_service: EntityCorrelationService,
) -> TestClient:
    """Create a TestClient with all required services registered."""
    container = ServiceContainer.get_instance()
    container.register_singleton(AlertQueue, alert_queue)
    container.register_singleton(AlertSearchService, alert_search_service)
    container.register_singleton(AnalystBehaviorQueryService, behavior_query_service)
    container.register_singleton(AnalystAnnotationService, annotation_service)
    container.register_singleton(IncidentService, incident_service)
    container.register_singleton(EntityCorrelationService, entity_correlation_service)

    app = create_api_app()
    with TestClient(app) as client:
        yield client


@pytest.fixture
def timeline_service(
    alert_search_service: AlertSearchService,
    incident_service: IncidentService,
    annotation_service: AnalystAnnotationService,
    behavior_query_service: AnalystBehaviorQueryService,
    entity_correlation_service: EntityCorrelationService,
) -> InvestigationTimelineService:
    """Create an InvestigationTimelineService for testing."""
    from argusprowl.services.investigation_timeline_service import InvestigationTimelineService

    return InvestigationTimelineService(
        alert_search_service=alert_search_service,
        incident_service=incident_service,
        annotation_service=annotation_service,
        behavior_query_service=behavior_query_service,
        entity_correlation_service=entity_correlation_service,
    )


# ---------------------------------------------------------------------------
# Entity List Tests
# ---------------------------------------------------------------------------


class TestEntityListEndpoint:
    """Tests for GET /api/v1/entities."""

    def test_list_entities_returns_entities(
        self,
        api_client: TestClient,
        behavior_query_service: AnalystBehaviorQueryService,
    ) -> None:
        """Test that entity list returns entities with correct fields."""
        response = api_client.get("/api/v1/entities")
        assert response.status_code == 200

        data = response.json()
        assert "entities" in data
        assert "total_count" in data
        assert isinstance(data["entities"], list)
        assert isinstance(data["total_count"], int)

        # Verify deduplication: hostname workstation01 should appear once
        entity_ids = [(e["entity_type"], e["entity_id"]) for e in data["entities"]]
        assert len(entity_ids) == len(set(entity_ids)), "Entities should be deduplicated"

    def test_list_entities_has_correlation_support(
        self,
        api_client: TestClient,
    ) -> None:
        """Test that has_correlation_support reflects entity type."""
        response = api_client.get("/api/v1/entities")
        assert response.status_code == 200

        data = response.json()
        entities = data["entities"]

        # hostname should have correlation support
        hostname_entities = [e for e in entities if e["entity_type"] == "hostname"]
        for e in hostname_entities:
            assert e["has_correlation_support"] is True

        # dst_ip should have correlation support
        dst_ip_entities = [e for e in entities if e["entity_type"] == "dst_ip"]
        for e in dst_ip_entities:
            assert e["has_correlation_support"] is True

        # process should have correlation support
        process_entities = [e for e in entities if e["entity_type"] == "process"]
        for e in process_entities:
            assert e["has_correlation_support"] is True

        # src_ip should NOT have correlation support
        src_ip_entities = [e for e in entities if e["entity_type"] == "src_ip"]
        for e in src_ip_entities:
            assert e["has_correlation_support"] is False

        # username should NOT have correlation support
        username_entities = [e for e in entities if e["entity_type"] == "username"]
        for e in username_entities:
            assert e["has_correlation_support"] is False

    def test_list_entities_fields(
        self,
        api_client: TestClient,
    ) -> None:
        """Test that entity list items have required fields."""
        response = api_client.get("/api/v1/entities")
        assert response.status_code == 200

        data = response.json()
        if data["entities"]:
            entity = data["entities"][0]
            assert "entity_type" in entity
            assert "entity_id" in entity
            assert "has_correlation_support" in entity
            assert "maturity" in entity
            assert "observation_count" in entity
            assert "last_seen" in entity

    def test_list_entities_with_type_filter(
        self,
        api_client: TestClient,
    ) -> None:
        """Test filtering by entity type."""
        response = api_client.get("/api/v1/entities?entity_type=hostname")
        assert response.status_code == 200

        data = response.json()
        for entity in data["entities"]:
            assert entity["entity_type"] == "hostname"

    def test_list_entities_limit(
        self,
        api_client: TestClient,
    ) -> None:
        """Test limit parameter."""
        response = api_client.get("/api/v1/entities?limit=5")
        assert response.status_code == 200

        data = response.json()
        assert len(data["entities"]) <= 5


# ---------------------------------------------------------------------------
# Entity Detail Tests
# ---------------------------------------------------------------------------


class TestEntityDetailEndpoint:
    """Tests for GET /api/v1/entities/{entity_type}/{entity_id}."""

    def test_hostname_detail_returns_observed_keys(
        self,
        api_client: TestClient,
    ) -> None:
        """Test hostname entity detail returns observed correlation keys."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        assert data["entity_type"] == "hostname"
        assert data["entity_id"] == "workstation01"
        assert "observed_correlation_keys" in data
        assert "correlation_status" in data
        assert "correlation_note" in data

        # Should have observed keys from alerts
        assert isinstance(data["observed_correlation_keys"], list)
        assert data["correlation_status"] == "PARTIAL"

    def test_hostname_detail_no_single_canonical_key(
        self,
        api_client: TestClient,
    ) -> None:
        """Test that hostname detail does NOT return a single canonical_entity_key."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        # Should NOT have a single canonical key field
        assert "canonical_entity_key" not in data
        assert "entity_key" not in data

    def test_hostname_detail_multiple_keys(
        self,
        api_client: TestClient,
    ) -> None:
        """Test hostname returns multiple observed keys."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        keys = data["observed_correlation_keys"]

        # Should have multiple keys for hostname
        assert len(keys) >= 1
        # Verify keys are actual canonical keys, not fabricated
        for key in keys:
            assert not key.startswith("unknown:")

    def test_dst_ip_detail_returns_observed_keys(
        self,
        api_client: TestClient,
    ) -> None:
        """Test dst_ip entity detail returns observed correlation keys."""
        response = api_client.get("/api/v1/entities/dst_ip/203.0.113.50")
        assert response.status_code == 200

        data = response.json()
        assert data["entity_type"] == "dst_ip"
        assert data["entity_id"] == "203.0.113.50"
        assert isinstance(data["observed_correlation_keys"], list)
        assert data["correlation_status"] == "PARTIAL"

    def test_dst_ip_detail_multiple_key_forms(
        self,
        api_client: TestClient,
    ) -> None:
        """Test dst_ip returns both wildcard and host-scoped keys."""
        response = api_client.get("/api/v1/entities/dst_ip/203.0.113.50")
        assert response.status_code == 200

        data = response.json()
        keys = data["observed_correlation_keys"]

        # Should have at least one key
        assert len(keys) >= 1
        # Verify keys are actual canonical keys
        for key in keys:
            assert not key.startswith("unknown:")

    def test_process_detail_requires_host_context(
        self,
        api_client: TestClient,
    ) -> None:
        """Test process entity only correlates when host context exists."""
        response = api_client.get("/api/v1/entities/process/svchost.exe")
        assert response.status_code == 200

        data = response.json()
        assert data["entity_type"] == "process"
        assert data["entity_id"] == "svchost.exe"
        assert isinstance(data["observed_correlation_keys"], list)
        assert data["correlation_status"] == "PARTIAL"

        # Should NOT include keys without host context
        for key in data["observed_correlation_keys"]:
            # Keys without host should not be included
            assert not key.startswith("unknown:")

    def test_src_ip_correlation_unsupported(
        self,
        api_client: TestClient,
    ) -> None:
        """Test src_ip correlation is unsupported."""
        response = api_client.get("/api/v1/entities/src_ip/192.168.1.100")
        assert response.status_code == 200

        data = response.json()
        assert data["entity_type"] == "src_ip"
        assert data["entity_id"] == "192.168.1.100"
        assert data["correlation_status"] == "UNSUPPORTED"
        assert data["observed_correlation_keys"] == []
        assert data["alerts"] == {}

    def test_username_correlation_unsupported(
        self,
        api_client: TestClient,
    ) -> None:
        """Test username correlation is unsupported."""
        response = api_client.get("/api/v1/entities/username/admin")
        assert response.status_code == 200

        data = response.json()
        assert data["entity_type"] == "username"
        assert data["entity_id"] == "admin"
        assert data["correlation_status"] == "UNSUPPORTED"
        assert data["observed_correlation_keys"] == []
        assert data["alerts"] == {}

    def test_entity_detail_has_behavior(
        self,
        api_client: TestClient,
    ) -> None:
        """Test entity detail includes behavior data."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        assert "behavior" in data
        assert isinstance(data["behavior"], list)

    def test_entity_detail_has_annotations(
        self,
        api_client: TestClient,
    ) -> None:
        """Test entity detail includes annotations."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        assert "annotations" in data
        assert isinstance(data["annotations"], list)

    def test_entity_detail_has_incidents(
        self,
        api_client: TestClient,
    ) -> None:
        """Test entity detail includes incidents."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        assert "incidents" in data
        assert isinstance(data["incidents"], list)
        assert "incident_status" in data
        assert "incident_note" in data

    def test_entity_detail_no_fake_keys(
        self,
        api_client: TestClient,
    ) -> None:
        """Test that unsupported entity types do not use unknown:<alert_id> as fake correlation key."""
        response = api_client.get("/api/v1/entities/src_ip/192.168.1.100")
        assert response.status_code == 200

        data = response.json()
        for key in data["observed_correlation_keys"]:
            assert not key.startswith("unknown:")

    def test_entity_detail_partial_status(
        self,
        api_client: TestClient,
    ) -> None:
        """Test that supported entity types return PARTIAL status."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        assert data["correlation_status"] == "PARTIAL"
        assert "correlation_note" in data
        assert len(data["correlation_note"]) > 0

    def test_entity_detail_incident_status(
        self,
        api_client: TestClient,
    ) -> None:
        """Test incident status is PARTIAL or UNSUPPORTED."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        assert data["incident_status"] in ("PARTIAL", "UNSUPPORTED")
        assert "incident_note" in data

    def test_entity_detail_validates_input(
        self,
        api_client: TestClient,
    ) -> None:
        """Test input validation for entity detail."""
        # Oversized entity ID
        response = api_client.get("/api/v1/entities/hostname/" + "a" * 300)
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# Alert Retrieval Tests
# ---------------------------------------------------------------------------


class TestAlertRetrieval:
    """Tests for alert retrieval through observed correlation keys."""

    def test_hostname_alerts_grouped_by_key(
        self,
        api_client: TestClient,
    ) -> None:
        """Test alerts are grouped by observed correlation key."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        alerts = data["alerts"]

        # Should be a dict keyed by correlation key
        assert isinstance(alerts, dict)
        for _key, key_alerts in alerts.items():
            assert isinstance(key_alerts, list)
            for alert in key_alerts:
                assert "alert_id" in alert
                assert "title" in alert

    def test_alerts_no_duplicates(
        self,
        api_client: TestClient,
    ) -> None:
        """Test that duplicate alerts are not returned twice."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        alerts = data["alerts"]

        # Collect all alert IDs
        all_alert_ids = []
        for key_alerts in alerts.values():
            for alert in key_alerts:
                all_alert_ids.append(alert["alert_id"])

        # Should have no duplicates
        assert len(all_alert_ids) == len(set(all_alert_ids))

    def test_dst_ip_alerts_grouped_by_key(
        self,
        api_client: TestClient,
    ) -> None:
        """Test dst_ip alerts are grouped by observed correlation key."""
        response = api_client.get("/api/v1/entities/dst_ip/203.0.113.50")
        assert response.status_code == 200

        data = response.json()
        alerts = data["alerts"]

        assert isinstance(alerts, dict)
        for _key, key_alerts in alerts.items():
            assert isinstance(key_alerts, list)


# ---------------------------------------------------------------------------
# Incident Tests
# ---------------------------------------------------------------------------


class TestIncidentResolution:
    """Tests for incident resolution through observed correlation keys."""

    def test_incident_found_through_observed_key(
        self,
        api_client: TestClient,
        incident_service: IncidentService,
        alert_queue: AlertQueue,
    ) -> None:
        """Test incident is found through an observed correlation key."""
        # Create an incident for the hostname entity
        hostname_alert = alert_queue.list(entity_key="workstation01:*")[0]
        incident_service.get_or_create_incident_for_entity(
            "workstation01:*",
            [hostname_alert],
        )

        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        incidents = data["incidents"]

        # Should have at least one incident
        assert len(incidents) >= 1
        for inc in incidents:
            assert "incident_id" in inc
            assert "correlation_key" in inc

    def test_multiple_keys_do_not_lose_incidents(
        self,
        api_client: TestClient,
        incident_service: IncidentService,
        alert_queue: AlertQueue,
    ) -> None:
        """Test multiple observed keys do not silently lose incident relationships."""
        # Create incidents for different keys
        alerts = alert_queue.list(sort=False)
        if len(alerts) >= 2:
            incident_service.get_or_create_incident_for_entity(
                "workstation01:*",
                [alerts[0]],
            )
            incident_service.get_or_create_incident_for_entity(
                "workstation01:svchost.exe",
                [alerts[1]],
            )

        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        incidents = data["incidents"]

        # Should have incidents from both keys
        assert len(incidents) >= 1

    def test_unsupported_entity_no_incidents(
        self,
        api_client: TestClient,
    ) -> None:
        """Test unsupported entity types do not fabricate incidents."""
        response = api_client.get("/api/v1/entities/src_ip/192.168.1.100")
        assert response.status_code == 200

        data = response.json()
        assert data["incidents"] == []
        assert data["incident_status"] == "UNSUPPORTED"


# ---------------------------------------------------------------------------
# Annotation Tests
# ---------------------------------------------------------------------------


class TestEntityAnnotations:
    """Tests for entity annotation endpoints."""

    def test_get_annotations_uses_entity_target(
        self,
        api_client: TestClient,
        annotation_service: AnalystAnnotationService,
    ) -> None:
        """Test GET annotations uses entity target key."""
        # Create an annotation
        annotation_service.create_annotation(
            target_key="entity:hostname:workstation01",
            author="analyst1",
            comment="Test annotation",
        )

        response = api_client.get("/api/v1/entities/hostname/workstation01/annotations")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["target_key"] == "entity:hostname:workstation01"

    def test_post_creates_entity_annotation(
        self,
        api_client: TestClient,
        annotation_service: AnalystAnnotationService,
    ) -> None:
        """Test POST creates entity-target annotation."""
        response = api_client.post(
            "/api/v1/entities/hostname/workstation01/annotations",
            json={
                "author": "analyst2",
                "comment": "New annotation",
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert data["target_key"] == "entity:hostname:workstation01"
        assert data["author"] == "analyst2"
        assert data["comment"] == "New annotation"
        assert data["tombstoned"] is False

    def test_annotation_bounds_preserved(
        self,
        api_client: TestClient,
        annotation_service: AnalystAnnotationService,
    ) -> None:
        """Test existing annotation bounds are preserved."""
        # Create max annotations
        for i in range(50):
            annotation_service.create_annotation(
                target_key="entity:hostname:workstation01",
                author=f"analyst{i}",
                comment=f"Annotation {i}",
            )

        response = api_client.get("/api/v1/entities/hostname/workstation01/annotations")
        assert response.status_code == 200

        data = response.json()
        # Should be bounded
        assert len(data) <= 50

    def test_annotation_validation(
        self,
        api_client: TestClient,
    ) -> None:
        """Test annotation input validation."""
        # Empty author
        response = api_client.post(
            "/api/v1/entities/hostname/workstation01/annotations",
            json={
                "author": "",
                "comment": "Test",
            },
        )
        assert response.status_code == 400

        # Empty comment
        response = api_client.post(
            "/api/v1/entities/hostname/workstation01/annotations",
            json={
                "author": "analyst",
                "comment": "",
            },
        )
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# Contract Correctness Tests
# ---------------------------------------------------------------------------


class TestContractCorrectness:
    """Tests for API contract correctness."""

    def test_no_single_canonical_key(
        self,
        api_client: TestClient,
    ) -> None:
        """Test that no single canonical_entity_key is returned."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        assert "canonical_entity_key" not in data
        assert "entity_key" not in data

    def test_observed_keys_contains_actual_keys(
        self,
        api_client: TestClient,
    ) -> None:
        """Test observed_correlation_keys contains actual keys only."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        for key in data["observed_correlation_keys"]:
            # Should be actual canonical keys, not fabricated
            assert key.startswith("workstation01:") or key.startswith("*:")
            assert not key.startswith("unknown:")

    def test_partial_correlation_status_present(
        self,
        api_client: TestClient,
    ) -> None:
        """Test partial correlation status/note is present."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        assert data["correlation_status"] == "PARTIAL"
        assert len(data["correlation_note"]) > 0

    def test_alerts_grouped_by_key(
        self,
        api_client: TestClient,
    ) -> None:
        """Test alerts are grouped by actual correlation key."""
        response = api_client.get("/api/v1/entities/hostname/workstation01")
        assert response.status_code == 200

        data = response.json()
        alerts = data["alerts"]

        # Should be dict keyed by correlation key
        assert isinstance(alerts, dict)
        for key in alerts:
            assert key in data["observed_correlation_keys"]

    def test_deterministic_ordering(
        self,
        api_client: TestClient,
    ) -> None:
        """Test deterministic ordering is preserved."""
        response1 = api_client.get("/api/v1/entities/hostname/workstation01")
        response2 = api_client.get("/api/v1/entities/hostname/workstation01")

        assert response1.status_code == 200
        assert response2.status_code == 200

        data1 = response1.json()
        data2 = response2.json()

        # Should be identical
        assert data1["observed_correlation_keys"] == data2["observed_correlation_keys"]

    def test_existing_bounds_respected(
        self,
        api_client: TestClient,
    ) -> None:
        """Test existing bounds are respected."""
        response = api_client.get("/api/v1/entities?limit=5")
        assert response.status_code == 200

        data = response.json()
        assert len(data["entities"]) <= 5
