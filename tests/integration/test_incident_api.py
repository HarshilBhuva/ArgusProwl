# ---------------------------------------------------------------------------
# Incident Endpoint Tests
# ---------------------------------------------------------------------------

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.constants.severity import Severity
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.incident.incident_service import IncidentService
from argusprowl.models.alert import Alert
from argusprowl.models.incident import Incident, IncidentStatus

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def incident_service() -> IncidentService:
    """Create a process-local incident service with bounded capacity."""
    return IncidentService(max_incidents=100)


@pytest.fixture
def sample_alert() -> Alert:
    """Create a minimal Alert used to bootstrap incidents."""
    return Alert(
        title="Test Alert",
        description="Test Description",
        severity=Severity.HIGH,
        source="test-detector",
    )


@pytest.fixture
def sample_incident(incident_service: IncidentService, sample_alert: Alert) -> Incident:
    """Create an incident backed by a real service so response serialization is honest."""
    return incident_service.create_incident([sample_alert])


@pytest.fixture
def api_client(incident_service: IncidentService) -> TestClient:
    """Create a TestClient with a real IncidentService wired into the container."""
    container = ServiceContainer.get_instance()
    container.register_singleton(IncidentService, lambda: incident_service)
    app = create_api_app()
    return TestClient(app)


# ---------------------------------------------------------------------------
# GET /incidents
# ---------------------------------------------------------------------------


class TestListIncidents:
    """Tests for GET /api/v1/incidents."""

    def test_returns_empty_list(self, api_client: TestClient) -> None:
        """GET /incidents returns an empty list when nothing is recorded."""
        response = api_client.get("/api/v1/incidents")
        assert response.status_code == 200
        data = response.json()
        assert data["incidents"] == []
        assert data["total_count"] == 0

    def test_returns_incidents(self, api_client: TestClient, sample_incident: Incident) -> None:
        """GET /incidents returns incidents with correct shape."""
        response = api_client.get("/api/v1/incidents")
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 1
        assert len(data["incidents"]) == 1
        assert data["incidents"][0]["incident_id"] == str(sample_incident.incident_id)
        assert data["incidents"][0]["title"] == sample_incident.title
        assert data["incidents"][0]["severity"] == "HIGH"
        assert data["incidents"][0]["status"] == sample_incident.status.value
        assert len(data["incidents"][0]["alert_ids"]) == 1

    def test_filters_by_status(
        self, api_client: TestClient, incident_service: IncidentService, sample_alert: Alert
    ) -> None:
        """Status filter matches incident lifecycle values from the API."""
        incident_service.create_incident([sample_alert], title="Open one")
        open_id = incident_service.list_incidents()[0].incident_id

        # Legal path to CLOSED: OPEN -> INVESTIGATING -> RESOLVED -> CLOSED
        incident_service.update_status(open_id, IncidentStatus.INVESTIGATING)
        incident_service.update_status(open_id, IncidentStatus.RESOLVED)
        updated = incident_service.update_status(open_id, IncidentStatus.CLOSED)

        response = api_client.get("/api/v1/incidents?status=closed")
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 1
        assert data["incidents"][0]["incident_id"] == str(updated.incident_id)

    def test_filters_by_severity(
        self, api_client: TestClient, incident_service: IncidentService, sample_alert: Alert
    ) -> None:
        """Severity filter matches incident severity values from the API."""
        incident_service.create_incident([sample_alert], title="High only", severity=Severity.HIGH)

        response = api_client.get("/api/v1/incidents?severity=HIGH")
        assert response.status_code == 200
        assert response.json()["total_count"] >= 1

    def test_invalid_status_returns_422(self, api_client: TestClient) -> None:
        """Invalid status raises 422 with validation detail."""
        response = api_client.get("/api/v1/incidents?status=missing")
        assert response.status_code == 422

    def test_invalid_severity_returns_422(self, api_client: TestClient) -> None:
        """Invalid severity raises 422 with validation detail."""
        response = api_client.get("/api/v1/incidents?severity=missing")
        assert response.status_code == 422

    def test_service_missing_returns_503(self) -> None:
        """When IncidentService is not registered, the endpoint returns 503."""
        container = ServiceContainer.get_instance()
        assert not container.is_registered(IncidentService)
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/incidents")
            assert response.status_code == 503


# ---------------------------------------------------------------------------
# GET /incidents/{id}
# ---------------------------------------------------------------------------


class TestGetIncidentDetail:
    """Tests for GET /api/v1/incidents/{id}."""

    def test_returns_incident(self, api_client: TestClient, sample_incident: Incident) -> None:
        """GET /incidents/{id} returns the incident with the expected shape."""
        response = api_client.get(f"/api/v1/incidents/{sample_incident.incident_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["incident_id"] == str(sample_incident.incident_id)
        assert data["title"] == sample_incident.title
        assert data["status"] == sample_incident.status.value
        assert isinstance(data["alert_ids"], list)

    def test_missing_incident_returns_404(self, api_client: TestClient) -> None:
        """Unknown UUID returns 404."""
        response = api_client.get("/api/v1/incidents/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404

    def test_invalid_uuid_returns_404(self, api_client: TestClient) -> None:
        """Non-UUID path parameter returns 404."""
        response = api_client.get("/api/v1/incidents/not-a-uuid")
        assert response.status_code == 404

    def test_service_missing_returns_503(self) -> None:
        """When IncidentService is not registered, the endpoint returns 503."""
        container = ServiceContainer.get_instance()
        assert not container.is_registered(IncidentService)
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get(f"/api/v1/incidents/{uuid4()}")
            assert response.status_code == 503


# ---------------------------------------------------------------------------
# POST /incidents/{id}/close
# ---------------------------------------------------------------------------


class TestCloseIncident:
    """Tests for POST /api/v1/incidents/{id}/close."""

    def test_closes_an_incident(
        self, api_client: TestClient, sample_incident: Incident, incident_service: IncidentService
    ) -> None:
        """Closing an incident returns LifecycleActionResponse with status closed.
        Legal path: OPEN -> INVESTIGATING -> RESOLVED -> CLOSED.
        """
        # Move to RESOLVED first
        incident_service.update_status(sample_incident.incident_id, IncidentStatus.INVESTIGATING)
        incident_service.update_status(sample_incident.incident_id, IncidentStatus.RESOLVED)

        response = api_client.post(f"/api/v1/incidents/{sample_incident.incident_id}/close")
        assert response.status_code == 200
        data = response.json()
        assert data["alert_id"] == str(sample_incident.incident_id)
        assert data["current_state"] == "closed"
        assert data["previous_state"] == "resolved"

    def test_closes_an_investigating_incident(
        self, api_client: TestClient, incident_service: IncidentService, sample_alert: Alert
    ) -> None:
        """INCIDENTS in RESOLVED can transition to CLOSED."""
        incident = incident_service.create_incident([sample_alert])
        incident_service.update_status(incident.incident_id, IncidentStatus.INVESTIGATING)
        updated = incident_service.update_status(incident.incident_id, IncidentStatus.RESOLVED)

        response = api_client.post(f"/api/v1/incidents/{updated.incident_id}/close")
        assert response.status_code == 200
        data = response.json()
        assert data["current_state"] == "closed"

    def test_missing_incident_returns_404(self, api_client: TestClient) -> None:
        """POST /close on an unknown UUID returns 404."""
        response = api_client.post("/api/v1/incidents/00000000-0000-0000-0000-000000000000/close")
        assert response.status_code == 404

    def test_invalid_uuid_returns_404(self, api_client: TestClient) -> None:
        """POST /close on a non-UUID returns 404."""
        response = api_client.post("/api/v1/incidents/not-a-uuid/close")
        assert response.status_code == 404

    def test_already_closed_returns_200(
        self, api_client: TestClient, sample_incident: Incident, incident_service: IncidentService
    ) -> None:
        """Closing an already-CLOSED incident is idempotent and returns 200."""
        # Move to CLOSED
        incident_service.update_status(sample_incident.incident_id, IncidentStatus.INVESTIGATING)
        incident_service.update_status(sample_incident.incident_id, IncidentStatus.RESOLVED)
        incident_service.update_status(sample_incident.incident_id, IncidentStatus.CLOSED)

        api_client.post(f"/api/v1/incidents/{sample_incident.incident_id}/close")
        response = api_client.post(f"/api/v1/incidents/{sample_incident.incident_id}/close")
        assert response.status_code == 200

    def test_service_missing_returns_503(self) -> None:
        """When IncidentService is not registered, the endpoint returns 503."""
        container = ServiceContainer.get_instance()
        assert not container.is_registered(IncidentService)
        app = create_api_app()
        with TestClient(app) as client:
            response = client.post(f"/api/v1/incidents/{uuid4()}/close")
            assert response.status_code == 503
