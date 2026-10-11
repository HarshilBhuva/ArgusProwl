# ---------------------------------------------------------------------------
# Incident Sub-Endpoint Tests
# ---------------------------------------------------------------------------

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
from argusprowl.constants.severity import Severity
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.incident.incident_service import IncidentService
from argusprowl.lifecycle.queue import AlertQueue
from argusprowl.models.alert import Alert
from argusprowl.models.incident import Incident, IncidentStatus


@pytest.fixture
def incident_service() -> IncidentService:
    return IncidentService(max_incidents=100)


@pytest.fixture
def alert_queue() -> AlertQueue:
    return AlertQueue(max_size=100)


@pytest.fixture
def sample_alert(alert_queue: AlertQueue) -> Alert:
    alert = Alert(
        title="Test Alert",
        description="Test Description",
        severity=Severity.HIGH,
        source="test-detector",
    )
    alert_queue.enqueue(alert)
    return alert


@pytest.fixture
def sample_incident(incident_service: IncidentService, sample_alert: Alert) -> Incident:
    return incident_service.create_incident([sample_alert])


@pytest.fixture
def api_client(
    incident_service: IncidentService, alert_queue: AlertQueue, sample_alert: Alert
) -> TestClient:
    container = ServiceContainer.get_instance()
    container.register_singleton(IncidentService, lambda: incident_service)
    container.register_singleton(AlertQueue, lambda: alert_queue)
    ann_service = AnalystAnnotationService()
    container.register_singleton(AnalystAnnotationService, lambda: ann_service)
    app = create_api_app()
    return TestClient(app)


class TestGetIncidentAlerts:
    def test_returns_alerts_for_incident(
        self, api_client: TestClient, sample_incident: Incident
    ) -> None:
        response = api_client.get(f"/api/v1/incidents/{sample_incident.incident_id}/alerts")
        assert response.status_code == 200
        data = response.json()
        assert data["incident_id"] == str(sample_incident.incident_id)
        assert isinstance(data["alerts"], list)
        assert data["total_alerts"] >= 1

    def test_missing_incident_returns_404(self, api_client: TestClient) -> None:
        response = api_client.get("/api/v1/incidents/00000000-0000-0000-0000-000000000000/alerts")
        assert response.status_code == 404

    def test_invalid_uuid_returns_404(self, api_client: TestClient) -> None:
        response = api_client.get("/api/v1/incidents/not-a-uuid/alerts")
        assert response.status_code == 404


class TestGetIncidentTimeline:
    def test_returns_timeline(self, api_client: TestClient, sample_incident: Incident) -> None:
        response = api_client.get(f"/api/v1/incidents/{sample_incident.incident_id}/timeline")
        assert response.status_code == 200
        data = response.json()
        assert data["incident_id"] == str(sample_incident.incident_id)
        assert isinstance(data["items"], list)
        assert "returned_count" in data
        assert "truncated" in data

    def test_missing_incident_returns_404(self, api_client: TestClient) -> None:
        response = api_client.get("/api/v1/incidents/00000000-0000-0000-0000-000000000000/timeline")
        assert response.status_code == 404


class TestIncidentAnnotations:
    def test_get_annotations_empty(self, api_client: TestClient, sample_incident: Incident) -> None:
        response = api_client.get(f"/api/v1/incidents/{sample_incident.incident_id}/annotations")
        assert response.status_code == 200
        assert response.json() == []

    def test_create_annotation(self, api_client: TestClient, sample_incident: Incident) -> None:
        response = api_client.post(
            f"/api/v1/incidents/{sample_incident.incident_id}/annotations",
            json={"author": "analyst-1", "comment": "Investigating breach"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["author"] == "analyst-1"
        assert data["comment"] == "Investigating breach"

    def test_get_annotations_after_create(
        self, api_client: TestClient, sample_incident: Incident
    ) -> None:
        api_client.post(
            f"/api/v1/incidents/{sample_incident.incident_id}/annotations",
            json={"author": "analyst-2", "comment": "Follow-up note"},
        )
        response = api_client.get(f"/api/v1/incidents/{sample_incident.incident_id}/annotations")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["author"] == "analyst-2"

    def test_missing_incident_returns_404(self, api_client: TestClient) -> None:
        response = api_client.get(
            "/api/v1/incidents/00000000-0000-0000-0000-000000000000/annotations"
        )
        assert response.status_code == 404


class TestTransitionIncident:
    def test_transitions_open_to_investigating(
        self, api_client: TestClient, sample_incident: Incident
    ) -> None:
        response = api_client.post(
            f"/api/v1/incidents/{sample_incident.incident_id}/transition?status=investigating"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["current_state"] == "investigating"
        assert data["previous_state"] == "open"

    def test_transitions_investigating_to_resolved(
        self, api_client: TestClient, sample_incident: Incident
    ) -> None:
        incident_service = ServiceContainer.get_instance().resolve(IncidentService)
        incident_service.update_status(sample_incident.incident_id, IncidentStatus.INVESTIGATING)
        response = api_client.post(
            f"/api/v1/incidents/{sample_incident.incident_id}/transition?status=resolved"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["current_state"] == "resolved"

    def test_invalid_status_returns_422(
        self, api_client: TestClient, sample_incident: Incident
    ) -> None:
        response = api_client.post(
            f"/api/v1/incidents/{sample_incident.incident_id}/transition?status=missing"
        )
        assert response.status_code == 422

    def test_missing_incident_returns_404(self, api_client: TestClient) -> None:
        response = api_client.post(
            "/api/v1/incidents/00000000-0000-0000-0000-000000000000/transition?status=investigating"
        )
        assert response.status_code == 404
