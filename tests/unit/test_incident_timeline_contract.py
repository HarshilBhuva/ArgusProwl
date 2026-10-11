"""Tests for Incident Timeline UUID contract."""

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.constants.severity import Severity
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.incident.incident_service import IncidentService
from argusprowl.lifecycle.queue import AlertQueue
from argusprowl.models.alert import Alert


@pytest.fixture
def container():
    return ServiceContainer.get_instance()


@pytest.fixture
def api_client(container):
    # Setup fresh services
    incident_service = IncidentService(max_incidents=100)
    alert_queue = AlertQueue(max_size=1000)

    container.register_singleton(IncidentService, lambda: incident_service)
    container.register_singleton(AlertQueue, lambda: alert_queue)

    app = create_api_app()
    return TestClient(app), incident_service, alert_queue


def test_timeline_retrieves_alerts_with_uuid_ids(api_client):
    """Prove that timeline correctly retrieves alerts when alert_ids are UUIDs."""
    client, incident_service, alert_queue = api_client

    # 1. Create alerts with a specific host
    target_host = "victim-host-01"
    alerts = [
        Alert(
            title=f"Alert {i}",
            description="desc",
            severity=Severity.HIGH,
            source="test",
            entity_context={"host": target_host},
        )
        for i in range(3)
    ]

    # 2. Enqueue alerts so they are available in the queue
    for a in alerts:
        alert_queue.enqueue(a)

    # 3. Create incident with these alerts
    incident = incident_service.create_incident(alerts)
    incident_id = incident.incident_id

    # 4. Call timeline endpoint
    response = client.get(f"/api/v1/incidents/{incident_id}/timeline")

    # If the bug is present, uuid.UUID(alert_id_str) on a UUID object will raise
    # AttributeError or ValueError, which is silently swallowed, resulting in
    # empty host_entities and a "correlation_status": "EMPTY" response.
    assert response.status_code == 200
    data = response.json()

    assert data["correlation_status"] != "EMPTY", "Timeline should not be empty when alerts exist"
    assert data["primary_entity"] == f"hostname:{target_host}"
    assert "items" in data
