# ---------------------------------------------------------------------------
# Alert Lifecycle Endpoint Tests
# ---------------------------------------------------------------------------

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from argusprowl.alerting.alert_manager import AlertManager
from argusprowl.api.app import create_api_app
from argusprowl.constants.severity import Severity
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.lifecycle.queue import AlertQueue
from argusprowl.models.alert import Alert


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
def api_client(alert_queue: AlertQueue, sample_alert: Alert) -> TestClient:
    container = ServiceContainer.get_instance()
    container.register_singleton(AlertQueue, lambda: alert_queue)
    container.register_singleton(
        AlertManager,
        lambda: AlertManager(alert_queue=alert_queue),
    )
    app = create_api_app()
    return TestClient(app)


class TestAcknowledgeAlert:
    def test_acknowledges_open_alert(self, api_client: TestClient, sample_alert: Alert) -> None:
        response = api_client.post(f"/api/v1/alerts/{sample_alert.alert_id}/acknowledge")
        assert response.status_code == 200
        data = response.json()
        assert data["alert_id"] == str(sample_alert.alert_id)
        assert data["previous_state"] == "OPEN"
        assert data["current_state"] == "ACKNOWLEDGED"

    def test_rejects_acknowledging_an_already_acknowledged_alert(
        self, api_client: TestClient, sample_alert: Alert
    ) -> None:
        first_response = api_client.post(f"/api/v1/alerts/{sample_alert.alert_id}/acknowledge")
        assert first_response.status_code == 200

        response = api_client.post(f"/api/v1/alerts/{sample_alert.alert_id}/acknowledge")
        assert response.status_code == 409

    def test_missing_alert_returns_404(self, api_client: TestClient) -> None:
        response = api_client.post(
            "/api/v1/alerts/00000000-0000-0000-0000-000000000000/acknowledge"
        )
        assert response.status_code == 404

    def test_invalid_uuid_returns_404(self, api_client: TestClient) -> None:
        response = api_client.post("/api/v1/alerts/not-a-uuid/acknowledge")
        assert response.status_code == 404


class TestCloseAlert:
    def test_closes_open_alert(self, api_client: TestClient, sample_alert: Alert) -> None:
        # OPEN -> ACKNOWLEDGED -> CLOSED
        api_client.post(f"/api/v1/alerts/{sample_alert.alert_id}/acknowledge")
        response = api_client.post(f"/api/v1/alerts/{sample_alert.alert_id}/close")
        assert response.status_code == 200
        data = response.json()
        assert data["current_state"] == "CLOSED"
        assert data["previous_state"] == "ACKNOWLEDGED"

    def test_closes_acknowledged_alert(self, api_client: TestClient, sample_alert: Alert) -> None:
        api_client.post(f"/api/v1/alerts/{sample_alert.alert_id}/acknowledge")
        response = api_client.post(f"/api/v1/alerts/{sample_alert.alert_id}/close")
        assert response.status_code == 200
        data = response.json()
        assert data["current_state"] == "CLOSED"

    def test_missing_alert_returns_404(self, api_client: TestClient) -> None:
        response = api_client.post("/api/v1/alerts/00000000-0000-0000-0000-000000000000/close")
        assert response.status_code == 404

    def test_invalid_uuid_returns_404(self, api_client: TestClient) -> None:
        response = api_client.post("/api/v1/alerts/not-a-uuid/close")
        assert response.status_code == 404

    def test_rejects_closing_an_already_closed_alert(
        self, api_client: TestClient, sample_alert: Alert
    ) -> None:
        api_client.post(f"/api/v1/alerts/{sample_alert.alert_id}/acknowledge")
        first_close = api_client.post(f"/api/v1/alerts/{sample_alert.alert_id}/close")
        assert first_close.status_code == 200

        response = api_client.post(f"/api/v1/alerts/{sample_alert.alert_id}/close")
        assert response.status_code == 409
