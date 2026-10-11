# ---------------------------------------------------------------------------
# IOC Lookup Endpoint Tests
# ---------------------------------------------------------------------------

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.services.ioc_investigation_service import IocInvestigationService


@pytest.fixture
def ioc_service() -> IocInvestigationService:
    """Provide a mocked IOC service for API contract tests."""
    return MagicMock(spec=IocInvestigationService)


@pytest.fixture
def api_client(ioc_service: IocInvestigationService) -> TestClient:
    container = ServiceContainer.get_instance()
    container.register_singleton(IocInvestigationService, lambda: ioc_service)
    app = create_api_app()
    return TestClient(app)


class TestIocLookup:
    def test_lookup_domain(
        self, api_client: TestClient, ioc_service: IocInvestigationService
    ) -> None:
        """Test that IOC lookup returns 200 with expected fields."""
        mock_result = MagicMock()
        mock_result.indicator = "example.com"
        mock_result.ioc_type = MagicMock()
        mock_result.ioc_type.value = "domain"
        mock_result.reputation = MagicMock()
        mock_result.reputation.to_dict.return_value = {"score": 0.5}
        mock_result.observations = ()
        mock_result.first_observed = None
        mock_result.last_observed = None
        mock_result.associated_alert_ids = ()
        mock_result.associated_hosts = ()
        mock_result.associated_rule_ids = ()
        mock_result.related_iocs = ()
        mock_result.timeline = ()
        mock_result.prevalence = None
        mock_result.status = MagicMock()
        mock_result.status.value = "OK"
        mock_result.reason = None
        mock_result.truncated = False
        mock_result.inspected_alert_count = 0
        mock_result.observation_note = "first observed in retained alert evidence"
        ioc_service.investigate.return_value = mock_result

        response = api_client.get("/api/v1/iocs/example.com")
        assert response.status_code == 200
        data = response.json()
        assert data["indicator"] == "example.com"
        assert "observations" in data
        assert "status" in data

    def test_lookup_ip(self, api_client: TestClient, ioc_service: IocInvestigationService) -> None:
        """Test that IP lookup returns 200 with expected fields."""
        mock_result = MagicMock()
        mock_result.indicator = "192.168.1.1"
        mock_result.ioc_type = MagicMock()
        mock_result.ioc_type.value = "ip"
        mock_result.reputation = MagicMock()
        mock_result.reputation.to_dict.return_value = {"score": 0.3}
        mock_result.observations = ()
        mock_result.first_observed = None
        mock_result.last_observed = None
        mock_result.associated_alert_ids = ()
        mock_result.associated_hosts = ()
        mock_result.associated_rule_ids = ()
        mock_result.related_iocs = ()
        mock_result.timeline = ()
        mock_result.prevalence = None
        mock_result.status = MagicMock()
        mock_result.status.value = "OK"
        mock_result.reason = None
        mock_result.truncated = False
        mock_result.inspected_alert_count = 0
        mock_result.observation_note = "first observed in retained alert evidence"
        ioc_service.investigate.return_value = mock_result

        response = api_client.get("/api/v1/iocs/192.168.1.1")
        assert response.status_code == 200
        data = response.json()
        assert data["indicator"] == "192.168.1.1"
        assert "observations" in data

    def test_lookup_fqdn(
        self, api_client: TestClient, ioc_service: IocInvestigationService
    ) -> None:
        """Test that FQDN lookup returns 200 with expected indicator."""
        mock_result = MagicMock()
        mock_result.indicator = "sub.example.com"
        mock_result.ioc_type = MagicMock()
        mock_result.ioc_type.value = "domain"
        mock_result.reputation = MagicMock()
        mock_result.reputation.to_dict.return_value = {"score": 0.2}
        mock_result.observations = ()
        mock_result.first_observed = None
        mock_result.last_observed = None
        mock_result.associated_alert_ids = ()
        mock_result.associated_hosts = ()
        mock_result.associated_rule_ids = ()
        mock_result.related_iocs = ()
        mock_result.timeline = ()
        mock_result.prevalence = None
        mock_result.status = MagicMock()
        mock_result.status.value = "OK"
        mock_result.reason = None
        mock_result.truncated = False
        mock_result.inspected_alert_count = 0
        mock_result.observation_note = "first observed in retained alert evidence"
        ioc_service.investigate.return_value = mock_result

        response = api_client.get("/api/v1/iocs/sub.example.com")
        assert response.status_code == 200
        data = response.json()
        assert data["indicator"] == "sub.example.com"

    def test_service_missing_returns_503(self) -> None:
        """Test that missing service returns 503."""
        container = ServiceContainer.get_instance()
        assert not container.is_registered(IocInvestigationService)
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/iocs/example.com")
            assert response.status_code == 503
