# ---------------------------------------------------------------------------
# Rules Endpoint Tests
# ---------------------------------------------------------------------------

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.detection.detection_manager import DetectionManager


@pytest.fixture(autouse=True)
def register_detection_manager(reset_singletons: None) -> None:
    """Bind the backend required by rules endpoints for each isolated test."""
    container = ServiceContainer.get_instance()
    container.register_singleton(DetectionManager, DetectionManager())


class TestListRules:
    def test_returns_rules(
        self,
    ) -> None:
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/rules")
            assert response.status_code == 200
            data = response.json()
            assert isinstance(data["rules"], list)
            assert isinstance(data["total_count"], int)

    def test_filters_by_enabled(self) -> None:
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/rules?enabled=true")
            assert response.status_code == 200
            data = response.json()
            assert isinstance(data["rules"], list)
            assert isinstance(data["total_count"], int)

    def test_filters_by_detector_class(self) -> None:
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/rules?detector_class=NetworkDetector")
            assert response.status_code == 200
            data = response.json()
            assert isinstance(data["rules"], list)

    def test_invalid_enabled_returns_422(self) -> None:
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/rules?enabled=maybe")
            assert response.status_code == 422


class TestGetRuleDetail:
    def test_returns_rule_detail(self) -> None:
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/rules")
            rules = response.json()["rules"]
            if not rules:
                return  # Skip if no rules loaded
            rule_id = rules[0]["rule_id"]
            detail_response = client.get(f"/api/v1/rules/{rule_id}")
            assert detail_response.status_code == 200
            data = detail_response.json()
            assert data["rule_id"] == rule_id
            assert "name" in data
            assert "parameters" in data
            assert "attck_mappings" in data

    def test_missing_rule_returns_404(self) -> None:
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/rules/nonexistent-rule-id")
            assert response.status_code == 404
