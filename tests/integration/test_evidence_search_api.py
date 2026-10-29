# ---------------------------------------------------------------------------
# Evidence Search Endpoint Tests
# ---------------------------------------------------------------------------

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.services.telemetry_evidence_service import (
    EvidenceDetailResult,
    EvidenceSearchResult,
    TelemetryEvidenceService,
)


@pytest.fixture
def evidence_service() -> TelemetryEvidenceService:
    return MagicMock(spec=TelemetryEvidenceService)


@pytest.fixture
def api_client(evidence_service: TelemetryEvidenceService) -> TestClient:
    container = ServiceContainer.get_instance()
    container.register_singleton(TelemetryEvidenceService, lambda: evidence_service)
    app = create_api_app()
    return TestClient(app)


class TestSearchEvidence:
    def test_search_returns_result(
        self, api_client: TestClient, evidence_service: TelemetryEvidenceService
    ) -> None:
        evidence_service.search.return_value = EvidenceSearchResult(
            records=(),
            events={},
            status="AVAILABLE",
            reason=None,
            truncated=False,
            total_count=0,
            returned_count=0,
        )
        response = api_client.get("/api/v1/evidence")
        assert response.status_code == 200
        data = response.json()
        assert data["records"] == []
        assert data["status"] == "AVAILABLE"

    def test_search_with_params(
        self, api_client: TestClient, evidence_service: TelemetryEvidenceService
    ) -> None:
        evidence_service.search.return_value = EvidenceSearchResult(
            records=(),
            events={},
            status="AVAILABLE",
            reason=None,
            truncated=False,
            total_count=0,
            returned_count=0,
        )
        response = api_client.get("/api/v1/evidence?entity_type=host&entity_id=server-01")
        assert response.status_code == 200
        evidence_service.search.assert_called_once()

    def test_service_missing_returns_503(self) -> None:
        container = ServiceContainer.get_instance()
        assert not container.is_registered(TelemetryEvidenceService)
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/evidence")
            assert response.status_code == 503


class TestEvidenceDetail:
    def test_detail_returns_result(
        self, api_client: TestClient, evidence_service: TelemetryEvidenceService
    ) -> None:
        from uuid import UUID

        evidence_service.get_detail.return_value = EvidenceDetailResult(
            event_id=UUID("00000000-0000-4000-8000-000000000001"),
            status="AVAILABLE",
            reason=None,
            event=None,
            record=None,
        )
        response = api_client.get("/api/v1/evidence/00000000-0000-4000-8000-000000000001")
        assert response.status_code == 200
        data = response.json()
        assert data["event_id"] == "00000000-0000-4000-8000-000000000001"
        assert data["status"] == "AVAILABLE"

    def test_service_missing_returns_503(self) -> None:
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/evidence/test-event-id")
            assert response.status_code == 503


class TestEvidenceStats:
    def test_stats_returns_result(
        self, api_client: TestClient, evidence_service: TelemetryEvidenceService
    ) -> None:
        evidence_service.get_stats.return_value = {
            "retained_events": 0,
            "max_retained_events": 10000,
            "eviction_count": 0,
            "capacity_used_pct": 0.0,
            "persistence_enabled": True,
            "recovery_status": "UNAVAILABLE",
            "recovery_reason": "Persisted evidence could not be loaded during startup.",
            "persistence_operations_failed": 1,
        }
        response = api_client.get("/api/v1/evidence/stats")
        assert response.status_code == 200
        data = response.json()
        assert "retained_events" in data
        assert "max_retained_events" in data
        assert data["recovery_status"] == "UNAVAILABLE"
        assert data["recovery_reason"] == "Persisted evidence could not be loaded during startup."
        assert data["persistence_enabled"] is True
        assert data["persistence_operations_failed"] == 1

    def test_service_missing_returns_503(self) -> None:
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/evidence/stats")
            assert response.status_code == 503
