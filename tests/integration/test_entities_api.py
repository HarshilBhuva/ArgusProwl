# ---------------------------------------------------------------------------
# Entity Endpoint Tests
# ---------------------------------------------------------------------------

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.constants.severity import Severity
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.models.alert import Alert


@pytest.fixture
def sample_alert() -> Alert:
    return Alert(
        title="Test Alert",
        description="Test Description",
        severity=Severity.HIGH,
        source="test-detector",
        entity_context={"host": "test-host"},
    )


@pytest.fixture
def api_client(sample_alert: Alert) -> TestClient:
    container = ServiceContainer.get_instance()
    from argusprowl.lifecycle.queue import AlertQueue

    queue = AlertQueue(max_size=10)
    queue.enqueue(sample_alert)
    container.register_singleton(AlertQueue, lambda: queue)
    from argusprowl.alerting.alert_persistence import AlertPersistence

    with tempfile.TemporaryDirectory() as tmpdir:
        persistence = AlertPersistence(db_path=str(Path(tmpdir) / "test.db"))
        persistence.initialize()
        container.register_singleton(AlertPersistence, lambda: persistence)
        from argusprowl.correlation.entity_correlation_service import (
            EntityCorrelationService,
        )
        from argusprowl.services.alert_search_service import AlertSearchService

        ecs = EntityCorrelationService()
        container.register_singleton(EntityCorrelationService, lambda: ecs)
        search_service = AlertSearchService(queue, persistence, ecs)
        container.register_singleton(AlertSearchService, lambda: search_service)
        from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
        from argusprowl.behavior.analyst_behavior_query_service import (
            AnalystBehaviorQueryService,
        )
        from argusprowl.services.investigation_timeline_service import (
            InvestigationTimelineService,
        )

        ann_service = AnalystAnnotationService()
        container.register_singleton(AnalystAnnotationService, lambda: ann_service)
        mock_behavior = MagicMock(spec=AnalystBehaviorQueryService)
        mock_behavior.list_entities.return_value = []
        mock_behavior.get_entity_behavior.return_value = []
        container.register_singleton(AnalystBehaviorQueryService, lambda: mock_behavior)
        timeline_service = InvestigationTimelineService(
            alert_search_service=search_service,
            incident_service=MagicMock(),
            annotation_service=ann_service,
            behavior_query_service=mock_behavior,
            entity_correlation_service=ecs,
        )
        container.register_singleton(InvestigationTimelineService, lambda: timeline_service)
        app = create_api_app()
        yield TestClient(app)


class TestListEntities:
    def test_returns_entities(self, api_client: TestClient) -> None:
        response = api_client.get("/api/v1/entities")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["entities"], list)
        assert isinstance(data["total_count"], int)

    def test_service_missing_returns_503(self) -> None:
        from argusprowl.behavior.analyst_behavior_query_service import (
            AnalystBehaviorQueryService,
        )

        container = ServiceContainer.get_instance()
        assert not container.is_registered(AnalystBehaviorQueryService)
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/entities")
            assert response.status_code == 503


class TestGetEntityDetail:
    def test_returns_entity_detail(self, api_client: TestClient) -> None:
        response = api_client.get("/api/v1/entities/hostname/test-host")
        assert response.status_code == 200
        data = response.json()
        assert data["entity_type"] == "hostname"
        assert data["entity_id"] == "test-host"
        assert data["observed_correlation_keys"] == ["test-host:*"]

    def test_missing_entity_returns_404(self, api_client: TestClient) -> None:
        response = api_client.get("/api/v1/entities/hostname/nonexistent-entity-id")
        assert response.status_code == 404

    def test_service_missing_returns_503(self) -> None:
        from argusprowl.behavior.analyst_behavior_query_service import (
            AnalystBehaviorQueryService,
        )

        container = ServiceContainer.get_instance()
        assert not container.is_registered(AnalystBehaviorQueryService)
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/entities/host/nonexistent")
            assert response.status_code == 503


class TestEntityAnnotations:
    def test_get_annotations_empty(self, api_client: TestClient) -> None:
        response = api_client.get("/api/v1/entities/host/test-host-annotations/annotations")
        assert response.status_code == 200
        assert response.json() == []

    def test_create_annotation(self, api_client: TestClient) -> None:
        response = api_client.post(
            "/api/v1/entities/host/test-host-annotations/annotations",
            json={"author": "analyst-1", "comment": "Test annotation"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["author"] == "analyst-1"
        assert data["comment"] == "Test annotation"
