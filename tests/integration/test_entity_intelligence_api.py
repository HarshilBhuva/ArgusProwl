"""API coverage for durable entity intelligence pivots."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.entity_intelligence.service import EntityIntelligenceService
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService
from argusprowl.storage.sqlite_storage import SQLiteAdapter


@pytest.fixture
def api_client(tmp_path) -> TestClient:
    ServiceContainer.reset_instance()
    container = ServiceContainer.get_instance()
    storage = SQLiteAdapter(tmp_path / "entity-api.db")
    evidence = TelemetryEvidenceService(storage=storage)
    event = NormalizedEvent(
        source_type="sysmon",
        event_type="process_start",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        hostname="api-host",
        username="analyst",
        process_name="agent.exe",
        pid=1234,
        dst_ip="198.51.100.10",
    )
    evidence.record_event(event)
    container.register_singleton(
        EntityIntelligenceService,
        EntityIntelligenceService(storage),
    )
    try:
        with TestClient(create_api_app()) as client:
            yield client
    finally:
        storage.close()
        ServiceContainer.reset_instance()


def test_entity_intelligence_list_endpoint_returns_durable_entities(api_client: TestClient) -> None:
    response = api_client.get("/api/v1/entities/intelligence?entity_type=hostname")
    assert response.status_code == 200
    data = response.json()
    assert data["returned_count"] == 1
    assert data["entities"][0]["entity_type"] == "hostname"
    assert data["entities"][0]["entity_id"] == "api-host"
    assert data["entities"][0]["observation_count"] == 1


def test_entity_relationship_endpoint_returns_evidence_backed_pivots(api_client: TestClient) -> None:
    response = api_client.get("/api/v1/entities/hostname/api-host/relationships")
    assert response.status_code == 200
    data = response.json()
    relation_types = {item["relationship_type"] for item in data["relationships"]}
    assert "HAS_USER" in relation_types
    assert "RUNS_PROCESS" in relation_types
    assert "COMMUNICATES_WITH" in relation_types
    relation = next(item for item in data["relationships"] if item["relationship_type"] == "RUNS_PROCESS")
    assert relation["evidence_kind"] == "OBSERVED"
    assert relation["evidence_refs"][0]["available"] is True


def test_entity_evidence_endpoint_exposes_event_references(api_client: TestClient) -> None:
    response = api_client.get("/api/v1/entities/hostname/api-host/evidence")
    assert response.status_code == 200
    data = response.json()
    assert data["returned_count"] == 1
    assert data["evidence_refs"][0]["available"] is True


def test_entity_intelligence_endpoints_report_missing_service_as_503() -> None:
    ServiceContainer.reset_instance()
    with TestClient(create_api_app()) as client:
        response = client.get("/api/v1/entities/intelligence")
    assert response.status_code == 503
    ServiceContainer.reset_instance()
