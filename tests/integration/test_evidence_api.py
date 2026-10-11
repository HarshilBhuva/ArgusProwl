"""Tests for TelemetryEvidence API (Phase 7.8)."""

import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.lifecycle.queue import AlertQueue
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.telemetry_evidence_service import (
    PROVENANCE_OBSERVED_CONTEXT,
    EvidenceRecord,
    EvidenceSearchResult,
    TelemetryEvidenceService,
)


@pytest.fixture
def evidence_service() -> MagicMock:
    return MagicMock(spec=TelemetryEvidenceService)


@pytest.fixture
def api_client(evidence_service: MagicMock) -> TestClient:
    container = ServiceContainer.get_instance()
    container.reset_instance()
    container = ServiceContainer.get_instance()
    container.register_singleton(TelemetryEvidenceService, lambda: evidence_service)

    app = create_api_app()
    with TestClient(app) as client:
        yield client

    container.reset_instance()


class TestTelemetryEvidenceApi:
    def test_search_evidence(self, api_client: TestClient, evidence_service: MagicMock) -> None:
        ev_id = uuid.uuid4()
        event = NormalizedEvent(
            event_id=ev_id,
            timestamp=datetime.now(UTC),
            source_type="zeek",
            event_type="conn",
        )
        record = EvidenceRecord(
            event_id=ev_id,
            provenance=PROVENANCE_OBSERVED_CONTEXT,
        )
        evidence_service.search.return_value = EvidenceSearchResult(
            records=(record,),
            events={ev_id: event},
            status="AVAILABLE",
            reason=None,
            truncated=False,
            total_count=1,
            returned_count=1,
        )

        res = api_client.get(
            "/api/v1/evidence", params={"limit": 10, "entity_type": "ip", "entity_id": "1.2.3.4"}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["total_count"] == 1
        assert len(data["records"]) == 1
        assert data["records"][0]["event_id"] == str(ev_id)
        assert data["records"][0]["provenance"] == "OBSERVED_CONTEXT"
        assert str(ev_id) in data["events"]
        assert data["events"][str(ev_id)]["source_type"] == "zeek"

    def test_get_evidence_detail(self, api_client: TestClient, evidence_service: MagicMock) -> None:
        from argusprowl.services.telemetry_evidence_service import EvidenceDetailResult

        ev_id = uuid.uuid4()
        event = NormalizedEvent(
            event_id=ev_id,
            timestamp=datetime.now(UTC),
            source_type="sysmon",
            event_type="process_creation",
        )
        record = EvidenceRecord(
            event_id=ev_id,
            provenance="DETECTION_SOURCE",
        )
        evidence_service.get_detail.return_value = EvidenceDetailResult(
            event_id=ev_id,
            status="AVAILABLE",
            reason=None,
            event=event,
            record=record,
        )

        res = api_client.get(f"/api/v1/evidence/{ev_id}")
        assert res.status_code == 200
        data = res.json()
        assert data["event_id"] == str(ev_id)
        assert data["status"] == "AVAILABLE"
        assert data["event"]["event_id"] == str(ev_id)
        assert data["record"]["provenance"] == "DETECTION_SOURCE"

    def test_get_evicted_contributing_evidence_detail(
        self, api_client: TestClient, evidence_service: MagicMock
    ) -> None:
        from argusprowl.services.telemetry_evidence_service import EvidenceDetailResult

        ev_id = uuid.uuid4()
        record = EvidenceRecord(event_id=ev_id, provenance="CONTRIBUTING_EVENT")
        evidence_service.get_detail.return_value = EvidenceDetailResult(
            event_id=ev_id,
            status="EVICTED",
            reason="Referenced contributing telemetry is no longer retained in memory.",
            event=None,
            record=record,
        )

        res = api_client.get(f"/api/v1/evidence/{ev_id}")
        assert res.status_code == 200
        data = res.json()
        assert data["event_id"] == str(ev_id)
        assert data["status"] == "EVICTED"
        assert data["event"] is None
        assert data["record"]["event_id"] == str(ev_id)
        assert data["record"]["provenance"] == "CONTRIBUTING_EVENT"

    def test_get_evidence_detail_not_found(
        self, api_client: TestClient, evidence_service: MagicMock
    ) -> None:
        evidence_service.get_detail.return_value = None
        res = api_client.get(f"/api/v1/evidence/{uuid.uuid4()}")
        assert res.status_code == 404

    def test_get_evidence_stats(self, api_client: TestClient, evidence_service: MagicMock) -> None:
        evidence_service.get_stats.return_value = {
            "retained_events": 50,
            "max_retained_events": 1000,
            "eviction_count": 0,
            "capacity_used_pct": 5.0,
        }
        res = api_client.get("/api/v1/evidence/stats")
        assert res.status_code == 200
        assert res.json()["retained_events"] == 50

    def test_service_unavailable(self, evidence_service: MagicMock) -> None:
        container = ServiceContainer.get_instance()
        container.reset_instance()

        app = create_api_app()
        with TestClient(app) as client:
            res = client.get("/api/v1/evidence")
            assert res.status_code == 503

            res = client.get(f"/api/v1/evidence/{uuid.uuid4()}")
            assert res.status_code == 503

            res = client.get("/api/v1/evidence/stats")
            assert res.status_code == 503

        container.reset_instance()

    def test_stats_route_not_interpreted_as_event_uuid(
        self, api_client: TestClient, evidence_service: MagicMock
    ) -> None:
        """Prove /evidence/stats is never interpreted as an event UUID path."""
        evidence_service.get_stats.return_value = {
            "retained_events": 10,
            "max_retained_events": 100,
            "eviction_count": 0,
            "capacity_used_pct": 10.0,
        }
        # If /evidence/stats were interpreted as an event UUID, it would hit
        # get_evidence_detail and raise a 404 because "stats" is not a valid UUID.
        res = api_client.get("/api/v1/evidence/stats")
        assert res.status_code == 200
        data = res.json()
        assert data["retained_events"] == 10
        assert data["max_retained_events"] == 100
        assert data["eviction_count"] == 0
        assert data["capacity_used_pct"] == 10.0

    def test_stats_route_service_unavailable(self, evidence_service: MagicMock) -> None:
        """Prove /evidence/stats returns 503 when service is unavailable."""
        container = ServiceContainer.get_instance()
        container.reset_instance()

        app = create_api_app()
        with TestClient(app) as client:
            res = client.get("/api/v1/evidence/stats")
            assert res.status_code == 503

        container.reset_instance()

    def test_alert_detail_includes_contributing_event_status(
        self, api_client: TestClient, evidence_service: MagicMock
    ) -> None:
        """Alert detail includes per-event contributing status."""
        from argusprowl.constants.severity import Severity
        from argusprowl.models.alert import Alert

        alert = Alert(
            alert_id=uuid.uuid4(),
            title="Test Alert",
            description="Test",
            severity=Severity.HIGH,
            source="test",
            contributing_event_ids=(uuid.uuid4(), uuid.uuid4()),
        )

        container = ServiceContainer.get_instance()
        queue = AlertQueue()
        queue.enqueue(alert)
        container.register_singleton(AlertQueue, lambda: queue)

        res = api_client.get(f"/api/v1/alerts/{alert.alert_id}")
        assert res.status_code == 200
        data = res.json()
        assert "contributing_event_status" in data
        assert isinstance(data["contributing_event_status"], dict)

    def test_alert_detail_contributing_event_status_evicted(
        self, api_client: TestClient, evidence_service: MagicMock
    ) -> None:
        """Alert detail shows EVICTED status for evicted contributing events."""
        from argusprowl.constants.severity import Severity
        from argusprowl.lifecycle.queue import AlertQueue
        from argusprowl.models.alert import Alert

        event_id = uuid.uuid4()
        alert = Alert(
            alert_id=uuid.uuid4(),
            title="Test Alert",
            description="Test",
            severity=Severity.HIGH,
            source="test",
            contributing_event_ids=(event_id,),
        )

        evidence_service.resolve_referenced_status.return_value = {event_id: "EVICTED"}

        container = ServiceContainer.get_instance()
        queue = AlertQueue()
        queue.enqueue(alert)
        container.register_singleton(AlertQueue, lambda: queue)

        res = api_client.get(f"/api/v1/alerts/{alert.alert_id}")
        assert res.status_code == 200
        data = res.json()
        assert data["contributing_event_status"][str(event_id)] == "EVICTED"

    def test_alert_detail_contributing_event_status_available(
        self, api_client: TestClient, evidence_service: MagicMock
    ) -> None:
        """Alert detail shows AVAILABLE status for retained contributing events."""
        from argusprowl.constants.severity import Severity
        from argusprowl.lifecycle.queue import AlertQueue
        from argusprowl.models.alert import Alert

        event_id = uuid.uuid4()
        alert = Alert(
            alert_id=uuid.uuid4(),
            title="Test Alert",
            description="Test",
            severity=Severity.HIGH,
            source="test",
            contributing_event_ids=(event_id,),
        )

        evidence_service.resolve_referenced_status.return_value = {event_id: "AVAILABLE"}

        container = ServiceContainer.get_instance()
        queue = AlertQueue()
        queue.enqueue(alert)
        container.register_singleton(AlertQueue, lambda: queue)

        res = api_client.get(f"/api/v1/alerts/{alert.alert_id}")
        assert res.status_code == 200
        data = res.json()
        assert data["contributing_event_status"][str(event_id)] == "AVAILABLE"
