"""End-to-end Hunt query execution and evidence ownership API tests."""

from uuid import UUID

from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.hunting.hunt_service import HuntService
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.hunt_query_execution_service import HuntQueryExecutionService
from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService
from argusprowl.storage.sqlite_storage import SQLiteAdapter


def test_analyst_executes_exact_owned_event_query_and_recovers_after_restart(tmp_path):
    ServiceContainer.reset_instance()
    container = ServiceContainer.get_instance()
    hunt_storage = SQLiteAdapter(tmp_path / "hunts.db")
    event_storage = SQLiteAdapter(tmp_path / "events.db")
    evidence = TelemetryEvidenceService(storage=event_storage)
    event = NormalizedEvent(
        source_type="sysmon",
        event_type="process_start",
        hostname="host-01",
        metadata={"owner_subject": "analyst-01"},
    )
    evidence.record_event(event)
    hunts = HuntService(hunt_storage)
    container.register_singleton(HuntService, hunts)
    container.register_singleton(TelemetryEvidenceService, evidence)
    container.register_singleton(
        HuntQueryExecutionService, HuntQueryExecutionService(evidence)
    )
    secret = "analyst-query-execution-test-secret-32chars"
    app = create_api_app(
        auth_enabled=True,
        api_keys={
            "analyst": {
                "secret": secret,
                "subject": "analyst-01",
                "role": "analyst",
            }
        },
        audit_db_path=str(tmp_path / "audit.db"),
    )
    try:
        with TestClient(app) as client:
            headers = {"X-ArgusProwl-Key": secret}
            created = client.post(
                "/api/v1/hunts",
                json={"title": "Test", "hypothesis": "Find process starts"},
                headers=headers,
            )
            assert created.status_code == 200
            hunt_id = created.json()["hunt_id"]
            saved = client.post(
                f"/api/v1/hunts/{hunt_id}/queries",
                json={"name": "proc", "definition": {"event_id": str(event.event_id)}},
                headers=headers,
            )
            assert saved.status_code == 200
            query = saved.json()["queries"][0]
            response = client.post(
                f"/api/v1/hunts/{hunt_id}/queries/{query['query_id']}/execute?version=1",
                headers=headers,
            )
            assert response.status_code == 200, response.text
            assert response.json()["execution"]["result_count"] == 1
            assert response.json()["execution"]["status"] == "complete"

        recovered = HuntService(SQLiteAdapter(tmp_path / "hunts.db")).get_hunt(
            UUID(hunt_id)
        )
        assert recovered is not None
        assert len(recovered.executions) == 1
        assert recovered.evidence_references[0].event_id == event.event_id
    finally:
        ServiceContainer.reset_instance()
        event_storage.close()
        hunt_storage.close()


def test_analyst_cannot_attach_or_execute_against_another_owners_evidence(tmp_path):
    ServiceContainer.reset_instance()
    container = ServiceContainer.get_instance()
    hunt_storage = SQLiteAdapter(tmp_path / "owned-hunts.db")
    event_storage = SQLiteAdapter(tmp_path / "owned-events.db")
    evidence = TelemetryEvidenceService(storage=event_storage)
    foreign_event = NormalizedEvent(
        source_type="sysmon",
        event_type="process_start",
        hostname="host-private",
        metadata={"owner_subject": "analyst-02"},
    )
    evidence.record_event(foreign_event)
    hunts = HuntService(hunt_storage)
    container.register_singleton(HuntService, hunts)
    container.register_singleton(TelemetryEvidenceService, evidence)
    container.register_singleton(
        HuntQueryExecutionService, HuntQueryExecutionService(evidence)
    )
    secret = "analyst-evidence-owner-check-secret-32chars"
    app = create_api_app(
        auth_enabled=True,
        api_keys={
            "analyst": {
                "secret": secret,
                "subject": "analyst-01",
                "role": "analyst",
            }
        },
        audit_db_path=str(tmp_path / "owned-audit.db"),
    )
    try:
        with TestClient(app) as client:
            headers = {"X-ArgusProwl-Key": secret}
            created = client.post(
                "/api/v1/hunts",
                json={
                    "title": "Scoped hunt",
                    "hypothesis": "Investigate owned telemetry",
                },
                headers=headers,
            )
            assert created.status_code == 200
            hunt_id = created.json()["hunt_id"]
            saved = client.post(
                f"/api/v1/hunts/{hunt_id}/queries",
                json={
                    "name": "broad",
                    "definition": {"event_type": "process_start"},
                },
                headers=headers,
            )
            assert saved.status_code == 200
            query_id = saved.json()["queries"][0]["query_id"]

            broad_execution = client.post(
                f"/api/v1/hunts/{hunt_id}/queries/{query_id}/execute?version=1",
                headers=headers,
            )
            assert broad_execution.status_code == 403

            attached = client.post(
                f"/api/v1/hunts/{hunt_id}/evidence",
                json={"event_id": str(foreign_event.event_id), "role": "context"},
                headers=headers,
            )
            assert attached.status_code == 404

            receipt = client.post(
                f"/api/v1/hunts/{hunt_id}/executions",
                json={
                    "query_id": query_id,
                    "query_version": 1,
                    "started_at": "2026-11-20T10:00:00Z",
                    "completed_at": "2026-11-20T10:00:01Z",
                    "result_count": 1,
                    "evidence_event_ids": [str(foreign_event.event_id)],
                },
                headers=headers,
            )
            assert receipt.status_code == 404

            detail = client.get(f"/api/v1/hunts/{hunt_id}", headers=headers)
            assert detail.status_code == 200
            assert detail.json()["evidence_references"] == []
            assert detail.json()["executions"] == []
    finally:
        ServiceContainer.reset_instance()
        event_storage.close()
        hunt_storage.close()
