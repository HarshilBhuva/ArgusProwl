"""End-to-end Hunt query execution API tests."""
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.hunting.hunt_service import HuntService
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.hunt_query_execution_service import HuntQueryExecutionService
from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService
from argusprowl.storage.sqlite_storage import SQLiteAdapter


def test_analyst_executes_query_searches_real_event_and_recovers_after_restart(tmp_path):
    ServiceContainer.reset_instance()
    container = ServiceContainer.get_instance()
    hunt_db = tmp_path / "hunts.db"
    event_db = tmp_path / "events.db"
    hunt_storage = SQLiteAdapter(hunt_db)
    event_storage = SQLiteAdapter(event_db)
    evidence = TelemetryEvidenceService(storage=event_storage)
    event = NormalizedEvent(source_type="sysmon",event_type="process_start",hostname="host-01")
    evidence.record_event(event)
    hunts = HuntService(hunt_storage)
    container.register_singleton(HuntService, hunts)
    container.register_singleton(TelemetryEvidenceService, evidence)
    container.register_singleton(HuntQueryExecutionService, HuntQueryExecutionService(evidence))
    secret="analyst-query-execution-test-secret-32chars"
    app=create_api_app(auth_enabled=True,api_keys={"analyst":{"secret":secret,"subject":"analyst-01","role":"analyst"}},audit_db_path=str(tmp_path/"audit.db"))
    with TestClient(app) as client:
        headers={"X-ArgusProwl-Key":secret}
        created=client.post("/api/v1/hunts",json={"title":"Test","hypothesis":"Find process starts"},headers=headers).json()
        hunt_id=created["hunt_id"]
        saved=client.post(f"/api/v1/hunts/{hunt_id}/queries",json={"name":"proc","definition":{"event_type":"process_start"}},headers=headers).json()
        query=saved["queries"][0]
        response=client.post(f"/api/v1/hunts/{hunt_id}/queries/{query['query_id']}/execute?version=1",headers=headers)
        assert response.status_code==200,response.text
        assert response.json()["execution"]["result_count"]==1
        assert response.json()["execution"]["status"]=="complete"
    recovered=HuntService(SQLiteAdapter(hunt_db)).get_hunt(__import__("uuid").UUID(hunt_id))
    assert recovered is not None and len(recovered.executions)==1
    assert recovered.evidence_references[0].event_id==event.event_id
    ServiceContainer.reset_instance()
    event_storage.close()
    hunt_storage.close()
