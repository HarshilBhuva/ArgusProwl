"""Unit tests for executing persistent hunt query versions."""
from unittest.mock import MagicMock

from argusprowl.hunting.hunt_service import HuntService
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.hunt_query_execution_service import HuntQueryExecutionService
from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService
from argusprowl.storage.sqlite_storage import SQLiteAdapter


def test_executes_saved_query_attaches_only_durable_matches_and_survives_restart(tmp_path):
    storage = SQLiteAdapter(tmp_path / "hunts.db")
    evidence_storage = SQLiteAdapter(tmp_path / "events.db")
    evidence = TelemetryEvidenceService(storage=evidence_storage)
    event = NormalizedEvent(source_type="sysmon", event_type="process_start", hostname="host-1")
    evidence.record_event(event)
    hunts = HuntService(storage)
    hunt = hunts.create_hunt(title="Investigation", hypothesis="Test", actor="analyst")
    saved = hunts.save_query(hunt.hunt_id, name="processes", definition={"event_type":"process_start","limit":20}, actor="analyst")
    query = saved.queries[0]
    result = HuntQueryExecutionService(evidence).execute(hunts,hunt.hunt_id,query.query_id,1,"analyst")
    assert result.execution.status == "complete"
    assert result.execution.result_count == 1
    assert result.execution.evidence_event_ids == (event.event_id,)
    recovered = HuntService(storage).get_hunt(hunt.hunt_id)
    assert recovered is not None
    assert recovered.executions[0].query_version == 1
    assert recovered.evidence_references[0].event_id == event.event_id
    evidence_storage.close()
    storage.close()


def test_query_execution_rejects_unknown_fields_and_oversized_limits(tmp_path):
    storage = SQLiteAdapter(tmp_path / "hunts.db")
    evidence = MagicMock(spec=TelemetryEvidenceService)
    hunts = HuntService(storage)
    hunt = hunts.create_hunt(title="Investigation", hypothesis="Test", actor="analyst")
    for definition in ({"sql":"select *"}, {"limit":501}):
        saved = hunts.save_query(hunt.hunt_id,name="q"+str(len(hunt.queries)),definition=definition,actor="analyst")
        try:
            HuntQueryExecutionService(evidence).execute(hunts,hunt.hunt_id,saved.queries[-1].query_id,1,"analyst")
        except ValueError:
            pass
        else:
            raise AssertionError("invalid query accepted")
    storage.close()
