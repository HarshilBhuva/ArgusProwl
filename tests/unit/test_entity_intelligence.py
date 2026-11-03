"""Relational entity intelligence persistence and provenance tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from argusprowl.entity_intelligence.service import EntityIntelligenceService
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService
from argusprowl.storage.sqlite_storage import SQLiteAdapter


def _event(*, timestamp: datetime | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        source_type="sysmon",
        event_type="process_start",
        timestamp=timestamp or datetime(2026, 1, 1, tzinfo=UTC),
        hostname="WIN-01",
        username="ALICE",
        process_name="powershell.exe",
        pid=4321,
        dst_ip="203.0.113.10",
        attributes={
            "ProcessGuid": "{CHILD-GUID}",
            "ParentProcessGuid": "{PARENT-GUID}",
            "ParentProcessId": "1000",
            "ParentImage": r"C:\Windows\explorer.exe",
            "dns": {
                "rrname": "Example.COM.",
                "answers": ["203.0.113.20"],
            },
            "fileinfo": {
                "filename": r"C:\Temp\payload.exe",
                "sha256": "a" * 64,
            },
        },
    )


def test_event_ingestion_indexes_entities_relationships_and_process_ancestry(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "entities.db")
    evidence = TelemetryEvidenceService(storage=storage)
    event = _event()
    evidence.record_event(event)
    service = EntityIntelligenceService(storage)

    entities = service.list_entities(limit=100)
    entity_types = {item.entity_type for item in entities}
    assert {"hostname", "user", "process", "ip", "domain", "file", "file_hash"} <= entity_types

    host = service.get_entity("hostname", "win-01")
    assert host is not None
    assert host.observation_count == 1

    child = service.get_entity("process", "win-01|guid:{child-guid}")
    assert child is not None
    ancestry = service.get_relationships(
        "process",
        child.entity_id,
        direction="inbound",
    )
    parent_edges = [edge for edge in ancestry if edge.relationship_type == "PARENT_OF"]
    assert len(parent_edges) == 1
    assert parent_edges[0].evidence_kind.value == "OBSERVED"
    assert parent_edges[0].confidence == 1.0
    assert parent_edges[0].source_entity_id == "win-01|guid:{parent-guid}"
    assert parent_edges[0].evidence_refs[0].event_id == str(event.event_id)
    assert parent_edges[0].evidence_refs[0].available is True
    storage.close()


def test_duplicate_event_does_not_inflate_entity_or_relationship_counts(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "entities.db")
    evidence = TelemetryEvidenceService(storage=storage)
    event = _event()
    evidence.record_event(event)
    evidence.record_event(event)
    service = EntityIntelligenceService(storage)

    host = service.get_entity("hostname", "win-01")
    assert host is not None
    assert host.observation_count == 1
    edges = service.get_relationships("hostname", "win-01")
    host_process = [edge for edge in edges if edge.relationship_type == "RUNS_PROCESS"]
    assert len(host_process) == 1
    assert host_process[0].observation_count == 1
    storage.close()


def test_inferred_relationship_is_separate_and_requires_durable_evidence(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "entities.db")
    evidence = TelemetryEvidenceService(storage=storage)
    event = _event()
    evidence.record_event(event)
    service = EntityIntelligenceService(storage)

    service.record_inferred_relationship(
        "user",
        "alice",
        "hostname",
        "win-01",
        "ATTRIBUTED_TO",
        confidence=0.72,
        provenance="analyst-correlation:v1",
        evidence_event_ids=(str(event.event_id),),
    )
    relationships = service.get_relationships("user", "alice", direction="outbound")
    inferred = [edge for edge in relationships if edge.relationship_type == "ATTRIBUTED_TO"]
    assert len(inferred) == 1
    assert inferred[0].evidence_kind.value == "INFERRED"
    assert inferred[0].confidence == 0.72
    assert inferred[0].provenance == "analyst-correlation:v1"
    assert inferred[0].evidence_refs[0].available is True

    with pytest.raises(ValueError, match="confidence"):
        service.record_inferred_relationship(
            "user",
            "alice",
            "hostname",
            "win-01",
            "ATTRIBUTED_TO",
            confidence=1.1,
            provenance="invalid",
            evidence_event_ids=(str(event.event_id),),
        )
    storage.close()


def test_evidence_references_survive_retention_as_unavailable_tombstones(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "entities.db")
    evidence = TelemetryEvidenceService(
        storage=storage,
        retention_enabled=True,
        retention_days=1,
    )
    event = _event()
    evidence.record_event(event)

    deleted = storage.purge_expired_telemetry_evidence(
        event.timestamp + timedelta(seconds=1),
        batch_size=10,
    )
    assert deleted == [event.event_id]

    references = EntityIntelligenceService(storage).get_evidence("hostname", "win-01")
    assert len(references) == 1
    assert references[0].event_id == str(event.event_id)
    assert references[0].available is False
    storage.close()


def test_entity_index_migration_backfills_existing_evidence_records(tmp_path) -> None:
    database = tmp_path / "legacy.db"
    event = _event()
    payload = {
        "event": event.to_dict(),
        "provenance": "OBSERVED_CONTEXT",
        "detection_result_id": None,
        "contributing_event_ids": [],
    }
    storage = SQLiteAdapter(database)
    with storage._lock, storage._connection:
        storage._connection.execute(
            "INSERT INTO records(collection, record_id, payload) VALUES (?, ?, ?)",
            ("telemetry_evidence", str(event.event_id), json.dumps(payload)),
        )
        storage._connection.execute("DELETE FROM schema_migrations WHERE version IN (1, 2)")
    storage.close()

    migrated = SQLiteAdapter(database)
    host = EntityIntelligenceService(migrated).get_entity("hostname", "win-01")
    assert host is not None
    assert host.observation_count == 1
    migrated.close()


def test_entity_relationship_queries_use_directional_indexes(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "entities.db")
    plan = storage._connection.execute(
        """EXPLAIN QUERY PLAN
        SELECT relationship_id
        FROM entity_intelligence_relationships
        WHERE source_entity_id=?
        ORDER BY last_seen DESC
        LIMIT ?""",
        ("entity-id", 10),
    ).fetchall()
    details = " ".join(str(row[-1]) for row in plan)
    assert "idx_entity_intelligence_rel_source_seen" in details
    storage.close()
