"""Indexed historical telemetry search and pagination integration tests."""

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService
from argusprowl.storage.sqlite_storage import SQLiteAdapter


def _event(index: int, *, source_type: str = "sysmon", hostname: str = "host-1") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=uuid4(),
        timestamp=datetime(2025, 1, 1, tzinfo=UTC) + timedelta(minutes=index),
        source_type=source_type,
        event_type="process_start" if index % 2 == 0 else "network_connection",
        hostname=hostname,
        username="analyst",
        process_name="agent.exe",
        src_ip="10.0.0.10",
        dst_ip="198.51.100.20",
    )


def test_indexed_search_pages_all_durable_records_after_cache_eviction(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    service = TelemetryEvidenceService(max_retained_events=1, storage=storage)
    events = [_event(i) for i in range(3)]
    for event in events:
        service.record_event(event)

    first = service.search(limit=1)
    second = service.search(limit=1, cursor=first.next_cursor)
    third = service.search(limit=1, cursor=second.next_cursor)

    assert first.total_count == second.total_count == third.total_count == 3
    assert first.returned_count == second.returned_count == third.returned_count == 1
    assert first.truncated and second.truncated
    assert first.next_cursor and second.next_cursor
    assert third.truncated is False
    assert third.next_cursor is None
    assert [first.records[0].event_id, second.records[0].event_id, third.records[0].event_id] == [
        event.event_id for event in events
    ]

    # The first event is outside the hot cache but remains authoritative in SQLite.
    assert service.get_event(events[0].event_id) is None
    historical = service.get_detail(events[0].event_id)
    assert historical is not None and historical.event is not None
    assert historical.event.event_id == events[0].event_id
    storage.close()


def test_historical_contributing_event_remains_available_after_cache_eviction(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    service = TelemetryEvidenceService(max_retained_events=1, storage=storage)
    first = _event(0)
    service.record_event(first, "DETECTION_SOURCE")
    service.record_event(_event(1))

    detail = service.get_detail(first.event_id)
    assert detail is not None
    assert detail.status == "AVAILABLE"
    assert detail.event is not None
    assert detail.record is not None
    assert service.resolve_referenced_status((first.event_id,))[first.event_id] == "AVAILABLE"
    storage.close()


def test_indexed_search_applies_filters_and_inclusive_time_bounds(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    service = TelemetryEvidenceService(storage=storage)
    matching = _event(1, hostname="workstation-02")
    service.record_event(_event(0, hostname="workstation-01"))
    service.record_event(matching)
    service.record_event(_event(2, source_type="zeek", hostname="workstation-02"))

    result = service.search(
        start_time=matching.timestamp,
        end_time=matching.timestamp,
        source_type="sysmon",
        entity_type="hostname",
        entity_id="WORKSTATION-02",
        event_type="network_connection",
    )
    assert result.total_count == 1
    assert result.records[0].event_id == matching.event_id
    storage.close()


def test_index_is_deleted_atomically_with_its_authoritative_record(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    event = _event(0)
    storage.save(
        "telemetry_evidence",
        event.event_id,
        {
            "event": event.to_dict(),
            "provenance": "OBSERVED_CONTEXT",
            "detection_result_id": None,
            "contributing_event_ids": [],
        },
    )
    assert storage.search_telemetry_evidence({}, limit=10)["total_count"] == 1

    assert storage.delete("telemetry_evidence", event.event_id) is True
    assert storage.search_telemetry_evidence({}, limit=10)["total_count"] == 0
    storage.close()


def test_legacy_evidence_rows_are_backfilled_into_the_search_index(tmp_path) -> None:
    path = tmp_path / "legacy.db"
    event = _event(0)
    payload = {
        "event": event.to_dict(),
        "provenance": "OBSERVED_CONTEXT",
        "detection_result_id": None,
        "contributing_event_ids": [],
    }
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE records (collection TEXT NOT NULL, record_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(collection, record_id))"
    )
    connection.execute(
        "INSERT INTO records(collection, record_id, payload) VALUES (?, ?, ?)",
        ("telemetry_evidence", str(event.event_id), json.dumps(payload)),
    )
    connection.commit()
    connection.close()

    storage = SQLiteAdapter(path)
    result = storage.search_telemetry_evidence({"entity_type": "hostname", "entity_id": "host-1"}, limit=10)
    assert result["total_count"] == 1
    assert result["records"][0]["event"]["event_id"] == str(event.event_id)
    storage.close()


def test_source_filter_uses_a_persisted_search_index(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    plan = storage._connection.execute(
        """EXPLAIN QUERY PLAN
        SELECT event_id FROM telemetry_evidence_index
        WHERE source_type=? ORDER BY timestamp ASC, event_id ASC LIMIT ?""",
        ("sysmon", 50),
    ).fetchall()
    details = " ".join(str(row[-1]) for row in plan)
    assert "idx_evidence_source_type_time" in details
    storage.close()


def test_invalid_or_tampered_cursor_is_rejected(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    try:
        storage.search_telemetry_evidence({}, limit=10, cursor="not-a-valid-cursor")
    except ValueError as exc:
        assert "Invalid evidence pagination cursor" in str(exc)
    else:
        raise AssertionError("invalid cursor was accepted")
    storage.close()


def test_retention_deletes_only_expired_rows_in_bounded_batches(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    service = TelemetryEvidenceService(max_retained_events=10, storage=storage)
    events = [_event(i) for i in range(3)]
    for event in events:
        service.record_event(event)

    cutoff = datetime(2025, 1, 1, 0, 2, tzinfo=UTC)
    first = service.run_retention(cutoff, batch_size=1)
    assert first["deleted_count"] == 1
    assert first["event_ids"] == (events[0].event_id,)
    assert storage.load("telemetry_evidence", events[0].event_id) is None
    assert service.get_event(events[0].event_id) is None
    assert storage.search_telemetry_evidence({}, limit=10)["total_count"] == 2

    second = service.run_retention(cutoff, batch_size=1)
    assert second["deleted_count"] == 1
    assert second["event_ids"] == (events[1].event_id,)
    assert storage.load("telemetry_evidence", events[1].event_id) is None
    assert storage.load("telemetry_evidence", events[2].event_id) is not None
    assert service.get_stats()["retention_last_deleted_count"] == 1
    assert service.get_stats()["retention_runs_failed"] == 0
    storage.close()


def test_retention_does_not_delete_events_at_or_after_cutoff(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    service = TelemetryEvidenceService(storage=storage)
    event = _event(2)
    service.record_event(event)

    result = service.run_retention(event.timestamp, batch_size=10)

    assert result["deleted_count"] == 0
    assert storage.load("telemetry_evidence", event.event_id) is not None
    assert storage.count_telemetry_evidence() == 1
    storage.close()


def test_retention_delete_failure_rolls_back_records_and_index(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    service = TelemetryEvidenceService(storage=storage)
    event = _event(0)
    service.record_event(event)
    storage._connection.execute(
        """CREATE TRIGGER fail_evidence_retention BEFORE DELETE ON records
        WHEN OLD.collection = 'telemetry_evidence'
        BEGIN SELECT RAISE(ABORT, 'synthetic retention failure'); END"""
    )
    storage._connection.commit()

    try:
        service.run_retention(datetime(2025, 1, 1, 0, 1, tzinfo=UTC), batch_size=10)
    except Exception:
        pass
    else:
        raise AssertionError("retention failure should be propagated")

    assert storage.load("telemetry_evidence", event.event_id) is not None
    assert storage.count_telemetry_evidence() == 1
    assert service.get_stats()["retention_runs_failed"] == 1
    assert service.get_stats()["retention_last_error"]
    storage.close()


def test_retention_rejects_naive_cutoff_and_invalid_batch_size(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    service = TelemetryEvidenceService(storage=storage)
    try:
        service.run_retention(datetime(2025, 1, 1), batch_size=10)
    except ValueError as exc:
        assert "timezone-aware" in str(exc)
    else:
        raise AssertionError("naive cutoff was accepted")
    try:
        service.run_retention(datetime(2025, 1, 1, tzinfo=UTC), batch_size=0)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid batch size was accepted")
    storage.close()


def test_storage_metrics_report_database_footprint_and_integrity(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    service = TelemetryEvidenceService(storage=storage)
    service.record_event(_event(0))

    stats = service.get_stats()
    metrics = stats["storage_metrics"]
    assert metrics["database_bytes"] > 0
    assert metrics["wal_bytes"] >= 0
    assert metrics["durable_events"] == 1
    assert storage.check_integrity() == "ok"
    storage.close()
