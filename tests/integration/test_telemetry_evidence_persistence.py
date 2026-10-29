"""Integration tests for durable telemetry evidence and alert persistence."""

import sqlite3
from uuid import uuid4

import pytest

from argusprowl.alerting.alert_manager import AlertManager
from argusprowl.alerting.alert_persistence import AlertPersistence
from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.severity import Severity
from argusprowl.exceptions.exceptions import StorageError
from argusprowl.metrics.collector import MetricsCollector
from argusprowl.models.alert import Alert
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.telemetry_evidence_service import (
    PROVENANCE_DETECTION_SOURCE,
    PROVENANCE_OBSERVED_CONTEXT,
    TelemetryEvidenceService,
)
from argusprowl.storage.sqlite_storage import SQLiteAdapter


def _event(*, event_id=None, event_type="process_start") -> NormalizedEvent:
    return NormalizedEvent(
        source_type="test",
        event_type=event_type,
        event_id=event_id or uuid4(),
        hostname="endpoint-01",
        process_name="example.exe",
        raw_event={"fixture": "durability"},
    )


def _alert(event: NormalizedEvent, *, alert_id=None) -> Alert:
    return Alert(
        title="Test detection",
        description="Evidence persistence integration test",
        severity=Severity.HIGH,
        source="test-detector",
        alert_id=alert_id or uuid4(),
        detection_source_event_id=event.event_id,
        contributing_event_ids=(event.event_id,),
    )


def test_evidence_and_alert_survive_storage_restart_and_remain_linked(tmp_path) -> None:
    evidence_db = tmp_path / "evidence.db"
    alerts_db = tmp_path / "alerts.db"
    event = _event()
    alert = _alert(event)

    storage = SQLiteAdapter(evidence_db)
    metrics = MetricsCollector()
    evidence = TelemetryEvidenceService(storage=storage, metrics_collector=metrics)
    evidence.record_event(event, PROVENANCE_OBSERVED_CONTEXT)
    evidence.record_provenance(
        event.event_id,
        PROVENANCE_DETECTION_SOURCE,
        detection_result_id=uuid4(),
        contributing_event_ids=(event.event_id,),
    )

    alerts = AlertPersistence(alerts_db)
    alerts.initialize()
    assert alerts.save_alert(alert) is True
    alerts.close()
    storage.close()

    # A fresh service and fresh connections simulate a process restart.
    recovered_storage = SQLiteAdapter(evidence_db)
    recovered_evidence = TelemetryEvidenceService(storage=recovered_storage)
    recovered_alerts = AlertPersistence(alerts_db)
    recovered_alerts.initialize()

    recovered = recovered_evidence.get_event(event.event_id)
    persisted_alert = recovered_alerts.load_alert(alert.alert_id)

    assert recovered is not None
    recovered_event, evidence_record = recovered
    assert recovered_event.to_dict() == event.to_dict()
    assert evidence_record.provenance == PROVENANCE_DETECTION_SOURCE
    assert evidence_record.contributing_event_ids == (event.event_id,)
    assert persisted_alert is not None
    assert persisted_alert.detection_source_event_id == event.event_id
    assert persisted_alert.contributing_event_ids == (event.event_id,)

    recovered_alerts.close()
    recovered_storage.close()


def test_evidence_write_failure_is_reported_and_not_cached(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    metrics = MetricsCollector()
    service = TelemetryEvidenceService(storage=storage, metrics_collector=metrics)
    event = _event()

    # Abort after SQLite has performed the INSERT, exercising transaction rollback.
    storage._connection.execute(
        """CREATE TRIGGER fail_evidence_insert AFTER INSERT ON records
        WHEN NEW.collection = 'telemetry_evidence'
        BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END"""
    )
    storage._connection.commit()

    with pytest.raises(StorageError):
        service.record_event(event)

    assert service.get_event(event.event_id) is None
    assert storage.load("telemetry_evidence", event.event_id) is None
    assert metrics.get_counter("evidence_persistence_writes_failed").get_value() == 1
    assert metrics.get_counter("evidence_persistence_writes_succeeded").get_value() == 0

    # Recovery is explicit: remove the failing trigger and retry once.
    storage._connection.execute("DROP TRIGGER fail_evidence_insert")
    storage._connection.commit()
    service.record_event(event)
    assert service.get_event(event.event_id) is not None
    assert storage.load("telemetry_evidence", event.event_id) is not None
    assert metrics.get_counter("evidence_persistence_writes_succeeded").get_value() == 1
    storage.close()


def test_duplicate_evidence_write_is_idempotent_and_conflicts_are_rejected(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    service = TelemetryEvidenceService(storage=storage)
    event = _event()

    service.record_event(event)
    service.record_provenance(
        event.event_id,
        PROVENANCE_DETECTION_SOURCE,
        detection_result_id=uuid4(),
        contributing_event_ids=(event.event_id,),
    )
    service.record_event(event)

    rows = storage.list_records("telemetry_evidence", limit=10)
    assert len(rows) == 1
    assert service.get_event(event.event_id) is not None

    conflicting = _event(event_id=event.event_id, event_type="different_event")
    with pytest.raises(ValueError, match="Conflicting telemetry payload"):
        service.record_event(conflicting)

    persisted = storage.load("telemetry_evidence", event.event_id)
    assert persisted is not None
    assert persisted["event"]["event_type"] == event.event_type
    assert persisted["provenance"] == PROVENANCE_DETECTION_SOURCE
    assert persisted["contributing_event_ids"] == [str(event.event_id)]
    storage.close()


def test_alert_write_failure_rolls_back_eviction_and_partial_write(tmp_path, monkeypatch) -> None:
    persistence = AlertPersistence(tmp_path / "alerts.db", max_alerts=1)
    persistence.initialize()
    original_event = _event()
    original_alert = _alert(original_event)
    assert persistence.save_alert(original_alert) is True

    next_alert = _alert(_event())

    def delete_then_fail(conn):
        conn.execute(
            "DELETE FROM alerts WHERE alert_id = ?",
            (str(original_alert.alert_id),),
        )
        raise sqlite3.OperationalError("synthetic failure after eviction")

    monkeypatch.setattr(persistence, "_evict_oldest", delete_then_fail)
    assert persistence.save_alert(next_alert) is False

    # The failed transaction must not lose the previously committed alert.
    assert persistence.load_alert(original_alert.alert_id) is not None
    assert persistence.load_alert(next_alert.alert_id) is None
    persistence.close()


def test_duplicate_alert_save_does_not_evict_existing_alert(tmp_path) -> None:
    persistence = AlertPersistence(tmp_path / "alerts.db", max_alerts=1)
    persistence.initialize()
    event = _event()
    alert = _alert(event)

    assert persistence.save_alert(alert) is True
    assert persistence.update_lifecycle(alert.alert_id, AlertLifecycleState.ACKNOWLEDGED.value) is True
    assert persistence.save_alert(alert) is True
    loaded = persistence.load_alert(alert.alert_id)
    assert loaded is not None
    assert loaded.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED
    assert len(persistence.list_all().alerts) == 1
    persistence.close()


def test_alert_manager_reports_false_persistence_result(tmp_path) -> None:
    persistence = AlertPersistence(tmp_path / "alerts.db")
    persistence.initialize()
    event = _event()
    alert = _alert(event)
    manager = AlertManager(alert_persistence=persistence)

    # Force an explicit storage rejection without changing the public send API.
    persistence._initialized = False
    manager.send_alert(alert)

    stats = manager.get_statistics()
    assert stats["alert_persistence_writes_succeeded"] == 0
    assert stats["alert_persistence_writes_failed"] == 1
    persistence.close()


def test_evidence_retention_evicts_durable_records_but_duplicate_does_not(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    service = TelemetryEvidenceService(max_retained_events=1, storage=storage)
    first = _event()
    second = _event()

    service.record_event(first)
    service.record_event(first)  # duplicate must not evict itself or another record
    assert storage.load("telemetry_evidence", first.event_id) is not None

    service.record_event(second)
    assert service.get_event(first.event_id) is None
    assert storage.load("telemetry_evidence", first.event_id) is None
    assert service.get_event(second.event_id) is not None
    assert storage.load("telemetry_evidence", second.event_id) is not None
    storage.close()


def test_startup_list_failure_marks_search_and_health_unavailable(tmp_path, monkeypatch) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")

    def fail_list_records(*args, **kwargs):
        raise StorageError("synthetic startup read failure")

    monkeypatch.setattr(storage, "list_records", fail_list_records)
    service = TelemetryEvidenceService(storage=storage)

    result = service.search()
    assert result.status == "UNAVAILABLE"
    assert result.reason and "could not be loaded" in result.reason
    assert result.returned_count == 0
    stats = service.get_stats()
    assert stats["recovery_status"] == "UNAVAILABLE"
    assert stats["recovery_reason"] == result.reason
    missing_detail = service.get_detail(uuid4())
    assert missing_detail is not None
    assert missing_detail.status == "UNAVAILABLE"
    assert missing_detail.event is None
    storage.close()


def test_malformed_persisted_record_marks_recovery_degraded(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    malformed_id = uuid4()
    valid = _event()
    storage.save(
        "telemetry_evidence",
        malformed_id,
        {"event": {"not": "a normalized event"}, "provenance": "INVALID"},
    )
    storage.save(
        "telemetry_evidence",
        valid.event_id,
        {
            "event": valid.to_dict(),
            "provenance": PROVENANCE_OBSERVED_CONTEXT,
            "detection_result_id": None,
            "contributing_event_ids": [],
        },
    )

    service = TelemetryEvidenceService(storage=storage)
    result = service.search()
    assert result.status == "DEGRADED"
    assert result.reason and "malformed persisted record" in result.reason
    assert result.returned_count == 1
    assert valid.event_id in result.events
    detail = service.get_detail(valid.event_id)
    assert detail is not None
    assert detail.status == "DEGRADED"
    # An absent ID is not evidence of a healthy miss when recovery was partial.
    missing_detail = service.get_detail(uuid4())
    assert missing_detail is not None
    assert missing_detail.status == "DEGRADED"
    assert missing_detail.reason and "malformed persisted record" in missing_detail.reason
    assert service.get_stats()["recovery_status"] == "DEGRADED"
    storage.close()


def test_successful_recovery_with_no_matches_returns_available_empty_result(tmp_path) -> None:
    storage = SQLiteAdapter(tmp_path / "evidence.db")
    service = TelemetryEvidenceService(storage=storage)

    result = service.search(event_type="not-present")
    assert result.status == "AVAILABLE"
    assert result.reason is None
    assert result.returned_count == 0
    assert service.get_stats()["recovery_status"] == "AVAILABLE"
    storage.close()


def test_successful_recovery_preserves_available_status_for_recovered_event(tmp_path) -> None:
    db_path = tmp_path / "evidence.db"
    event = _event()
    first_storage = SQLiteAdapter(db_path)
    first = TelemetryEvidenceService(storage=first_storage)
    first.record_event(event)
    first_storage.close()

    recovered_storage = SQLiteAdapter(db_path)
    recovered = TelemetryEvidenceService(storage=recovered_storage)
    result = recovered.search(event_id=event.event_id)
    detail = recovered.get_detail(event.event_id)

    assert result.status == "AVAILABLE"
    assert result.returned_count == 1
    assert detail is not None and detail.status == "AVAILABLE"
    recovered_storage.close()
