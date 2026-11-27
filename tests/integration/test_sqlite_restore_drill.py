"""End-to-end offline restore drill for the separate SQLite state stores."""

import sqlite3

from argusprowl.alerting.alert_persistence import AlertPersistence
from argusprowl.api.audit import AuditLog
from argusprowl.api.auth_store import ApiKeyRevocationStore
from argusprowl.constants.severity import Severity
from argusprowl.models.alert import Alert
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.telemetry_evidence_service import (
    PROVENANCE_DETECTION_SOURCE,
    TelemetryEvidenceService,
)
from argusprowl.storage.sqlite_backup import SQLiteBackupManager
from argusprowl.storage.sqlite_storage import SQLiteAdapter


def test_offline_restore_drill_recovers_all_sqlite_state_stores(tmp_path):
    """Back up, delete, restore, and verify evidence, alerts, auth, and audit."""
    evidence_path = tmp_path / "events.db"
    alerts_path = tmp_path / "alerts.db"
    security_path = tmp_path / "security.db"
    manager = SQLiteBackupManager()

    evidence_storage = SQLiteAdapter(evidence_path)
    evidence_service = TelemetryEvidenceService(storage=evidence_storage)
    source_event = NormalizedEvent(
        source_type="restore-drill",
        event_type="process_start",
        hostname="restore-drill-host",
        process_name="restore-drill-process",
    )
    evidence_service.record_event(source_event, provenance=PROVENANCE_DETECTION_SOURCE)

    alert_store = AlertPersistence(alerts_path)
    alert_store.initialize()
    alert = Alert(
        title="Restore drill alert",
        description="Persisted before the offline backup",
        severity=Severity.HIGH,
        source="restore-drill",
        detection_source_event_id=source_event.event_id,
    )
    assert alert_store.save_alert(alert) is True

    audit = AuditLog(str(security_path))
    audit.append(
        event_type="RESTORE_DRILL",
        actor_id="restore-drill-admin",
        role="admin",
        method="POST",
        path="/api/v1/restore-drill",
        status_code=200,
        request_id="restore-drill-request",
        client_ip="127.0.0.1",
    )
    revocations = ApiKeyRevocationStore(str(security_path))
    assert revocations.revoke("restore-drill-key", revoked_by="restore-drill-admin") is True
    assert revocations.is_revoked("restore-drill-key") is True

    paths = {
        evidence_path: tmp_path / "backup-events.db",
        alerts_path: tmp_path / "backup-alerts.db",
        security_path: tmp_path / "backup-security.db",
    }
    for source, backup in paths.items():
        manager.create_backup(source, backup, application_version="restore-drill")

    evidence_storage.close()
    alert_store.close()
    revocations.close()

    # Simulate loss of the complete local state set after the backups have been
    # published and verified. No live SQLite connections remain open.
    for source in paths:
        source.unlink()
        assert not source.exists()

    for source, backup in paths.items():
        manager.restore_backup(backup, source)
        with sqlite3.connect(source) as connection:
            assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"

    restored_evidence_storage = SQLiteAdapter(evidence_path)
    restored_evidence = TelemetryEvidenceService(storage=restored_evidence_storage)
    detail = restored_evidence.get_detail(source_event.event_id)
    assert detail is not None
    assert detail.event is not None
    assert detail.record is not None
    assert detail.record.provenance == PROVENANCE_DETECTION_SOURCE
    restored_evidence_storage.close()

    restored_alerts = AlertPersistence(alerts_path)
    restored_alerts.initialize()
    alert_result = restored_alerts.list_all()
    assert alert_result.status.value == "AVAILABLE"
    assert [item.alert_id for item in alert_result.alerts] == [alert.alert_id]
    restored_alerts.close()

    restored_audit = AuditLog(str(security_path))
    assert restored_audit.verify_integrity() == {
        "valid": True,
        "checked_count": 1,
        "first_invalid_id": None,
    }
    restored_revocations = ApiKeyRevocationStore(str(security_path))
    assert restored_revocations.is_revoked("restore-drill-key") is True
    restored_revocations.close()
