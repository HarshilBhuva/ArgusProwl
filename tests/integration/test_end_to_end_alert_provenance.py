"""End-to-end durability test using the existing first-seen production rule.

The test begins at the normalized-event ingestion boundary. It proves that the
production rule registry detects a first-seen process on a host, then follows
the alert and evidence through durable storage and a fresh application lifecycle.
Source-specific raw-log parsing remains covered upstream of this boundary.
"""

from __future__ import annotations

from threading import Event
from uuid import UUID, uuid4

from argusprowl.alerting.alert_persistence import AlertPersistence
from argusprowl.core.application import Application
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.interfaces.storage import Storage
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.telemetry_evidence_service import (
    PROVENANCE_DETECTION_SOURCE,
    TelemetryEvidenceService,
)


PRODUCTION_RULE_ID = "first_seen_host_process"


def _write_config(tmp_path) -> str:
    config_path = tmp_path / "integration.yaml"
    config_path.write_text(
        "\n".join(
            [
                "app_name: ArgusProwl durability integration test",
                "logging:",
                "  console_enabled: false",
                "  file_enabled: false",
                "  json_enabled: false",
                "storage:",
                f"  base_path: {tmp_path.as_posix()}",
                f"  database_path: {(tmp_path / 'evidence.db').as_posix()}",
                "alert_persistence:",
                "  enabled: true",
                f"  db_path: {(tmp_path / 'alerts.db').as_posix()}",
                "  max_alerts: 100",
                "attck:",
                "  enabled: false",
                "api:",
                "  enabled: false",
                "temporal:",
                "  enabled: false",
                "endpoint_correlation:",
                "  enabled: true",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return str(config_path)


def _start_application(config_path: str):
    container = ServiceContainer()
    app = Application(config_path=config_path, container=container)
    app.startup(start_api=False)
    # Resolve services from the production composition root.
    evidence = container.resolve(TelemetryEvidenceService)
    return app, container, evidence


def test_detection_alert_and_evidence_survive_application_restart(tmp_path) -> None:
    config_path = _write_config(tmp_path)
    event_id = uuid4()
    event = NormalizedEvent(
        source_type="integration-test",
        event_type="process_start",
        event_id=event_id,
        hostname="endpoint-durable-01",
        process_name="suspicious-test-process",
        command_line="suspicious-test-process --fixture",
        source_record_id="durable-provenance-fixture-001",
        raw_event={"fixture": "end-to-end-durable-provenance"},
    )
    pipeline_completed = Event()

    app, container, evidence = _start_application(config_path)
    try:
        # Keep the production registry intact and verify that the configured
        # YAML-backed rule is present before submitting the event.
        manager = container.resolve(DetectionManager)
        detector = manager.get_detector(PRODUCTION_RULE_ID)
        assert detector is not None
        assert detector.is_enabled()

        original_record_provenance = evidence.record_provenance

        def signal_after_provenance(*args, **kwargs):
            result = original_record_provenance(*args, **kwargs)
            pipeline_completed.set()
            return result

        evidence.record_provenance = signal_after_provenance  # type: ignore[method-assign]
        # Submit through the same queue callback used by production collectors.
        app._collector_callback(event)
        assert pipeline_completed.wait(timeout=5), (
            "Queued event did not complete production detection and evidence recording"
        )

        alert_persistence = container.resolve(AlertPersistence)
        before_alerts = alert_persistence.list_all()
        matching_alerts = [
            item for item in before_alerts.alerts
            if item.detection_source_event_id == event_id
        ]
        assert len(matching_alerts) == 1
        alert = matching_alerts[0]

        # The alert must name the actual configured production rule, not a
        # test-only detector or a manually synthesized alert.
        assert alert.source == PRODUCTION_RULE_ID
        assert alert.metadata["rule_id"] == PRODUCTION_RULE_ID
        assert alert.detection_source_event_id == event_id
        assert alert.metadata["event_id"] == str(event_id)
        assert alert.metadata["result_id"]

        evidence_result = evidence.search(event_id=event_id)
        assert evidence_result.status == "AVAILABLE"
        assert evidence_result.reason is None
        assert evidence_result.returned_count == 1
        recovered_pair = evidence.get_event(event_id)
        assert recovered_pair is not None
        stored_event, evidence_record = recovered_pair
        assert stored_event.to_dict() == event.to_dict()
        assert stored_event.timestamp == event.timestamp
        assert evidence_record.event_id == event_id
        assert evidence_record.provenance == PROVENANCE_DETECTION_SOURCE
        assert evidence_record.detection_result_id == UUID(alert.metadata["result_id"])
        assert evidence_record.contributing_event_ids == alert.contributing_event_ids
        assert alert.contributing_event_ids == (event_id,)
        assert len(container.resolve(Storage).list_records("telemetry_evidence", limit=10)) == 1
    finally:
        app.shutdown()

    # A new Application, container, SQLite connection, alert persistence object,
    # and evidence service are created against the same on-disk stores.
    recovered_app, recovered_container, recovered_evidence = _start_application(config_path)
    try:
        recovered_alerts = recovered_container.resolve(AlertPersistence)
        after_alerts = recovered_alerts.list_all()
        matching_alerts = [
            item for item in after_alerts.alerts
            if item.detection_source_event_id == event_id
        ]
        assert len(matching_alerts) == 1
        persisted_alert = recovered_alerts.load_alert(alert.alert_id)
        assert persisted_alert is not None
        assert persisted_alert.to_dict() == alert.to_dict()
        assert persisted_alert.source == PRODUCTION_RULE_ID
        assert persisted_alert.metadata["rule_id"] == PRODUCTION_RULE_ID
        assert persisted_alert.detection_source_event_id == event_id
        assert persisted_alert.metadata["event_id"] == str(event_id)

        # Healthy startup recovery must explicitly report complete availability.
        result = recovered_evidence.search(event_id=event_id)
        assert result.status == "AVAILABLE"
        assert result.reason is None
        assert result.returned_count == 1
        detail = recovered_evidence.get_detail(event_id)
        assert detail is not None
        assert detail.status == "AVAILABLE"
        assert detail.reason is None
        assert detail.event is not None
        assert detail.event.to_dict() == event.to_dict()
        assert detail.record is not None
        assert detail.record.event_id == event_id
        assert detail.record.provenance == PROVENANCE_DETECTION_SOURCE
        assert detail.record.detection_result_id == UUID(persisted_alert.metadata["result_id"])
        assert detail.record.contributing_event_ids == persisted_alert.contributing_event_ids
        assert detail.record.contributing_event_ids == (event_id,)

        # Repeated normal-interface reads must not create duplicate durable rows.
        assert recovered_alerts.load_alert(alert.alert_id).to_dict() == persisted_alert.to_dict()
        assert recovered_evidence.get_detail(event_id).record == detail.record
        assert len(after_alerts.alerts) == 1
        assert len(
            recovered_container.resolve(Storage).list_records("telemetry_evidence", limit=10)
        ) == 1
    finally:
        recovered_app.shutdown()
