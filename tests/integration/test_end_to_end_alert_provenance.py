"""End-to-end durability test for detection alerts and telemetry evidence."""

from __future__ import annotations

from threading import Event
from uuid import UUID, uuid4

from argusprowl.alerting.alert_persistence import AlertPersistence
from argusprowl.constants.severity import Severity
from argusprowl.core.application import Application
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.interfaces.detector import Detector
from argusprowl.interfaces.storage import Storage
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.telemetry_evidence_service import (
    PROVENANCE_DETECTION_SOURCE,
    TelemetryEvidenceService,
)


class _DeterministicEventDetector(Detector):
    """A deterministic test rule executed by the real DetectionManager."""

    def __init__(self, event_id: UUID) -> None:
        self._event_id = event_id

    @property
    def name(self) -> str:
        return "integration.durable-provenance"

    def is_enabled(self) -> bool:
        return True

    def observe(self, _event: NormalizedEvent) -> None:
        """Mark this as an event-based detector for DetectionManager."""

    def detect(self, event: NormalizedEvent) -> DetectionResult:
        return DetectionResult(
            rule_id=self.name,
            event_id=event.event_id,
            matched=event.event_id == self._event_id,
            severity=Severity.HIGH,
            confidence=0.99,
            description="Deterministic end-to-end durability test detection.",
            evidence=[
                {
                    "field": "process_name",
                    "observed": event.process_name or "unknown",
                    "condition": "event matches test rule",
                }
            ],
        )


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
    # Resolve the service registered by the production composition root.
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
        # Use a deterministic test rule, but execute it through the application's
        # real queue consumer, DetectionManager, DecisionEngine, and AlertManager.
        manager = container.resolve(DetectionManager)
        manager.get_registry().clear()
        manager.register_detector(_DeterministicEventDetector(event_id))

        original_record_provenance = evidence.record_provenance

        def signal_after_provenance(*args, **kwargs):
            result = original_record_provenance(*args, **kwargs)
            pipeline_completed.set()
            return result

        evidence.record_provenance = signal_after_provenance  # type: ignore[method-assign]
        app._collector_callback(event)
        assert pipeline_completed.wait(timeout=5), "Queued event did not complete detection/evidence"

        alert_persistence = container.resolve(AlertPersistence)
        before_alerts = alert_persistence.list_all()
        assert len(before_alerts.alerts) == 1
        alert = before_alerts.alerts[0]
        assert alert.source == "integration.durable-provenance"
        assert alert.detection_source_event_id == event_id
        assert alert.metadata["event_id"] == str(event_id)

        evidence_result = evidence.search(event_id=event_id)
        assert evidence_result.status == "AVAILABLE"
        assert evidence_result.returned_count == 1
        recovered_pair = evidence.get_event(event_id)
        assert recovered_pair is not None
        stored_event, evidence_record = recovered_pair
        assert stored_event.to_dict() == event.to_dict()
        assert evidence_record.provenance == PROVENANCE_DETECTION_SOURCE
        assert evidence_record.detection_result_id == UUID(alert.metadata["result_id"])
        assert evidence_record.contributing_event_ids == alert.contributing_event_ids
        assert len(container.resolve(Storage).list_records("telemetry_evidence", limit=10)) == 1
    finally:
        app.shutdown()

    # A new Application, container, SQLite connection, and evidence service
    # simulate process restart; only the persistent database files are reused.
    recovered_app, recovered_container, recovered_evidence = _start_application(config_path)
    try:
        recovered_alerts = recovered_container.resolve(AlertPersistence)
        after_alerts = recovered_alerts.list_all()
        assert len(after_alerts.alerts) == 1
        persisted_alert = recovered_alerts.load_alert(alert.alert_id)
        assert persisted_alert is not None
        assert persisted_alert.to_dict() == alert.to_dict()

        result = recovered_evidence.search(event_id=event_id)
        assert result.status == "AVAILABLE"
        assert result.reason is None
        assert result.returned_count == 1
        detail = recovered_evidence.get_detail(event_id)
        assert detail is not None
        assert detail.status == "AVAILABLE"
        assert detail.event is not None
        assert detail.event.to_dict() == event.to_dict()
        assert detail.record is not None
        assert detail.record.provenance == PROVENANCE_DETECTION_SOURCE
        assert detail.record.detection_result_id == UUID(persisted_alert.metadata["result_id"])
        assert detail.record.contributing_event_ids == persisted_alert.contributing_event_ids
        assert len(
            recovered_container.resolve(Storage).list_records("telemetry_evidence", limit=10)
        ) == 1
    finally:
        recovered_app.shutdown()
