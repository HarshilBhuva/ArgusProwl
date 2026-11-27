"""Acceptance test: real Zeek quickstart PCAP through parsing and detection."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from argusprowl.alerting.alert_persistence import AlertPersistence
from argusprowl.collectors.zeek.parser import ZeekConnLogParser
from argusprowl.core.application import Application
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService


def _write_config(tmp_path: Path) -> str:
    config_path = tmp_path / "real-pcap.yaml"
    config_path.write_text(
        "\n".join(
            [
                "app_name: ArgusProwl real PCAP acceptance",
                "logging:",
                "  console_enabled: false",
                "  file_enabled: false",
                "  json_enabled: false",
                "storage:",
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
                "",
            ]
        ),
        encoding="utf-8",
    )
    return str(config_path)


def test_real_zeek_pcap_reaches_production_detection_and_evidence(tmp_path):
    """Replay Zeek output generated from the upstream, real quickstart.pcap."""
    log_path = os.environ.get("ARGUSPROWL_REAL_ZEEK_CONN_LOG")
    if not log_path:
        pytest.skip("Real PCAP acceptance runs in the dedicated Zeek CI job.")

    conn_log = Path(log_path)
    assert conn_log.is_file() and conn_log.stat().st_size > 0

    parser = ZeekConnLogParser()
    events = [
        parser.parse(line)
        for line in conn_log.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert len(events) == 2, "The pinned Zeek quickstart capture should produce two connections."
    assert all(event.source_type == "zeek" for event in events)
    assert all(event.src_ip and event.dst_ip and event.source_record_id for event in events)

    app = Application(config_path=_write_config(tmp_path), container=ServiceContainer())
    app.startup(start_api=False)
    try:
        # Submit the real parser output to the same production event-processing
        # method used by the ingestion worker; do not synthesize NormalizedEvent.
        assert all(app._process_event(event) is True for event in events)

        container = app._container
        evidence = container.resolve(TelemetryEvidenceService)
        for event in events:
            detail = evidence.get_detail(event.event_id)
            assert detail is not None
            assert detail.event is not None
            assert detail.event.to_dict() == event.to_dict()

        persisted_alerts = container.resolve(AlertPersistence).list_all()
        assert persisted_alerts.status.value == "AVAILABLE"
        detections = [
            alert
            for alert in persisted_alerts.alerts
            if alert.source == "first_seen_src_dst"
        ]
        assert detections, (
            "The real capture's source/destination pair should trigger the enabled "
            "first_seen_src_dst production rule."
        )
        assert all(
            alert.detection_source_event_id in {event.event_id for event in events}
            for alert in detections
        )
    finally:
        app.shutdown()
