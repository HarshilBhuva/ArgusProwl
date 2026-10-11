"""Tests for dataclass models."""

from uuid import UUID

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.models.alert import Alert
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.event import Event
from argusprowl.models.system_status import ComponentHealth, HealthStatus, SystemStatus


def test_alert_model():
    alert = Alert(
        title="Suspicious Process",
        description="cmd.exe spawned by powershell",
        severity=Severity.HIGH,
        source="process_monitor",
    )
    assert isinstance(alert.alert_id, UUID)
    assert alert.title == "Suspicious Process"
    assert alert.severity == Severity.HIGH
    assert alert.schema_version == 2


def test_alert_validation():
    with pytest.raises(ValueError, match="title must not be empty"):
        Alert(title="   ", description="desc", severity=Severity.LOW, source="src")


def test_event_model():
    event = Event(source="syslog", event_type="login", raw_data="raw syslog line")
    assert isinstance(event.event_id, UUID)
    assert event.source == "syslog"


def test_detection_result_model():
    res = DetectionResult(
        rule_id="RULE-001",
        event_id=Event(source="s", event_type="e", raw_data="r").event_id,
        matched=True,
        confidence=0.95,
    )
    assert res.matched is True
    assert res.confidence == 0.95
    assert isinstance(res.detection_id, UUID)
    assert res.schema_version == 1


def test_detection_result_validation():
    event = Event(source="s", event_type="e", raw_data="r")
    with pytest.raises(ValueError, match="Confidence must be between"):
        DetectionResult(rule_id="R1", event_id=event.event_id, matched=True, confidence=1.5)


def test_system_status_model():
    comp = ComponentHealth(name="config", status=HealthStatus.HEALTHY, message="OK")
    status = SystemStatus(
        status=HealthStatus.HEALTHY,
        version="0.1.0",
        uptime_seconds=10.5,
        components=(comp,),
    )
    assert status.status == HealthStatus.HEALTHY
    assert len(status.components) == 1
