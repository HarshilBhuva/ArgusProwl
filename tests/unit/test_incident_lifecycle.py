"""Tests for IncidentService lifecycle state machine."""

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.incident.incident_service import IncidentService
from argusprowl.models.alert import Alert
from argusprowl.models.incident import IncidentStatus


def _alert(host: str = "host1") -> Alert:
    return Alert(
        title="Test Alert",
        description="Test Description",
        severity=Severity.HIGH,
        source="test",
        entity_context={"host": host} if host else None,
    )


@pytest.fixture
def service() -> IncidentService:
    return IncidentService(max_incidents=100)


def test_lifecycle_open_to_investigating(service: IncidentService) -> None:
    """Legal: OPEN -> INVESTIGATING"""
    incident = service.create_incident([_alert()])
    updated = service.update_status(incident.incident_id, IncidentStatus.INVESTIGATING)
    assert updated.status == IncidentStatus.INVESTIGATING


def test_lifecycle_investigating_to_resolved(service: IncidentService) -> None:
    """Legal: INVESTIGATING -> RESOLVED"""
    incident = service.create_incident([_alert()])
    service.update_status(incident.incident_id, IncidentStatus.INVESTIGATING)
    updated = service.update_status(incident.incident_id, IncidentStatus.RESOLVED)
    assert updated.status == IncidentStatus.RESOLVED


def test_lifecycle_resolved_to_closed(service: IncidentService) -> None:
    """Legal: RESOLVED -> CLOSED"""
    incident = service.create_incident([_alert()])
    service.update_status(incident.incident_id, IncidentStatus.INVESTIGATING)
    service.update_status(incident.incident_id, IncidentStatus.RESOLVED)
    updated = service.update_status(incident.incident_id, IncidentStatus.CLOSED)
    assert updated.status == IncidentStatus.CLOSED


def test_lifecycle_reject_open_to_resolved(service: IncidentService) -> None:
    """Illegal: OPEN -> RESOLVED"""
    incident = service.create_incident([_alert()])
    with pytest.raises(ValueError, match="Invalid transition: open -> resolved"):
        service.update_status(incident.incident_id, IncidentStatus.RESOLVED)


def test_lifecycle_reject_open_to_closed(service: IncidentService) -> None:
    """Illegal: OPEN -> CLOSED"""
    incident = service.create_incident([_alert()])
    with pytest.raises(ValueError, match="Invalid transition: open -> closed"):
        service.update_status(incident.incident_id, IncidentStatus.CLOSED)


def test_lifecycle_reject_resolved_to_investigating(service: IncidentService) -> None:
    """Illegal: RESOLVED -> INVESTIGATING"""
    incident = service.create_incident([_alert()])
    service.update_status(incident.incident_id, IncidentStatus.INVESTIGATING)
    service.update_status(incident.incident_id, IncidentStatus.RESOLVED)
    with pytest.raises(ValueError, match="Invalid transition: resolved -> investigating"):
        service.update_status(incident.incident_id, IncidentStatus.INVESTIGATING)


def test_lifecycle_reject_closed_to_any(service: IncidentService) -> None:
    """Illegal: CLOSED -> anything"""
    incident = service.create_incident([_alert()])
    # Force to closed via legal path
    service.update_status(incident.incident_id, IncidentStatus.INVESTIGATING)
    service.update_status(incident.incident_id, IncidentStatus.RESOLVED)
    service.update_status(incident.incident_id, IncidentStatus.CLOSED)

    with pytest.raises(ValueError, match="Cannot change status of a CLOSED incident"):
        service.update_status(incident.incident_id, IncidentStatus.OPEN)
