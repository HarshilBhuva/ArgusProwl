from uuid import UUID

from argusprowl.constants.severity import Severity
from argusprowl.models.incident import Incident, IncidentStatus


def test_incident_has_schema_uuid_and_safe_defaults() -> None:
    incident = Incident("Suspicious activity", "Investigation required", Severity.HIGH)
    assert isinstance(incident.incident_id, UUID)
    assert incident.schema_version == 1
    assert incident.status is IncidentStatus.OPEN
