"""Integration tests for owner-scoped alerts, incidents, and telemetry evidence."""

from __future__ import annotations

from datetime import UTC, datetime
from fastapi.testclient import TestClient

from argusprowl.alerting.alert_manager import AlertManager
from argusprowl.api.app import create_api_app
from argusprowl.constants.severity import Severity
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.incident.incident_service import IncidentService
from argusprowl.lifecycle.queue import AlertQueue
from argusprowl.models.alert import Alert
from argusprowl.models.incident import Incident, IncidentStatus
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService


ALICE_KEY = "alice-test-key-with-more-than-thirty-two-characters"
BOB_KEY = "bob-test-key-with-more-than-thirty-two-characters"
ADMIN_KEY = "admin-test-key-with-more-than-thirty-two-characters"


def _client(tmp_path) -> TestClient:
    ServiceContainer.reset_instance()
    container = ServiceContainer.get_instance()
    queue = AlertQueue(max_size=100)
    container.register_singleton(AlertQueue, lambda: queue)
    container.register_singleton(AlertManager, lambda: AlertManager(alert_queue=queue))
    container.register_singleton(IncidentService, lambda: IncidentService(max_incidents=100))
    container.register_singleton(
        TelemetryEvidenceService, lambda: TelemetryEvidenceService(max_retained_events=100)
    )

    app = create_api_app(
        auth_enabled=True,
        audit_db_path=str(tmp_path / "object-auth-audit.db"),
        api_keys={
            "alice": {"secret": ALICE_KEY, "subject": "alice", "role": "analyst"},
            "bob": {"secret": BOB_KEY, "subject": "bob", "role": "analyst"},
            "admin": {"secret": ADMIN_KEY, "subject": "platform-admin", "role": "admin"},
        },
    )
    return TestClient(app)


def _headers(key: str) -> dict[str, str]:
    return {"X-ArgusProwl-Key": key}


def test_alert_detail_and_lifecycle_are_owner_scoped(tmp_path) -> None:
    client = _client(tmp_path)
    container = ServiceContainer.get_instance()
    queue = container.resolve(AlertQueue)
    alert = Alert(
        title="Alice alert",
        description="Scoped alert",
        severity=Severity.HIGH,
        source="test",
        metadata={"owner_subject": "alice"},
    )
    queue.enqueue(alert)

    assert client.get(f"/api/v1/alerts/{alert.alert_id}", headers=_headers(ALICE_KEY)).status_code == 200
    assert client.get(f"/api/v1/alerts/{alert.alert_id}", headers=_headers(BOB_KEY)).status_code == 404
    assert client.get(f"/api/v1/alerts/{alert.alert_id}", headers=_headers(ADMIN_KEY)).status_code == 200

    denied = client.post(
        f"/api/v1/alerts/{alert.alert_id}/close", headers=_headers(BOB_KEY)
    )
    assert denied.status_code == 404
    assert queue.get(alert.alert_id).lifecycle_state.value == "OPEN"

    allowed = client.post(
        f"/api/v1/alerts/{alert.alert_id}/close", headers=_headers(ALICE_KEY)
    )
    assert allowed.status_code == 200
    assert allowed.json()["current_state"] == "CLOSED"
    ServiceContainer.reset_instance()


def test_incident_list_and_detail_are_owner_scoped(tmp_path) -> None:
    client = _client(tmp_path)
    service = ServiceContainer.get_instance().resolve(IncidentService)
    incident = Incident(
        title="Alice case",
        description="Scoped case",
        severity=Severity.MEDIUM,
        status=IncidentStatus.OPEN,
        assigned_analyst="alice",
    )
    # The service is the authoritative in-memory incident repository. Seed a
    # domain object with an explicit assignee, as an assignment workflow would.
    service._incidents[incident.incident_id] = incident

    alice_list = client.get("/api/v1/incidents", headers=_headers(ALICE_KEY))
    bob_list = client.get("/api/v1/incidents", headers=_headers(BOB_KEY))
    assert alice_list.status_code == 200
    assert alice_list.json()["total_count"] == 1
    assert bob_list.status_code == 200
    assert bob_list.json()["total_count"] == 0

    assert client.get(
        f"/api/v1/incidents/{incident.incident_id}", headers=_headers(ALICE_KEY)
    ).status_code == 200
    assert client.get(
        f"/api/v1/incidents/{incident.incident_id}", headers=_headers(BOB_KEY)
    ).status_code == 404
    assert client.get(
        f"/api/v1/incidents/{incident.incident_id}", headers=_headers(ADMIN_KEY)
    ).status_code == 200
    ServiceContainer.reset_instance()


def test_evidence_detail_requires_explicit_event_owner(tmp_path) -> None:
    client = _client(tmp_path)
    service = ServiceContainer.get_instance().resolve(TelemetryEvidenceService)
    event = NormalizedEvent(
        source_type="test",
        event_type="process_start",
        timestamp=datetime.now(UTC),
        hostname="workstation-01",
        metadata={"owner_subject": "alice"},
    )
    service.record_event(event)

    assert client.get(
        f"/api/v1/evidence/{event.event_id}", headers=_headers(ALICE_KEY)
    ).status_code == 200
    assert client.get(
        f"/api/v1/evidence/{event.event_id}", headers=_headers(BOB_KEY)
    ).status_code == 404
    assert client.get(
        f"/api/v1/evidence/{event.event_id}", headers=_headers(ADMIN_KEY)
    ).status_code == 200

    # A paginated global evidence query cannot safely filter ownership after
    # pagination; non-admin callers must use exact event IDs until the storage
    # layer supports owner-filtered keyset pagination.
    assert client.get("/api/v1/evidence", headers=_headers(ALICE_KEY)).status_code == 403
    ServiceContainer.reset_instance()


def test_unowned_legacy_alerts_and_evidence_are_hidden_from_analysts(tmp_path) -> None:
    client = _client(tmp_path)
    container = ServiceContainer.get_instance()
    queue = container.resolve(AlertQueue)
    alert = Alert(
        title="Legacy alert",
        description="No ownership metadata",
        severity=Severity.LOW,
        source="legacy",
    )
    queue.enqueue(alert)

    evidence = container.resolve(TelemetryEvidenceService)
    event = NormalizedEvent(source_type="legacy", event_type="observed")
    evidence.record_event(event)

    assert client.get(
        f"/api/v1/alerts/{alert.alert_id}", headers=_headers(ALICE_KEY)
    ).status_code == 404
    assert client.get(
        f"/api/v1/evidence/{event.event_id}", headers=_headers(ALICE_KEY)
    ).status_code == 404
    assert client.get(
        f"/api/v1/alerts/{alert.alert_id}", headers=_headers(ADMIN_KEY)
    ).status_code == 200
    ServiceContainer.reset_instance()
