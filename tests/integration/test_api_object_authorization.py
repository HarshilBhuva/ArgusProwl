"""Integration tests for owner-scoped alerts, incidents, and telemetry evidence."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

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
    # The current timeline implementation aggregates all telemetry for a host;
    # until it can apply owner filters before aggregation, non-admin access is denied.
    assert client.get(
        f"/api/v1/incidents/{incident.incident_id}/timeline",
        headers=_headers(ALICE_KEY),
    ).status_code == 403
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


def test_attck_investigation_filters_alerts_by_owner(tmp_path) -> None:
    client = _client(tmp_path)
    queue = ServiceContainer.get_instance().resolve(AlertQueue)
    alert = Alert(
        title="Alice ATT&CK alert",
        description="Owner-scoped investigation source",
        severity=Severity.HIGH,
        source="test",
        metadata={
            "owner_subject": "alice",
            "attck_observations": [
                {
                    "technique_id": "T1059",
                    "mapping_type": "DIRECT",
                    "version": "14.1",
                    "technique_name": "Command and Scripting Interpreter",
                    "tactic": "Execution",
                    "rationale": "Observed command execution",
                }
            ],
        },
    )
    queue.enqueue(alert)
    path = f"/api/v1/attck/investigation?alert_ids={alert.alert_id}"

    alice = client.get(path, headers=_headers(ALICE_KEY))
    assert alice.status_code == 200
    assert alice.json()["alert_count"] == 1

    # An inaccessible alert is indistinguishable from a missing alert.
    assert client.get(path, headers=_headers(BOB_KEY)).status_code == 404
    assert client.get(path, headers=_headers(ADMIN_KEY)).status_code == 200
    ServiceContainer.reset_instance()


def test_alert_and_evidence_provenance_hide_foreign_event_references(tmp_path) -> None:
    client = _client(tmp_path)
    container = ServiceContainer.get_instance()
    queue = container.resolve(AlertQueue)
    evidence = container.resolve(TelemetryEvidenceService)

    source_event = NormalizedEvent(
        source_type="test",
        event_type="process_start",
        metadata={"owner_subject": "alice"},
    )
    alice_contributor = NormalizedEvent(
        source_type="test",
        event_type="network_connection",
        metadata={"owner_subject": "alice"},
    )
    bob_contributor = NormalizedEvent(
        source_type="test",
        event_type="network_connection",
        metadata={"owner_subject": "bob"},
    )
    for event in (source_event, alice_contributor, bob_contributor):
        evidence.record_event(event)

    detection_result_id = uuid4()
    evidence.record_provenance(
        event_id=source_event.event_id,
        provenance="DETECTION_SOURCE",
        detection_result_id=detection_result_id,
        contributing_event_ids=(bob_contributor.event_id, alice_contributor.event_id),
    )
    alert = Alert(
        title="Alice correlated alert",
        description="Alert with mixed-owner provenance references",
        severity=Severity.HIGH,
        source="test",
        metadata={
            "owner_subject": "alice",
            "event_id": str(source_event.event_id),
        },
        detection_source_event_id=source_event.event_id,
        contributing_event_ids=(bob_contributor.event_id, alice_contributor.event_id),
    )
    queue.enqueue(alert)

    alice_alert = client.get(
        f"/api/v1/alerts/{alert.alert_id}", headers=_headers(ALICE_KEY)
    )
    assert alice_alert.status_code == 200
    alert_data = alice_alert.json()
    assert alert_data["detection_source_event_id"] == str(source_event.event_id)
    assert alert_data["metadata"]["event_id"] == str(source_event.event_id)
    assert alert_data["contributing_event_ids"] == [str(alice_contributor.event_id)]
    assert set(alert_data["contributing_event_status"]) == {
        str(alice_contributor.event_id)
    }

    alice_detail = client.get(
        f"/api/v1/evidence/{source_event.event_id}", headers=_headers(ALICE_KEY)
    )
    assert alice_detail.status_code == 200
    assert alice_detail.json()["record"]["contributing_event_ids"] == [
        str(alice_contributor.event_id)
    ]

    alice_search = client.get(
        f"/api/v1/evidence?event_id={source_event.event_id}",
        headers=_headers(ALICE_KEY),
    )
    assert alice_search.status_code == 200
    assert alice_search.json()["records"][0]["contributing_event_ids"] == [
        str(alice_contributor.event_id)
    ]

    admin_alert = client.get(
        f"/api/v1/alerts/{alert.alert_id}", headers=_headers(ADMIN_KEY)
    )
    assert admin_alert.status_code == 200
    assert set(admin_alert.json()["contributing_event_ids"]) == {
        str(alice_contributor.event_id),
        str(bob_contributor.event_id),
    }
    ServiceContainer.reset_instance()
