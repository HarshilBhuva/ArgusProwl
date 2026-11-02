"""API integration tests for hunt persistence, request validation and RBAC."""
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.hunting.hunt_service import HuntService
from argusprowl.storage.sqlite_storage import SQLiteAdapter


def _client(tmp_path, role: str = "admin"):
    ServiceContainer.reset_instance()
    container = ServiceContainer.get_instance()
    storage = SQLiteAdapter(tmp_path / f"{role}-hunts.db")
    service = HuntService(storage)
    container.register_singleton(HuntService, lambda: service)
    secret = f"{role}-hunt-test-secret-with-at-least-32-characters"
    app = create_api_app(
        auth_enabled=True,
        api_keys={
            f"{role}-key": {
                "secret": secret,
                "subject": f"{role}-operator",
                "role": role,
            }
        },
        audit_db_path=str(tmp_path / f"{role}-audit.db"),
    )
    return TestClient(app), {"X-ArgusProwl-Key": secret}, service, storage


def test_analyst_can_create_and_update_hunt_and_request_is_audited(tmp_path) -> None:
    client, headers, service, storage = _client(tmp_path, "analyst")
    created = client.post(
        "/api/v1/hunts",
        json={
            "title": "Suspicious remote access",
            "hypothesis": "Credential abuse precedes lateral movement.",
        },
        headers=headers,
    )
    assert created.status_code == 200
    data = created.json()
    hunt_id = data["hunt_id"]
    assert data["created_by"] == "analyst-operator"
    assert data["status"] == "draft"
    assert data["audit_history"][0]["action"] == "HUNT_CREATED"

    scope = client.post(
        f"/api/v1/hunts/{hunt_id}/scope",
        json={"hosts": ["server-01"], "users": ["svc-admin"], "sources": ["windows"]},
        headers=headers,
    )
    assert scope.status_code == 200
    assert scope.json()["scope"]["hosts"] == ["server-01"]

    query = client.post(
        f"/api/v1/hunts/{hunt_id}/queries",
        json={"name": "failed-logons", "definition": {"event_type": "authentication_failure"}},
        headers=headers,
    )
    assert query.status_code == 200
    assert query.json()["queries"][0]["version"] == 1

    detail = client.get(f"/api/v1/hunts/{hunt_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["revision"] == 3

    listed = client.get("/api/v1/hunts?status=draft&limit=10", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["total_count"] == 1

    assert service.get_hunt(__import__("uuid").UUID(hunt_id)) is not None
    ServiceContainer.reset_instance()
    storage.close()


def test_viewer_can_read_but_cannot_create_hunt(tmp_path) -> None:
    client, headers, _service, storage = _client(tmp_path, "viewer")
    assert client.get("/api/v1/hunts", headers=headers).status_code == 200
    denied = client.post(
        "/api/v1/hunts",
        json={"title": "Blocked", "hypothesis": "Viewer must not mutate."},
        headers=headers,
    )
    assert denied.status_code == 403
    ServiceContainer.reset_instance()
    storage.close()


def test_invalid_hunt_scope_and_status_transitions_are_rejected(tmp_path) -> None:
    client, headers, _service, storage = _client(tmp_path)
    invalid = client.post(
        "/api/v1/hunts",
        json={"title": "", "hypothesis": "x"},
        headers=headers,
    )
    assert invalid.status_code == 422
    created = client.post(
        "/api/v1/hunts",
        json={"title": "Test hunt", "hypothesis": "Test hypothesis"},
        headers=headers,
    )
    hunt_id = created.json()["hunt_id"]
    invalid_scope = client.post(
        f"/api/v1/hunts/{hunt_id}/scope",
        json={"start_time": "2026-11-03T12:00:00+00:00", "end_time": "2026-11-02T12:00:00+00:00"},
        headers=headers,
    )
    assert invalid_scope.status_code == 422
    invalid_transition = client.post(
        f"/api/v1/hunts/{hunt_id}/status",
        json={"status": "completed"},
        headers=headers,
    )
    assert invalid_transition.status_code == 409
    ServiceContainer.reset_instance()
    storage.close()


def test_hunt_is_durable_across_service_recreation(tmp_path) -> None:
    client, headers, service, storage = _client(tmp_path)
    created = client.post(
        "/api/v1/hunts",
        json={"title": "Persistence", "hypothesis": "Survive process restart."},
        headers=headers,
    )
    hunt_id = created.json()["hunt_id"]
    recovered = HuntService(storage).get_hunt(__import__("uuid").UUID(hunt_id))
    assert recovered is not None
    assert recovered.title == "Persistence"
    ServiceContainer.reset_instance()
    storage.close()



def test_analyst_cannot_read_or_mutate_another_analysts_hunt(tmp_path) -> None:
    client, headers, service, storage = _client(tmp_path, "analyst")
    foreign = service.create_hunt(
        title="Private hunt",
        hypothesis="Owned by a different analyst.",
        actor="other-analyst",
    )
    assert client.get(f"/api/v1/hunts/{foreign.hunt_id}", headers=headers).status_code == 404
    denied = client.post(
        f"/api/v1/hunts/{foreign.hunt_id}/scope",
        json={"hosts": ["host-01"]},
        headers=headers,
    )
    assert denied.status_code == 404
    assert client.get("/api/v1/hunts", headers=headers).json()["total_count"] == 0
    ServiceContainer.reset_instance()
    storage.close()
