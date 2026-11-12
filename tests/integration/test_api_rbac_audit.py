"""Integration coverage for API RBAC and durable audit records."""

from __future__ import annotations

import sqlite3
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.api.audit import AuditLog
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.services.alert_search_service import AlertSearchService


def _build_client(
    tmp_path, role: str, key_options: dict[str, object] | None = None
) -> tuple[TestClient, str]:
    ServiceContainer.reset_instance()
    service = MagicMock(spec=AlertSearchService)
    result = MagicMock()
    result.alerts = []
    result.status = MagicMock()
    result.status.value = "AVAILABLE"
    result.reason = None
    service.search.return_value = result
    ServiceContainer.get_instance().register_singleton(AlertSearchService, lambda: service)

    secret = f"{role}-test-secret-that-is-at-least-32-characters"
    audit_path = tmp_path / f"{role}-audit.db"
    definition: dict[str, object] = {
        "secret": secret,
        "subject": f"{role}-operator",
        "role": role,
    }
    definition.update(key_options or {})
    app = create_api_app(
        auth_enabled=True,
        api_keys={f"{role}-key": definition},
        audit_db_path=str(audit_path),
    )
    return TestClient(app), str(audit_path)


def test_viewer_can_read_but_cannot_write(tmp_path) -> None:
    client, _ = _build_client(tmp_path, "viewer")
    headers = {"X-ArgusProwl-Key": "viewer-test-secret-that-is-at-least-32-characters"}
    assert client.get("/api/v1/alerts", headers=headers).status_code == 200
    denied = client.post(
        "/api/v1/entities/host/server-01/annotations",
        json={},
        headers=headers,
    )
    assert denied.status_code == 403
    assert client.get("/api/v1/audit/integrity", headers=headers).status_code == 403
    ServiceContainer.reset_instance()


def test_analyst_can_reach_investigation_write_routes_but_not_audit_reader(tmp_path) -> None:
    client, _ = _build_client(tmp_path, "analyst")
    headers = {"X-ArgusProwl-Key": "analyst-test-secret-that-is-at-least-32-characters"}
    allowed = client.post(
        "/api/v1/entities/host/server-01/annotations",
        json={},
        headers=headers,
    )
    assert allowed.status_code != 403
    assert client.get("/api/v1/audit", headers=headers).status_code == 403
    assert client.get("/api/v1/audit/integrity", headers=headers).status_code == 403
    ServiceContainer.reset_instance()


def test_admin_can_read_persisted_audit_events(tmp_path) -> None:
    client, audit_path = _build_client(tmp_path, "admin")
    headers = {"X-ArgusProwl-Key": "admin-test-secret-that-is-at-least-32-characters"}
    response = client.get("/api/v1/alerts?limit=1", headers=headers)
    assert response.status_code == 200
    events = AuditLog(audit_path).list_events(limit=10)
    assert any(
        event["event_type"] == "REQUEST_COMPLETED"
        and event["actor_id"] == "admin-operator"
        and event["role"] == "admin"
        and event["path"] == "/api/v1/alerts"
        for event in events
    )
    reader = client.get("/api/v1/audit", headers=headers)
    assert reader.status_code == 200
    assert reader.json()["total_count"] >= 3
    integrity = client.get("/api/v1/audit/integrity", headers=headers)
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is True
    ServiceContainer.reset_instance()


def test_failed_authentication_is_audited_without_recording_credentials(tmp_path) -> None:
    client, audit_path = _build_client(tmp_path, "viewer")
    response = client.get(
        "/api/v1/alerts",
        headers={"X-ArgusProwl-Key": "incorrect-secret-value"},
    )
    assert response.status_code == 401
    events = AuditLog(audit_path).list_events(limit=10)
    failure = next(event for event in events if event["event_type"] == "AUTHENTICATION_FAILED")
    assert failure["actor_id"] == "anonymous"
    assert "incorrect-secret-value" not in str(failure)
    ServiceContainer.reset_instance()


def test_non_ascii_api_key_header_is_rejected_without_server_error(tmp_path) -> None:
    client, _ = _build_client(tmp_path, "viewer")
    response = client.get(
        "/api/v1/alerts",
        headers=[(b"X-ArgusProwl-Key", b"\xe9" * 40)],
    )
    assert response.status_code == 401
    ServiceContainer.reset_instance()


def test_audit_hash_chain_detects_event_tampering(tmp_path) -> None:
    audit_path = str(tmp_path / "audit.db")
    audit = AuditLog(audit_path)
    first_id = audit.append(
        event_type="REQUEST_STARTED", actor_id="operator", role="admin",
        method="GET", path="/api/v1/alerts", status_code=0,
        request_id="request-1", client_ip="127.0.0.1",
    )
    audit.append(
        event_type="REQUEST_COMPLETED", actor_id="operator", role="admin",
        method="GET", path="/api/v1/alerts", status_code=200,
        request_id="request-1", client_ip="127.0.0.1",
    )
    assert audit.verify_integrity() == {
        "valid": True, "checked_count": 2, "first_invalid_id": None
    }

    with sqlite3.connect(audit_path) as connection:
        connection.execute(
            "UPDATE api_audit_events SET path = ? WHERE id = ?",
            ("/api/v1/modified", first_id),
        )

    result = audit.verify_integrity()
    assert result["valid"] is False
    assert result["first_invalid_id"] == first_id


def test_legacy_audit_database_is_backfilled_without_losing_events(tmp_path) -> None:
    audit_path = str(tmp_path / "legacy-audit.db")
    with sqlite3.connect(audit_path) as connection:
        connection.execute(
            """
            CREATE TABLE api_audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                role TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                request_id TEXT NOT NULL,
                client_ip TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO api_audit_events (
                timestamp, event_type, actor_id, role, method, path,
                status_code, request_id, client_ip
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "2026-11-03T00:00:00+00:00", "REQUEST_COMPLETED", "legacy",
                "admin", "GET", "/api/v1/alerts", 200, "legacy-request", None,
            ),
        )

    audit = AuditLog(audit_path)
    assert audit.count_events() == 1
    assert audit.verify_integrity() == {
        "valid": True, "checked_count": 1, "first_invalid_id": None
    }
    assert audit.list_events(limit=1)[0]["actor_id"] == "legacy"



def test_concurrent_audit_writers_preserve_a_single_chain(tmp_path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    audit_path = str(tmp_path / "concurrent-audit.db")
    audit_logs = [AuditLog(audit_path) for _ in range(4)]

    def append_event(index: int) -> int:
        audit = audit_logs[index % len(audit_logs)]
        return audit.append(
            event_type="REQUEST_COMPLETED",
            actor_id=f"operator-{index}",
            role="admin",
            method="GET",
            path="/api/v1/alerts",
            status_code=200,
            request_id=f"request-{index}",
            client_ip="127.0.0.1",
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        event_ids = list(executor.map(append_event, range(32)))

    assert len(set(event_ids)) == 32
    assert audit_logs[0].count_events() == 32
    assert audit_logs[0].verify_integrity() == {
        "valid": True,
        "checked_count": 32,
        "first_invalid_id": None,
    }


def test_disabled_named_api_key_is_rejected(tmp_path) -> None:
    client, _ = _build_client(tmp_path, "viewer", {"enabled": False})
    response = client.get(
        "/api/v1/alerts",
        headers={"X-ArgusProwl-Key": "viewer-test-secret-that-is-at-least-32-characters"},
    )
    assert response.status_code == 401
    ServiceContainer.reset_instance()


def test_expired_named_api_key_is_rejected(tmp_path) -> None:
    client, _ = _build_client(
        tmp_path, "viewer", {"expires_at": "2000-01-01T00:00:00Z"}
    )
    response = client.get(
        "/api/v1/alerts",
        headers={"X-ArgusProwl-Key": "viewer-test-secret-that-is-at-least-32-characters"},
    )
    assert response.status_code == 401
    ServiceContainer.reset_instance()


def test_unexpired_named_api_key_is_accepted(tmp_path) -> None:
    client, _ = _build_client(
        tmp_path, "viewer", {"expires_at": "2999-01-01T00:00:00Z"}
    )
    response = client.get(
        "/api/v1/alerts",
        headers={"X-ArgusProwl-Key": "viewer-test-secret-that-is-at-least-32-characters"},
    )
    assert response.status_code == 200
    ServiceContainer.reset_instance()


def test_admin_revocation_persists_and_invalidates_browser_sessions(tmp_path) -> None:
    ServiceContainer.reset_instance()
    service = MagicMock(spec=AlertSearchService)
    result = MagicMock()
    result.alerts = []
    result.status = MagicMock()
    result.status.value = "AVAILABLE"
    result.reason = None
    service.search.return_value = result
    ServiceContainer.get_instance().register_singleton(AlertSearchService, lambda: service)
    audit_path = str(tmp_path / "shared-auth.db")
    keys = {
        "admin-key": {
            "secret": "admin-key-secret-with-at-least-32-characters",
            "subject": "security-admin",
            "role": "admin",
        },
        "viewer-key": {
            "secret": "viewer-key-secret-with-at-least-32-characters",
            "subject": "read-only-operator",
            "role": "viewer",
        },
    }
    app = create_api_app(
        auth_enabled=True,
        api_keys=keys,
        audit_db_path=audit_path,
    )
    admin_client = TestClient(app)
    viewer_client = TestClient(app)
    admin_headers = {
        "X-ArgusProwl-Key": "admin-key-secret-with-at-least-32-characters"
    }
    viewer_headers = {
        "X-ArgusProwl-Key": "viewer-key-secret-with-at-least-32-characters"
    }

    login = viewer_client.post(
        "/api/v1/auth/session",
        json={"api_key": viewer_headers["X-ArgusProwl-Key"]},
        headers={"Origin": "http://testserver"},
    )
    assert login.status_code == 200
    assert viewer_client.get("/api/v1/alerts").status_code == 200

    revoked = admin_client.post(
        "/api/v1/auth/keys/viewer-key/revoke",
        headers=admin_headers,
    )
    assert revoked.status_code == 200
    assert revoked.json() == {"revoked": True, "key_id": "viewer-key"}

    assert viewer_client.get("/api/v1/alerts").status_code == 401
    assert viewer_client.get("/api/v1/alerts", headers=viewer_headers).status_code == 401

    restarted_app = create_api_app(
        auth_enabled=True,
        api_keys=keys,
        audit_db_path=audit_path,
    )
    restarted_client = TestClient(restarted_app)
    assert restarted_client.get("/api/v1/alerts", headers=viewer_headers).status_code == 401
    ServiceContainer.reset_instance()


def test_auth_session_endpoint_rate_limits_failed_logins(tmp_path) -> None:
    ServiceContainer.reset_instance()
    client = TestClient(
        create_api_app(
            auth_enabled=True,
            api_keys={
                "admin-key": {
                    "secret": "admin-key-secret-with-at-least-32-characters",
                    "subject": "security-admin",
                    "role": "admin",
                }
            },
            audit_db_path=str(tmp_path / "rate-limit.db"),
        )
    )
    statuses = [
        client.post(
            "/api/v1/auth/session",
            json={"api_key": "incorrect-key"},
            headers={"Origin": "http://testserver"},
        ).status_code
        for _ in range(10)
    ]
    assert statuses[:9] == [401] * 9
    assert statuses[9] == 429
    blocked = client.post(
        "/api/v1/auth/session",
        json={"api_key": "admin-key-secret-with-at-least-32-characters"},
        headers={"Origin": "http://testserver"},
    )
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0
    ServiceContainer.reset_instance()



def test_viewer_and_analyst_deny_unknown_read_routes_by_default(tmp_path) -> None:
    for role in ("viewer", "analyst"):
        client, _ = _build_client(tmp_path, role)
        headers = {
            "X-ArgusProwl-Key": f"{role}-test-secret-that-is-at-least-32-characters"
        }
        assert client.get("/api/v1/alerts", headers=headers).status_code == 200
        denied = client.get("/api/v1/internal/undocumented-resource", headers=headers)
        assert denied.status_code == 403
        ServiceContainer.reset_instance()
