"""Integration tests for HttpOnly browser sessions backed by API-key credentials."""

from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.api.audit import AuditLog


def _client(tmp_path, role: str = "viewer"):
    secret = f"{role}-browser-session-key-with-at-least-32-bytes"
    audit_path = tmp_path / "auth-session-audit.db"
    app = create_api_app(
        auth_enabled=True,
        api_keys={
            f"{role}-key": {
                "secret": secret,
                "subject": f"{role}-operator",
                "role": role,
            }
        },
        audit_db_path=str(audit_path),
    )
    return TestClient(app), secret, audit_path


def test_api_auth_status_is_public_and_reports_authentication_mode(tmp_path) -> None:
    client, _secret, _audit_path = _client(tmp_path)

    response = client.get("/api/v1/auth/status")

    assert response.status_code == 200
    assert response.json() == {"auth_enabled": True, "session_ttl_seconds": 3600}


def test_browser_login_issues_httponly_session_and_logout_clears_it(tmp_path) -> None:
    client, secret, audit_path = _client(tmp_path, "analyst")

    login = client.post("/api/v1/auth/session", json={"api_key": secret})

    assert login.status_code == 200
    assert login.json() == {
        "authenticated": True,
        "subject": "analyst-operator",
        "role": "analyst",
        "key_id": "analyst-key",
    }
    cookie_header = login.headers["set-cookie"]
    assert "HttpOnly" in cookie_header
    assert "SameSite=strict" in cookie_header
    assert "Path=/api" in cookie_header
    assert "Max-Age=3600" in cookie_header
    assert secret not in cookie_header

    current = client.get("/api/v1/auth/me")
    assert current.status_code == 200
    assert current.headers["cache-control"] == "no-store"
    assert current.json()["subject"] == "analyst-operator"
    assert current.json()["role"] == "analyst"

    logout = client.delete("/api/v1/auth/session")
    assert logout.status_code == 200
    assert logout.json() == {"authenticated": False}
    assert "Max-Age=0" in logout.headers["set-cookie"]
    assert client.get("/api/v1/auth/me").status_code == 401

    events = AuditLog(str(audit_path)).list_events(limit=50)
    event_types = {event["event_type"] for event in events}
    assert "AUTHENTICATION_SUCCEEDED" in event_types
    assert "SESSION_TERMINATED" in event_types
    assert secret not in str(events)



def test_logout_clears_cookie_even_if_audit_storage_fails(tmp_path, monkeypatch) -> None:
    client, secret, _audit_path = _client(tmp_path, "analyst")
    assert client.post("/api/v1/auth/session", json={"api_key": secret}).status_code == 200

    def fail_audit(**_kwargs):
        raise OSError("audit store unavailable")

    monkeypatch.setattr(client.app.state.audit_log, "append", fail_audit)
    logout = client.delete("/api/v1/auth/session")

    assert logout.status_code == 200
    assert "Max-Age=0" in logout.headers["set-cookie"]
    assert client.get("/api/v1/auth/me").status_code == 401


def test_invalid_browser_login_is_rejected_and_audited(tmp_path) -> None:
    client, _secret, audit_path = _client(tmp_path)

    response = client.post(
        "/api/v1/auth/session",
        json={"api_key": "not-the-configured-api-key"},
    )

    assert response.status_code == 401
    assert response.headers.get("set-cookie") is None
    events = AuditLog(str(audit_path)).list_events(limit=20)
    assert any(event["event_type"] == "AUTHENTICATION_FAILED" for event in events)
    assert "not-the-configured-api-key" not in str(events)


def test_browser_session_respects_role_authorization(tmp_path) -> None:
    client, secret, _audit_path = _client(tmp_path, "viewer")
    assert client.post("/api/v1/auth/session", json={"api_key": secret}).status_code == 200

    denied = client.post(
        "/api/v1/hunts",
        json={"title": "Not allowed", "hypothesis": "Viewer must not create hunts."},
    )

    assert denied.status_code == 403


def test_browser_session_rejects_cross_origin_state_changes(tmp_path) -> None:
    client, secret, _audit_path = _client(tmp_path, "analyst")
    assert client.post("/api/v1/auth/session", json={"api_key": secret}).status_code == 200

    denied = client.post(
        "/api/v1/hunts",
        json={"title": "CSRF attempt", "hypothesis": "Cross-origin mutation must fail."},
        headers={"Origin": "https://attacker.example"},
    )

    assert denied.status_code == 403



def test_browser_session_rejects_state_changes_without_origin(tmp_path) -> None:
    client, secret, _audit_path = _client(tmp_path, "analyst")
    assert client.post("/api/v1/auth/session", json={"api_key": secret}).status_code == 200

    denied = client.post(
        "/api/v1/hunts",
        json={"title": "Missing Origin", "hypothesis": "Cookie mutations require an origin."},
    )

    assert denied.status_code == 403

def test_rotating_api_key_invalidates_existing_browser_sessions(tmp_path) -> None:
    client, secret, _audit_path = _client(tmp_path, "analyst")
    assert client.post("/api/v1/auth/session", json={"api_key": secret}).status_code == 200
    service = client.app.state.auth_service
    principal, _old_secret, enabled, expires_at = service._credentials["analyst-key"]
    service._credentials["analyst-key"] = (
        principal,
        "rotated-api-key-secret-is-now-different-000000",
        enabled,
        expires_at,
    )

    assert client.get("/api/v1/auth/me").status_code == 401



def test_public_health_is_minimal_and_detailed_health_requires_auth(tmp_path) -> None:
    client, secret, _audit_path = _client(tmp_path, "viewer")

    public = client.get("/api/v1/health")
    assert public.status_code == 200
    assert public.json()["components"] == []
    assert client.get("/health").status_code == 200
    assert client.get("/api/v1/health/details").status_code == 401

    assert client.post("/api/v1/auth/session", json={"api_key": secret}).status_code == 200
    detailed = client.get("/api/v1/health/details")
    assert detailed.status_code == 200
    assert "components" in detailed.json()

def test_auth_disabled_status_does_not_require_browser_login(tmp_path) -> None:
    app = create_api_app(auth_enabled=False, audit_db_path=str(tmp_path / "audit.db"))
    client = TestClient(app)

    status = client.get("/api/v1/auth/status")

    assert status.status_code == 200
    assert status.json()["auth_enabled"] is False
