"""Tests for shared-secret API key authentication.

Verifies:
- Auth-enabled mode rejects requests without a key
- Auth-enabled mode rejects wrong keys
- Auth-enabled mode allows correct key
- Auth-disabled mode allows all requests (no key needed)
- Health and public endpoints remain accessible regardless of auth setting
- Environment variable fallback when api_key config is empty
- Fail-closed behavior when auth is enabled but no key is configured anywhere
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.api.auth import ApiKeyAuthMiddleware
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.services.alert_search_service import AlertSearchService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_container():
    """Ensure container is clean before and after each test."""
    ServiceContainer.reset_instance()
    yield
    ServiceContainer.reset_instance()


@pytest.fixture
def mock_alert_search_service() -> MagicMock:
    """Create a mock alert search service for route-level tests."""
    service = MagicMock(spec=AlertSearchService)
    search_result = MagicMock()
    search_result.alerts = []
    search_result.status = MagicMock()
    search_result.status.value = "AVAILABLE"
    search_result.reason = None
    service.search.return_value = search_result
    return service


def _make_auth_app(
    *,
    auth_enabled: bool,
    api_key: str,
    header_name: str = "X-ArgusProwl-Key",
    mock_service: MagicMock | None = None,
) -> TestClient:
    """Build a TestClient with optional auth middleware applied."""
    container = ServiceContainer.get_instance()
    if mock_service is not None:
        container.register_singleton(AlertSearchService, lambda: mock_service)
    app = create_api_app(
        auth_enabled=auth_enabled,
        api_key=api_key,
        auth_header_name=header_name,
    )
    # Apply middleware only when auth is enabled (create_api_app doesn't auto-add it
    # since the factory signature hasn't changed yet — we add it here in tests).
    if auth_enabled:
        app.add_middleware(
            ApiKeyAuthMiddleware,
            auth_enabled=True,
            api_key=api_key,
            auth_header_name=header_name,
        )
    return TestClient(app)


@pytest.fixture
def auth_enabled_app(mock_alert_search_service: MagicMock) -> TestClient:
    """App with auth enabled and a known key."""
    return _make_auth_app(
        auth_enabled=True,
        api_key="secret123",
        mock_service=mock_alert_search_service,
    )


@pytest.fixture
def auth_disabled_app(mock_alert_search_service: MagicMock) -> TestClient:
    """App with auth disabled (default)."""
    return _make_auth_app(
        auth_enabled=False,
        api_key="",
        mock_service=mock_alert_search_service,
    )


@pytest.fixture
def fail_closed_app() -> TestClient:
    """App with auth enabled but no key configured anywhere."""
    env_before = os.environ.pop("ARGUSPROWL_API_KEY", None)
    try:
        app = create_api_app(auth_enabled=True, api_key="", auth_header_name="X-ArgusProwl-Key")
        app.add_middleware(
            ApiKeyAuthMiddleware,
            auth_enabled=True,
            api_key="",
            auth_header_name="X-ArgusProwl-Key",
        )
        return TestClient(app)
    finally:
        if env_before is not None:
            os.environ["ARGUSPROWL_API_KEY"] = env_before


@pytest.fixture
def env_var_fallback_app(mock_alert_search_service: MagicMock) -> TestClient:
    """App with api_key="" in config but key present in env var."""
    env_before = os.environ.get("ARGUSPROWL_API_KEY")
    os.environ["ARGUSPROWL_API_KEY"] = "envsecret"
    try:
        container = ServiceContainer.get_instance()
        container.register_singleton(AlertSearchService, lambda: mock_alert_search_service)
        # create_api_app() adds ApiKeyAuthMiddleware internally when
        # auth_enabled=True; the middleware resolves the key lazily at
        # dispatch time via _resolve_key(), so the env var must remain
        # set for the duration of the test.
        app = create_api_app(
            auth_enabled=True,
            api_key="",  # config has no key — env var provides it
            auth_header_name="X-ArgusProwl-Key",
        )
        yield TestClient(app)
    finally:
        if env_before is None:
            os.environ.pop("ARGUSPROWL_API_KEY", None)
        else:
            os.environ["ARGUSPROWL_API_KEY"] = env_before


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAuthEnabledRejectsUnauthenticated:
    """When auth is enabled, unauthenticated requests must be rejected."""

    def test_unauthenticated_request_rejected_when_auth_enabled(
        self, auth_enabled_app: TestClient
    ) -> None:
        """GET /api/v1/alerts without header returns 401."""
        response = auth_enabled_app.get("/api/v1/alerts")
        assert response.status_code == 401
        assert response.json()["detail"] == "Unauthorized"

    def test_wrong_key_rejected(self, auth_enabled_app: TestClient) -> None:
        """GET /api/v1/alerts with wrong key returns 401."""
        response = auth_enabled_app.get(
            "/api/v1/alerts", headers={"X-ArgusProwl-Key": "wrongkey"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Unauthorized"

    def test_valid_key_allowed(self, auth_enabled_app: TestClient) -> None:
        """GET /api/v1/alerts with correct key returns 200."""
        response = auth_enabled_app.get(
            "/api/v1/alerts", headers={"X-ArgusProwl-Key": "secret123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert "total_count" in data


class TestAuthDisabledAllowsAll:
    """When auth is disabled, all requests go through regardless of header."""

    def test_auth_disabled_allows_no_key(self, auth_disabled_app: TestClient) -> None:
        """GET /api/v1/alerts with no header and auth disabled returns 200."""
        response = auth_disabled_app.get("/api/v1/alerts")
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert "total_count" in data

    def test_auth_disabled_ignores_header(self, auth_disabled_app: TestClient) -> None:
        """GET /api/v1/alerts with arbitrary header still returns 200 when auth disabled."""
        response = auth_disabled_app.get(
            "/api/v1/alerts", headers={"X-ArgusProwl-Key": "garbage"}
        )
        assert response.status_code == 200


class TestPublicEndpoints:
    """Public endpoints are always accessible, even with auth enabled."""

    def test_health_endpoint_public(self, auth_enabled_app: TestClient) -> None:
        """GET /health returns 200 even without key when auth is enabled."""
        response = auth_enabled_app.get("/health")
        assert response.status_code == 200

    def test_api_v1_health_public(self, auth_enabled_app: TestClient) -> None:
        """GET /api/v1/health returns 200 even without key when auth is enabled."""
        response = auth_enabled_app.get("/api/v1/health")
        assert response.status_code == 200

    def test_openapi_public(self, auth_enabled_app: TestClient) -> None:
        """GET /openapi.json is accessible without auth."""
        response = auth_enabled_app.get("/openapi.json")
        assert response.status_code == 200

    def test_docs_public(self, auth_enabled_app: TestClient) -> None:
        """GET /docs is accessible without auth."""
        response = auth_enabled_app.get("/docs")
        assert response.status_code == 200

    def test_redoc_public(self, auth_enabled_app: TestClient) -> None:
        """GET /redoc is accessible without auth."""
        response = auth_enabled_app.get("/redoc")
        assert response.status_code == 200


class TestEnvVarFallback:
    """Env var fallback: api_key config empty, but ARGUSPROWL_API_KEY set."""

    def test_env_var_fallback_accepts_env_key(self, env_var_fallback_app: TestClient) -> None:
        """Correct env var key grants access when config key is empty."""
        response = env_var_fallback_app.get(
            "/api/v1/alerts", headers={"X-ArgusProwl-Key": "envsecret"}
        )
        assert response.status_code == 200

    def test_env_var_fallback_rejects_wrong_key(self, env_var_fallback_app: TestClient) -> None:
        """Wrong key is still rejected even with env fallback."""
        response = env_var_fallback_app.get(
            "/api/v1/alerts", headers={"X-ArgusProwl-Key": "wrong"}
        )
        assert response.status_code == 401


class TestFailClosed:
    """When auth is enabled but no key exists anywhere, block everything."""

    def test_fail_closed_rejects_non_public(self, fail_closed_app: TestClient) -> None:
        """Non-public route returns 401 when no key is configured."""
        response = fail_closed_app.get("/api/v1/alerts")
        assert response.status_code == 401
        assert response.json()["detail"] == "Unauthorized"

    def test_fail_closed_allows_health(self, fail_closed_app: TestClient) -> None:
        """Health endpoint remains accessible even in fail-closed mode."""
        response = fail_closed_app.get("/health")
        assert response.status_code == 200

    def test_fail_closed_allows_api_v1_health(self, fail_closed_app: TestClient) -> None:
        """API health endpoint remains accessible even in fail-closed mode."""
        response = fail_closed_app.get("/api/v1/health")
        assert response.status_code == 200
