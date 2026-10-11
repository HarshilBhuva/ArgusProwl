"""Tests for frontend static-file serving and SPA fallback.

Covers:
- Static assets served from `static/` (mounted under /assets/)
- `/` serves index.html via FileResponse
- Catch-all `/{path:path}` returns index.html for unknown UI routes
- `/api/*` and `/docs` paths are NOT intercepted by the SPA fallback
- Graceful degradation when `static/` is absent (backend-only dev)
- Existing API routes (e.g. /health, /api/v1/*) continue to work
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import _static_dir, create_api_app
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.models.system_status import ComponentHealth, HealthStatus, SystemStatus
from argusprowl.services.health_service import HealthService


def _sample_health_status() -> SystemStatus:
    return SystemStatus(
        status=HealthStatus.HEALTHY,
        version="0.1.0",
        uptime_seconds=123.45,
        checked_at=datetime.now(UTC),
        components=(
            ComponentHealth(name="config", status=HealthStatus.HEALTHY, message="OK"),
            ComponentHealth(name="logging", status=HealthStatus.HEALTHY, message="OK"),
        ),
    )


def _register_mock_health_service() -> None:
    """Register a mocked HealthService so /health returns 200.

    Mirrors the api_client_with_services fixture in test_api.py: without a
    registered HealthService, the operational /health endpoint reports 503.
    """
    mock_health_service = MagicMock()
    mock_health_service.check_health.return_value = _sample_health_status()
    ServiceContainer.get_instance().register_singleton(HealthService, lambda: mock_health_service)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_static_fixture(tmp_path: Path) -> Path:
    """Write a minimal frontend-like static directory for testing."""
    static_dir = tmp_path / "static"
    assets_dir = static_dir / "assets"
    assets_dir.mkdir(parents=True)
    (static_dir / "index.html").write_text("<html><body>hello</body></html>")
    (assets_dir / "app.js").write_text("console.log('hello');")
    (assets_dir / "app.css").write_text("body { color: red; }")
    return static_dir


@pytest.fixture
def static_dir(tmp_path):
    return _write_static_fixture(tmp_path)


@pytest.fixture
def client_with_static(static_dir):
    """FastAPI app with static/ present."""
    _register_mock_health_service()
    with patch("argusprowl.api.app._static_dir", return_value=str(static_dir)):
        return TestClient(create_api_app())


@pytest.fixture
def client_without_static(tmp_path):
    """FastAPI app with static/ absent."""
    _register_mock_health_service()
    bogus = tmp_path / "no-static"
    with patch("argusprowl.api.app._static_dir", return_value=str(bogus)):
        return TestClient(create_api_app())


# ---------------------------------------------------------------------------
# Asset serving
# ---------------------------------------------------------------------------


def test_assets_js_served(client_with_static):
    resp = client_with_static.get("/assets/app.js")
    assert resp.status_code == 200
    assert "javascript" in resp.headers["content-type"]
    assert "console.log" in resp.text


def test_assets_css_served(client_with_static):
    resp = client_with_static.get("/assets/app.css")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/css")
    assert "body { color: red; }" in resp.text


def test_assets_missing_404(client_with_static):
    resp = client_with_static.get("/assets/nonexistent.js")
    assert resp.status_code == 404


def test_assets_no_assets_dir(tmp_path):
    """If static/ exists but assets/ doesn't, mount is skipped — 404 from FastAPI."""
    minimal = tmp_path / "static" / "minimal"
    minimal.mkdir(parents=True)
    (minimal / "index.html").write_text("<html></html>")
    with patch("argusprowl.api.app._static_dir", return_value=str(minimal)):
        client = TestClient(create_api_app())
    resp = client.get("/assets/app.js")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Root and SPA fallback
# ---------------------------------------------------------------------------


def test_root_serves_index_html(client_with_static):
    resp = client_with_static.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "hello" in resp.text


def test_spa_fallback_serves_index(client_with_static):
    resp = client_with_static.get("/alerts/some-route")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "hello" in resp.text


def test_spa_fallback_missing_index_returns_404(tmp_path):
    """When static/ exists but index.html is missing, 404 is returned."""
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (static_dir / "assets").mkdir()
    with patch("argusprowl.api.app._static_dir", return_value=str(static_dir)):
        client = TestClient(create_api_app())
    resp = client.get("/any-unknown-route")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# API and docs routes are NOT intercepted
# ---------------------------------------------------------------------------


def test_spa_fallback_does_not_steal_api_routes(client_with_static):
    """Unknown /api/* paths must return JSON 404, not index.html."""
    resp = client_with_static.get("/api/v1/nonexistent")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/json")


def test_spa_fallback_does_not_steal_docs(client_with_static):
    """FastAPI's /docs route must not be intercepted."""
    resp = client_with_static.get("/docs")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_spa_fallback_does_not_steal_openapi_json(client_with_static):
    resp = client_with_static.get("/openapi.json")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")


# ---------------------------------------------------------------------------
# Backend API still works with static present
# ---------------------------------------------------------------------------


def test_health_endpoint_works_with_static(client_with_static):
    resp = client_with_static.get("/health")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Graceful degradation: no static directory
# ---------------------------------------------------------------------------


def test_api_app_without_static_has_no_frontend_routes(client_without_static):
    """When static/ is absent, /assets/* and catch-all return 404 from FastAPI.

    No RuntimeError is raised — the app boots cleanly for backend-only dev.
    """
    resp = client_without_static.get("/assets/app.js")
    assert resp.status_code == 404
    resp = client_without_static.get("/any-ui-route")
    assert resp.status_code == 404


def test_api_routes_work_without_static(client_without_static):
    """Backend API must remain fully functional when static/ is absent."""
    resp = client_without_static.get("/health")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Static path resolution
# ---------------------------------------------------------------------------


def test_static_dir_env_override_wins(tmp_path, monkeypatch):
    """Explicit environment override takes precedence over discovered locations."""
    explicit_dir = tmp_path / "explicit-static"
    explicit_dir.mkdir()
    monkeypatch.setenv("ARGUSPROWL_STATIC_DIR", str(explicit_dir))
    monkeypatch.delenv("TH_API__STATIC_DIR", raising=False)
    assert _static_dir() == str(explicit_dir)


def test_static_dir_env_override_is_returned_even_when_missing(tmp_path, monkeypatch):
    """A configured static directory is honored even if it does not exist yet.

    The app factory remains able to degrade gracefully when the path is missing,
    but the resolver should not silently ignore the explicit operator override.
    """
    explicit_dir = tmp_path / "does-not-exist-yet"
    monkeypatch.setenv("TH_API__STATIC_DIR", str(explicit_dir))
    monkeypatch.delenv("ARGUSPROWL_STATIC_DIR", raising=False)
    assert _static_dir() == str(explicit_dir)


def test_static_dir_cwd_fallback_prefers_local_static_dir(tmp_path, monkeypatch):
    """When no env override, /app/static, or repo candidate exists, use CWD static dir."""
    cwd_root = tmp_path / "cwd-root"
    cwd_static = cwd_root / "static"
    cwd_static.mkdir(parents=True)
    monkeypatch.delenv("ARGUSPROWL_STATIC_DIR", raising=False)
    monkeypatch.delenv("TH_API__STATIC_DIR", raising=False)
    monkeypatch.setattr(
        "argusprowl.api.app._CONTAINER_STATIC_DIR", str(tmp_path / "missing-container")
    )
    monkeypatch.setattr(Path, "is_dir", lambda self: str(self) == str(cwd_static))
    monkeypatch.setattr(os, "getcwd", lambda: str(cwd_root))

    result = _static_dir()
    assert result == str(cwd_static)
