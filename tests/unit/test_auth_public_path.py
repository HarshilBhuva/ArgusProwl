"""Regression tests for the API authentication public-path boundary."""

from argusprowl.api.auth import _is_public_path


def test_exact_public_health_paths() -> None:
    assert _is_public_path("/health")
    assert _is_public_path("/api/v1/health")
    assert not _is_public_path("/health/private")
    assert not _is_public_path("/api/v1/health/private")


def test_api_paths_cannot_bypass_auth_by_file_extension() -> None:
    assert not _is_public_path("/api/v1/evidence.svg")
    assert not _is_public_path("/api/v1/alerts.js")
    assert not _is_public_path("/api/v1/rules.css", accept="text/html")


def test_docs_paths_are_exact_not_prefix_matches() -> None:
    assert _is_public_path("/docs")
    assert _is_public_path("/redoc")
    assert _is_public_path("/openapi.json")
    assert not _is_public_path("/docs-sensitive")
    assert not _is_public_path("/redoc/private")
    assert not _is_public_path("/openapi-private", accept="text/html")


def test_only_dedicated_asset_mount_is_public() -> None:
    assert _is_public_path("/assets/app-123.js")
    assert not _is_public_path("/api/v1/export.js")
    assert not _is_public_path("/private/app.js")


def test_spa_navigation_is_public_but_non_navigation_is_not() -> None:
    assert _is_public_path("/investigations/123", accept="text/html")
    assert not _is_public_path("/investigations/123", accept="application/json")
    assert not _is_public_path("/investigations/123", method="POST", accept="text/html")
    assert not _is_public_path("/health/private", accept="text/html")
