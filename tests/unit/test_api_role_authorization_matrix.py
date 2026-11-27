"""Explicit endpoint/method/role acceptance matrix for API authorization."""

import pytest

from argusprowl.api.auth import _role_allows


@pytest.mark.parametrize(
    ("role", "method", "path", "allowed"),
    [
        # Viewer: read-only access to supported investigation surfaces.
        ("viewer", "GET", "/api/v1/alerts", True),
        ("viewer", "HEAD", "/api/v1/evidence/00000000-0000-0000-0000-000000000001", True),
        ("viewer", "GET", "/api/v1/incidents", True),
        ("viewer", "GET", "/api/v1/hunts", True),
        ("viewer", "GET", "/api/v1/attck/investigation", True),
        ("viewer", "POST", "/api/v1/alerts/alert-1/close", False),
        ("viewer", "POST", "/api/v1/hunts", False),
        ("viewer", "DELETE", "/api/v1/incidents/incident-1", False),
        ("viewer", "GET", "/api/v1/audit", False),
        # Analyst: viewer reads plus explicitly enumerated investigation writes.
        ("analyst", "GET", "/api/v1/alerts/alert-1", True),
        ("analyst", "POST", "/api/v1/alerts/alert-1/acknowledge", True),
        ("analyst", "POST", "/api/v1/incidents/incident-1/transition", True),
        ("analyst", "POST", "/api/v1/entities/host/server-01/annotations", True),
        ("analyst", "POST", "/api/v1/hunts", True),
        ("analyst", "POST", "/api/v1/hunts/hunt-1/queries/query-1/execute", True),
        ("analyst", "DELETE", "/api/v1/hunts/hunt-1", False),
        ("analyst", "POST", "/api/v1/rules", False),
        ("analyst", "GET", "/api/v1/audit/integrity", False),
        # Admin: unrestricted API operations except audit remains read-only.
        ("admin", "POST", "/api/v1/rules", True),
        ("admin", "DELETE", "/api/v1/hunts/hunt-1", True),
        ("admin", "GET", "/api/v1/audit", True),
        ("admin", "POST", "/api/v1/audit", False),
        # Unknown roles and unlisted methods/paths fail closed.
        ("operator", "GET", "/api/v1/alerts", False),
        ("analyst", "PATCH", "/api/v1/alerts/alert-1", False),
        ("analyst", "POST", "/api/v1/alerts/alert-1/close/extra", False),
    ],
)
def test_role_method_endpoint_matrix(role, method, path, allowed):
    assert _role_allows(role, method, path) is allowed


def test_analyst_investigation_write_allowlist_requires_full_path_match():
    assert _role_allows("analyst", "POST", "/api/v1/hunts/hunt-1/status") is True
    assert _role_allows("analyst", "POST", "/api/v1/hunts/hunt-1/status/extra") is False
    assert _role_allows("analyst", "POST", "/api/v1/hunts/hunt-1/../../rules") is False


def test_admin_audit_access_is_read_only():
    assert _role_allows("admin", "GET", "/api/v1/audit/events") is True
    assert _role_allows("admin", "POST", "/api/v1/audit/events") is False
