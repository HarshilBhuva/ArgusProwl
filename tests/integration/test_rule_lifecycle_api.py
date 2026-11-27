"""Integration tests for authenticated rule revision APIs."""

from __future__ import annotations

from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.rule_loader import RuleLoader


def test_rule_admin_api_enforces_rbac_and_supports_history_update_rollback(tmp_path) -> None:
    ServiceContainer.reset_instance()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "port_scan.yaml").write_text(
        "rule_id: port_scan\n"
        "name: Port scan\n"
        "description: Detects scanning\n"
        "detector: PortScanDetector\n"
        "enabled: true\n"
        "version: 1\n"
        "confidence_threshold: 0.5\n"
        "parameters:\n  min_unique_ports: 10\n  min_connection_rate: 1.0\n"
        "severity: MEDIUM\n",
        encoding="utf-8",
    )
    manager = RuleLoader(rules_dir).build_detection_manager()
    ServiceContainer.get_instance().register_singleton(DetectionManager, manager)

    admin_secret = "admin-rule-api-secret-that-is-at-least-32-characters"
    viewer_secret = "viewer-rule-api-secret-that-is-at-least-32-characters"
    app = create_api_app(
        auth_enabled=True,
        api_keys={
            "admin-key": {"secret": admin_secret, "subject": "rule-admin", "role": "admin"},
            "viewer-key": {"secret": viewer_secret, "subject": "read-only", "role": "viewer"},
        },
        audit_db_path=str(tmp_path / "audit.db"),
    )
    app.state.rules_dir = rules_dir
    client = TestClient(app)
    admin_headers = {"X-ArgusProwl-Key": admin_secret}
    viewer_headers = {"X-ArgusProwl-Key": viewer_secret}

    denied = client.put(
        "/api/v1/rules/port_scan",
        json={"expected_version": 1, "change_reason": "Unauthorized edit", "enabled": False},
        headers=viewer_headers,
    )
    assert denied.status_code == 403

    updated = client.put(
        "/api/v1/rules/port_scan",
        json={"expected_version": 1, "change_reason": "Tune rule", "enabled": False},
        headers=admin_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["version"] == 2
    assert updated.json()["activated"] is True

    history = client.get("/api/v1/rules/port_scan/revisions", headers=viewer_headers)
    assert history.status_code == 200
    assert [item["version"] for item in history.json()["revisions"]] == [2, 1]

    rolled_back = client.post(
        "/api/v1/rules/port_scan/rollback",
        json={
            "expected_version": 2,
            "target_version": 1,
            "change_reason": "Restore baseline",
        },
        headers=admin_headers,
    )
    assert rolled_back.status_code == 200
    assert rolled_back.json()["version"] == 3
    assert rolled_back.json()["rollback_from_version"] == 1

    ServiceContainer.reset_instance()
