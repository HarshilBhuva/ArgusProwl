"""Regression tests for optional ATT&CK enrichment startup and behavior.

Covers:
- Application starts successfully when ATT&CK is enabled but no snapshot exists (status UNAVAILABLE/EMPTY).
- Core detection services and health endpoints function normally without snapshot.
- ATT&CK overview endpoint reports status correctly when knowledge is unavailable.
- Mapping validation remains strict when valid snapshot is present.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from argusprowl.api.app import create_api_app
from argusprowl.attck.knowledge_service import AttckKnowledgeService
from argusprowl.attck.mapping_registry import AttckMappingRegistry
from argusprowl.constants.attck import AttckKnowledgeStatus
from argusprowl.core.application import Application
from argusprowl.exceptions.exceptions import ValidationError


def test_application_startup_without_attck_snapshot(tmp_path: Path) -> None:
    """Application boots successfully when ATT&CK is enabled but snapshot path is missing."""
    # Create temp config with attck enabled but non-existent snapshot
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
app_name: ArgusProwl-Test
api:
  enabled: true
  host: 127.0.0.1
  port: 8080
attck:
  enabled: true
  snapshot_path: "non_existent_snapshot_path.json"
"""
    )

    app = Application(config_path=config_path)
    # Start application without background threads/API server binding for fast test
    app._config = app._config_manager.load(app._config_path)
    app._register_services()

    # Verify knowledge service is registered with UNAVAILABLE or EMPTY status
    assert app._container.is_registered(AttckKnowledgeService)
    ks = app._container.resolve(AttckKnowledgeService)
    assert ks.get_status() in {AttckKnowledgeStatus.UNAVAILABLE, AttckKnowledgeStatus.EMPTY}

    # Verify mapping registry is NOT registered when snapshot is unavailable
    assert not app._container.is_registered(AttckMappingRegistry)


def test_attck_overview_endpoint_without_snapshot(tmp_path: Path) -> None:
    """GET /attck/overview returns status response without error when snapshot is missing."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
app_name: ArgusProwl-Test
api:
  enabled: true
attck:
  enabled: true
  snapshot_path: "non_existent.json"
"""
    )
    app = Application(config_path=config_path)
    app._config = app._config_manager.load(app._config_path)
    app._register_services()

    api_app = create_api_app()
    client = TestClient(api_app)

    # Inject application container or mock container resolution if needed
    # (By default FastAPI app routes use container singleton if wired)
    with patch("argusprowl.dependency_injection.container.ServiceContainer.get_instance", return_value=app._container):
        response = client.get("/api/v1/attck/overview")
        assert response.status_code == 200
        data = response.json()
        assert data["knowledge_status"] in {"UNAVAILABLE", "EMPTY"}
        assert data["mapping_count"] == 0


def test_mapping_validation_with_valid_snapshot(tmp_path: Path) -> None:
    """Mapping validation succeeds and enforces checks when a valid snapshot is present."""
    # Build minimal valid knowledge snapshot
    snapshot_file = tmp_path / "enterprise-attack.json"
    snapshot_file.write_text(
        '{"type": "bundle", "id": "bundle--1", "spec_version": "2.1", "objects": [{"type": "x-mitre-collection", "spec_version": "2.1", "x_mitre_version": "14.0", "name": "Enterprise"},{"type": "attack-pattern", "id": "attack-pattern--t1046", "name": "Scanning", "external_references": [{"source_name": "mitre-attack", "external_id": "T1046"}]}]}'
    )

    mapping_file = tmp_path / "attck_mappings.yaml"
    mapping_file.write_text(
        """
mappings:
  - rule_id: "PORT_SCAN_01"
    technique_id: "T1046"
    mapping_type: "DIRECT"
    rationale: "Direct detection"
"""
    )

    ks = AttckKnowledgeService(snapshot_path=snapshot_file, enabled=True)
    assert ks.get_status() == AttckKnowledgeStatus.AVAILABLE

    registry = AttckMappingRegistry(knowledge_service=ks, mapping_path=mapping_file)
    mappings = registry.get_for_rule("PORT_SCAN_01")
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1046"

    # Verify invalid technique reference raises ValidationError
    bad_mapping_file = tmp_path / "bad_mappings.yaml"
    bad_mapping_file.write_text(
        """
mappings:
  - rule_id: "BAD_RULE"
    technique_id: "T9999"
    mapping_type: "DIRECT"
"""
    )
    with pytest.raises(ValidationError, match="Unknown ATT&CK technique_id"):
        AttckMappingRegistry(knowledge_service=ks, mapping_path=bad_mapping_file)


def test_alert_manager_resolves_without_snapshot(tmp_path: Path) -> None:
    """AlertManager resolves successfully when ATT&CK is enabled but snapshot is missing.

    Regression guard for the latent inconsistency where AlertManager eagerly resolved
    AttckEnrichmentService (keyed on attck.enabled) even when the mapping registry was
    not registered due to missing knowledge.
    """
    from argusprowl.alerting.alert_manager import AlertManager

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
app_name: ArgusProwl-Test
api:
  enabled: true
  host: 127.0.0.1
  port: 8080
attck:
  enabled: true
  snapshot_path: "non_existent_snapshot_path.json"
"""
    )
    app = Application(config_path=config_path)
    app._config = app._config_manager.load(app._config_path)
    app._register_services()

    # Should not raise DependencyError even though AttckEnrichmentService is absent.
    assert app._container.is_registered(AlertManager)
    alert_manager = app._container.resolve(AlertManager)
    assert alert_manager._attck_enrichment_service is None


def test_core_api_routes_without_attck_snapshot(tmp_path: Path) -> None:
    """Core API routes remain operational when ATT&CK knowledge is unavailable."""
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from argusprowl.api.app import create_api_app

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
app_name: ArgusProwl-Test
api:
  enabled: true
attck:
  enabled: true
  snapshot_path: "non_existent.json"
"""
    )
    app = Application(config_path=config_path)
    app._config = app._config_manager.load(app._config_path)
    app._register_services()

    api_app = create_api_app()
    client = TestClient(api_app)

    with patch(
        "argusprowl.dependency_injection.container.ServiceContainer.get_instance",
        return_value=app._container,
    ):
        # Health endpoint should return 200 degraded (not 503).
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json()["status"] == "degraded"

        # Rules list endpoint should work without ATT&CK.
        response = client.get("/api/v1/rules")
        assert response.status_code == 200
        data = response.json()
        assert "rules" in data
        assert "total_count" in data

        # Pick an existing rule and confirm its detail endpoint works with empty mappings.
        if data["rules"]:
            rule_id = data["rules"][0]["rule_id"]
            response = client.get(f"/api/v1/rules/{rule_id}")
            assert response.status_code == 200
            assert response.json()["attck_mappings"] == []

        # ATT&CK investigation should return 404 (no matching alerts) instead of 500.
        response = client.get(
            "/api/v1/attck/investigation?alert_ids="
            "00000000-0000-0000-0000-000000000000"
        )
        assert response.status_code == 404
