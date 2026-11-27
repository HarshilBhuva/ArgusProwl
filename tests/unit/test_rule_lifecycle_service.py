"""Tests for validated, audited detector rule lifecycle operations."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from argusprowl.api.audit import AuditLog
from argusprowl.detection.rule_lifecycle_service import (
    RuleLifecycleService,
    RuleVersionConflictError,
)
from argusprowl.detection.rule_loader import RuleLoader
from argusprowl.detection.rule_revision_store import RuleRevisionStore
from argusprowl.exceptions.exceptions import DetectionError
from argusprowl.storage.sqlite_storage import SQLiteAdapter


@pytest.fixture
def lifecycle(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_path = rules_dir / "port_scan.yaml"
    rule_path.write_text(
        "rule_id: port_scan\n"
        "name: Port scan\n"
        "description: Detects scanning\n"
        "detector: PortScanDetector\n"
        "enabled: true\n"
        "version: 1\n"
        "confidence_threshold: 0.5\n"
        "parameters:\n  min_unique_ports: 10\n  min_connection_rate: 1.0\n"
        "severity: MEDIUM\ntags: [reconnaissance]\nmetadata:\n  owner: detection-team\n",
        encoding="utf-8",
    )
    storage = SQLiteAdapter(tmp_path / "rules.db")
    audit = AuditLog(str(tmp_path / "audit.db"))
    manager = RuleLoader(rules_dir, storage=storage).build_detection_manager()
    service = RuleLifecycleService(
        rules_dir=rules_dir,
        revision_store=RuleRevisionStore(storage),
        detection_manager=manager,
        audit_log=audit,
    )
    yield service, manager, rule_path, audit
    storage.close()


def test_rule_update_versions_audits_and_activates_atomically(lifecycle) -> None:
    service, manager, rule_path, audit = lifecycle

    result = service.update(
        "port_scan",
        expected_version=1,
        actor="security-admin",
        change_reason="Disable noisy rule during maintenance",
        enabled=False,
        request_id="request-update-1",
    )

    active = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    assert result["version"] == 2
    assert result["activated"] is True
    assert active["version"] == 2
    assert active["enabled"] is False
    assert active["name"] == "Port scan"
    assert active["severity"] == "MEDIUM"
    assert active["tags"] == ["reconnaissance"]
    assert active["metadata"] == {"owner": "detection-team"}
    assert manager.get_registry().get("port_scan").is_enabled() is False
    assert [item["version"] for item in service.history("port_scan")] == [2, 1]
    assert audit.verify_integrity()["valid"] is True
    assert audit.count_events() == 2


def test_rollback_creates_forward_revision_and_reactivates_old_content(lifecycle) -> None:
    service, manager, rule_path, _ = lifecycle
    service.update(
        "port_scan",
        expected_version=1,
        actor="security-admin",
        change_reason="Temporarily disable",
        enabled=False,
    )

    result = service.rollback(
        "port_scan",
        target_version=1,
        expected_version=2,
        actor="security-admin",
        change_reason="Restore known-good configuration",
    )

    active = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    assert result["version"] == 3
    assert result["rollback_from_version"] == 1
    assert active["version"] == 3
    assert active["enabled"] is True
    assert manager.get_registry().get("port_scan").is_enabled() is True
    assert [item["version"] for item in service.history("port_scan")] == [3, 2, 1]


def test_stale_rule_update_is_rejected_without_mutation(lifecycle) -> None:
    service, _, rule_path, _ = lifecycle
    before = rule_path.read_bytes()

    with pytest.raises(RuleVersionConflictError):
        service.update(
            "port_scan",
            expected_version=7,
            actor="security-admin",
            change_reason="Stale update",
            enabled=False,
        )

    assert rule_path.read_bytes() == before
    assert service.history("port_scan") == []


def test_invalid_detector_configuration_is_rejected_before_revision(lifecycle) -> None:
    service, _, rule_path, _ = lifecycle
    before = rule_path.read_bytes()

    with pytest.raises(DetectionError):
        service.update(
            "port_scan",
            expected_version=1,
            actor="security-admin",
            change_reason="Invalid parameter",
            parameters={"not_a_port_scan_option": True},
        )

    assert rule_path.read_bytes() == before
    assert service.history("port_scan") == []
