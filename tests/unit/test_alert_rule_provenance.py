"""End-to-end rule revision provenance tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.detection.rule_fingerprint import rule_content_sha256, rule_revision_id
from argusprowl.detection.rule_loader import RuleLoader
from argusprowl.detection.rule_revision_store import RuleRevisionStore
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.models.alert import Alert
from argusprowl.storage.sqlite_storage import SQLiteAdapter


def test_detection_and_alert_pin_the_exact_immutable_rule_revision(tmp_path: Path) -> None:
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
        "parameters:\n  min_unique_ports: 10\n  min_connection_rate: 1.0\n",
        encoding="utf-8",
    )
    loader = RuleLoader(rules_dir)
    rule = loader.load_rule(rule_path)
    manager = loader.build_detection_manager()
    detector = manager.get_registry().get("port_scan")
    expected_hash = rule_content_sha256(rule)
    expected_revision_id = rule_revision_id("port_scan", 1)

    storage = SQLiteAdapter(tmp_path / "revision.db")
    try:
        revision = RuleRevisionStore(storage).record_revision(
            rule, actor="system", change_reason="Initial rule import"
        )
        assert revision.content_sha256 == expected_hash
        assert revision.revision_id == expected_revision_id

        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=uuid4(),
            window_start=now - timedelta(seconds=60),
            window_end=now,
            src_ip="192.0.2.10",
            connection_count=25,
            unique_dst_ports=15,
            connection_rate=2.5,
            port_concentration=0.1,
        )
        results = manager.process_feature_vector(vector)
        matched = next(result for result in results if result.rule_id == "port_scan")
        assert matched.matched is True
        assert matched.metadata["rule_content_sha256"] == expected_hash
        assert matched.metadata["rule_revision_id"] == expected_revision_id

        alert = DecisionEngine().process_detection_result(matched)
        assert alert is not None
        assert alert.metadata["rule_id"] == "port_scan"
        assert alert.metadata["rule_version"] == 1
        assert alert.metadata["rule_content_sha256"] == expected_hash
        assert alert.metadata["rule_revision_id"] == expected_revision_id

        restored = Alert.from_dict(alert.to_dict())
        assert restored.metadata["rule_content_sha256"] == expected_hash
        assert restored.metadata["rule_revision_id"] == expected_revision_id
    finally:
        storage.close()
