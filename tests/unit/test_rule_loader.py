"""Tests for YAML detector rule loading."""

from pathlib import Path

import pytest

from argusprowl.detection.detectors.port_scan import PortScanDetector
from argusprowl.detection.rule_loader import RuleLoader
from argusprowl.exceptions.exceptions import DetectionError


def test_load_default_rules_builds_configured_manager() -> None:
    manager = RuleLoader().build_detection_manager()

    # Should have 8 original rules + 2 behavior rules = 10
    assert manager.detector_count == 10
    assert manager.enabled_detector_count == 10
    assert isinstance(manager.get_registry().get("port_scan"), PortScanDetector)


def test_rule_parameters_configure_detector(tmp_path: Path) -> None:
    (tmp_path / "port_scan.yaml").write_text(
        "rule_id: port_scan\ndetector: PortScanDetector\nenabled: false\n"
        "parameters:\n  min_unique_ports: 99\n  min_connection_rate: 3.5\n"
    )

    detector = RuleLoader(tmp_path).build_detection_manager().get_registry().get("port_scan")

    assert detector.is_enabled() is False
    assert detector.get_config("min_unique_ports") == 99
    assert detector._min_unique_ports == 99
    assert detector._min_connection_rate == 3.5


def test_unknown_detector_is_rejected(tmp_path: Path) -> None:
    rule_file = tmp_path / "unknown.yaml"
    rule_file.write_text("rule_id: unknown\ndetector: ArbitraryCode\nparameters: {}\n")

    with pytest.raises(DetectionError, match="unsupported detector"):
        RuleLoader(tmp_path).load_rule(rule_file)


def test_rule_id_must_match_detector_name(tmp_path: Path) -> None:
    (tmp_path / "wrong.yaml").write_text(
        "rule_id: another_name\ndetector: PortScanDetector\nparameters: {}\n"
    )

    with pytest.raises(DetectionError, match="must match"):
        RuleLoader(tmp_path).build_detection_manager()


def test_event_count_rule_valid(tmp_path: Path) -> None:
    (tmp_path / "event_count.yaml").write_text(
        "rule_id: my_event_count\n"
        "detector: EventCountCorrelationDetector\n"
        "parameters:\n"
        "  correlation:\n"
        "    type: event_count\n"
        "    count: 10\n"
        "    timespan: 1h\n"
        "    group_by: [src_ip, dst_ip]\n"
        "    filter:\n"
        "      event_type: auth\n"
    )
    detector = RuleLoader(tmp_path).build_detection_manager().get_registry().get("my_event_count")
    assert detector.name == "my_event_count"
    assert detector._count == 10
    assert detector._timespan.total_seconds() == 3600
    assert detector._group_by == ["src_ip", "dst_ip"]
    assert detector._filter_config == {"event_type": "auth"}


def test_event_count_rule_invalid_correlation_type(tmp_path: Path) -> None:
    (tmp_path / "event_count.yaml").write_text(
        "rule_id: my_event_count\n"
        "detector: EventCountCorrelationDetector\n"
        "parameters:\n"
        "  correlation:\n"
        "    type: unknown_type\n"
        "    count: 10\n"
        "    timespan: 1h\n"
    )
    with pytest.raises(DetectionError, match="only 'event_count' correlation type is supported"):
        RuleLoader(tmp_path).build_detection_manager()


def test_event_count_rule_invalid_count(tmp_path: Path) -> None:
    (tmp_path / "event_count.yaml").write_text(
        "rule_id: my_event_count\n"
        "detector: EventCountCorrelationDetector\n"
        "parameters:\n"
        "  correlation:\n"
        "    type: event_count\n"
        "    count: 0\n"
        "    timespan: 1h\n"
    )
    with pytest.raises(DetectionError, match=r"correlation\.count must be a positive integer"):
        RuleLoader(tmp_path).build_detection_manager()


def test_event_count_rule_invalid_timespan(tmp_path: Path) -> None:
    (tmp_path / "event_count.yaml").write_text(
        "rule_id: my_event_count\n"
        "detector: EventCountCorrelationDetector\n"
        "parameters:\n"
        "  correlation:\n"
        "    type: event_count\n"
        "    count: 10\n"
        "    timespan: 1x\n"
    )
    with pytest.raises(DetectionError, match="Invalid timespan format"):
        RuleLoader(tmp_path).build_detection_manager()


def test_event_count_rule_invalid_group_by(tmp_path: Path) -> None:
    (tmp_path / "event_count.yaml").write_text(
        "rule_id: my_event_count\n"
        "detector: EventCountCorrelationDetector\n"
        "parameters:\n"
        "  correlation:\n"
        "    type: event_count\n"
        "    count: 10\n"
        "    timespan: 1h\n"
        "    group_by: [invalid_field]\n"
    )
    with pytest.raises(DetectionError, match="Invalid group_by field"):
        RuleLoader(tmp_path).build_detection_manager()


def test_event_count_rule_invalid_filter(tmp_path: Path) -> None:
    (tmp_path / "event_count.yaml").write_text(
        "rule_id: my_event_count\n"
        "detector: EventCountCorrelationDetector\n"
        "parameters:\n"
        "  correlation:\n"
        "    type: event_count\n"
        "    count: 10\n"
        "    timespan: 1h\n"
        "    filter:\n"
        "      invalid_field: value\n"
    )
    with pytest.raises(DetectionError, match="Invalid filter field"):
        RuleLoader(tmp_path).build_detection_manager()
