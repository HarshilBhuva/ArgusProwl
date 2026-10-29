"""Tests for replay metric semantics.

Covers the distinction between detection matches (raw matched results) and
actual Alert objects produced by the decision engine, and verifies that the
``alerts_generated`` property is a backward-compatible alias for
``alerts_created``.
"""

from pathlib import Path

from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.detector_registry import DetectorRegistry
from argusprowl.detection.detectors.port_scan import PortScanDetector
from argusprowl.feature_engineering.feature_extractor import FeatureExtractor
from argusprowl.replay.replay_engine import ReplayEngine


def _make_sample_log(tmp_path: Path) -> Path:
    log_file = tmp_path / "sample_conn.log"
    log_file.write_text(
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tconn\n"
        "#open\t2019-01-01-00-00-00\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\n"
        "1550000000.000000\tC1\t192.168.1.100\t12345\t10.0.0.1\t80\ttcp\thttp\t1.5\t1024\t2048\tSF\tShADadfF\t10\t8\n"
        "1550000001.000000\tC2\t192.168.1.100\t12346\t10.0.0.2\t443\ttcp\thttps\t2.0\t2048\t4096\tSF\tShADadfF\t15\t12\n"
    )
    return log_file


class TestNoDecisionEngine:
    """Without a decision engine, detection matches are counted but no alerts are created."""

    def test_detection_matches_without_decision_engine(self, tmp_path: Path) -> None:
        log_file = _make_sample_log(tmp_path)
        engine = ReplayEngine(log_path=log_file)
        alerts = engine.run()
        # The engine has no decision/intelligence services, so no Alert objects
        # should be produced regardless of whether detectors matched.
        assert isinstance(alerts, list)
        assert engine.alerts_created == 0
        assert engine.alerts_generated == 0  # deprecated alias must match
        assert engine.events_processed == 2


class TestWithDecisionEngine:
    """When a decision engine is present, alerts_created tracks real Alert objects."""

    def test_alerts_created_matches_returned_list(self, tmp_path: Path) -> None:
        feature_extractor = FeatureExtractor(window_size_seconds=3600.0)
        registry = DetectorRegistry()
        registry.register(PortScanDetector())
        detection_manager = DetectionManager(registry)
        log_file = _make_sample_log(tmp_path)
        engine = ReplayEngine(
            log_path=log_file,
            feature_extractor=feature_extractor,
            detection_manager=detection_manager,
        )
        alerts = engine.run()
        assert engine.alerts_created == len(alerts)
        assert engine.alerts_generated == engine.alerts_created


class TestGetStatistics:
    """get_statistics() must include the new metric keys."""

    def test_statistics_includes_new_keys(self, tmp_path: Path) -> None:
        log_file = _make_sample_log(tmp_path)
        engine = ReplayEngine(log_path=log_file)
        engine.run()
        stats = engine.get_statistics()
        assert "detection_matches" in stats
        assert "alerts_created" in stats
        assert "alerts_generated" in stats
        # alerts_generated is a deprecated alias for alerts_created
        assert stats["alerts_generated"] == stats["alerts_created"]

    def test_alerts_generated_equals_alerts_created(self, tmp_path: Path) -> None:
        log_file = _make_sample_log(tmp_path)
        engine = ReplayEngine(log_path=log_file)
        engine.run()
        assert engine.alerts_generated == engine.alerts_created


class TestRepr:
    """__repr__ must show both counts."""

    def test_repr_shows_both_counts(self, tmp_path: Path) -> None:
        log_file = _make_sample_log(tmp_path)
        engine = ReplayEngine(log_path=log_file)
        engine.run()
        r = repr(engine)
        assert "events=" in r
        assert "detections=" in r
        assert "alerts=" in r
