"""Tests for replay module."""

from pathlib import Path

import pytest

from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.detector_registry import DetectorRegistry
from argusprowl.detection.detectors.port_scan import PortScanDetector
from argusprowl.feature_engineering.feature_extractor import FeatureExtractor
from argusprowl.replay.replay_engine import ReplayEngine
from argusprowl.replay.replay_reader import ReplayReader


@pytest.fixture
def sample_log_file(tmp_path: Path) -> Path:
    """Create a sample Zeek log file for testing."""
    log_file = tmp_path / "sample_conn.log"

    # Write a minimal Zeek conn.log format
    # Header line starting with #
    # Separator line
    # Data lines
    log_content = """#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2019-01-01-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	history	orig_pkts	resp_pkts
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	string	count	count
1550000000.000000	C1	192.168.1.100	12345	10.0.0.1	80	tcp	http	1.5	1024	2048	SF	ShADadfF	10	8
1550000001.000000	C2	192.168.1.100	12346	10.0.0.2	443	tcp	https	2.0	2048	4096	SF	ShADadfF	15	12
1550000002.000000	C3	192.168.1.100	12347	10.0.0.3	22	tcp	ssh	0.5	512	256	SF	ShADadfF	5	3
"""

    log_file.write_text(log_content)
    return log_file


class TestReplayReader:
    """Tests for ReplayReader class."""

    def test_read_events(self, sample_log_file: Path) -> None:
        """Test reading events from log file."""
        reader = ReplayReader(sample_log_file)
        events = list(reader.read_events())

        assert len(events) == 3
        assert all(e.attributes["uid"] in ["C1", "C2", "C3"] for e in events)

    def test_file_not_found(self, tmp_path: Path) -> None:
        """Test error handling for missing file."""
        with pytest.raises(FileNotFoundError):
            ReplayReader(tmp_path / "nonexistent.log")

    def test_statistics(self, sample_log_file: Path) -> None:
        """Test reader statistics."""
        reader = ReplayReader(sample_log_file)
        stats = reader.get_statistics()

        assert stats["file_exists"] is True
        assert stats["file_size_bytes"] > 0
        assert stats["log_path"] == str(sample_log_file)


class TestReplayEngine:
    """Tests for ReplayEngine class."""

    def test_run_replay(self, sample_log_file: Path) -> None:
        """Test running replay through detection pipeline."""
        engine = ReplayEngine(log_path=sample_log_file)
        alerts = engine.run()

        # Should complete without errors
        assert isinstance(alerts, list)
        assert engine.events_processed == 3

    def test_run_with_callbacks(self, sample_log_file: Path) -> None:
        """Test replay with callbacks."""
        engine = ReplayEngine(log_path=sample_log_file)

        callback_events = []

        def on_event(event):
            callback_events.append(("event", event.attributes["uid"]))

        engine.run_with_callbacks(on_event=on_event)

        # Should have called callback for each event
        assert len(callback_events) == 3
        assert all(e[0] == "event" for e in callback_events)

    def test_get_statistics(self, sample_log_file: Path) -> None:
        """Test replay statistics."""
        engine = ReplayEngine(log_path=sample_log_file)
        engine.run()

        stats = engine.get_statistics()
        assert "reader" in stats
        assert "events_processed" in stats
        assert stats["events_processed"] == 3

    def test_replay_with_detectors(self, sample_log_file: Path) -> None:
        """Test replay with custom detectors."""
        feature_extractor = FeatureExtractor(window_size_seconds=3600.0)
        registry = DetectorRegistry()
        registry.register(PortScanDetector())
        detection_manager = DetectionManager(registry)

        engine = ReplayEngine(
            log_path=sample_log_file,
            feature_extractor=feature_extractor,
            detection_manager=detection_manager,
        )

        alerts = engine.run()
        assert isinstance(alerts, list)
        assert engine.events_processed == 3

    def test_replay_events_processed_count(self, sample_log_file: Path) -> None:
        """Test that events_processed is tracked correctly."""
        engine = ReplayEngine(log_path=sample_log_file)
        engine.run()

        assert engine.events_processed == 3

    def test_replay_alerts_generated_count(self, sample_log_file: Path) -> None:
        """Test that alerts_generated is tracked correctly."""
        engine = ReplayEngine(log_path=sample_log_file)
        engine.run()

        # With default detectors, may or may not generate alerts
        # Just verify the property exists and is an integer
        assert isinstance(engine.alerts_generated, int)
        assert engine.alerts_generated >= 0
