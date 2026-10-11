"""Tests for detection module."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.detector_registry import DetectorRegistry
from argusprowl.detection.detectors.connection_flood import ConnectionFloodDetector
from argusprowl.detection.detectors.failed_connections import FailedConnectionsDetector
from argusprowl.detection.detectors.horizontal_scan import HorizontalScanDetector
from argusprowl.detection.detectors.long_connection import LongConnectionDetector
from argusprowl.detection.detectors.port_scan import PortScanDetector
from argusprowl.detection.detectors.syn_scan import SynScanDetector
from argusprowl.detection.detectors.vertical_scan import VerticalScanDetector
from argusprowl.feature_engineering.feature_vector import FeatureVector


@pytest.fixture
def sample_feature_vector() -> FeatureVector:
    """Create a sample FeatureVector for testing."""
    now = datetime.now(UTC)
    return FeatureVector(
        event_id=uuid4(),
        window_start=now - timedelta(seconds=60),
        window_end=now,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        proto="tcp",
        connection_count=50,
        unique_dst_ports=15,
        unique_dst_ips=1,
        failed_connections=5,
        syn_count=45,
        avg_duration=1.0,
        max_duration=5.0,
        min_duration=0.1,
        std_duration=0.5,
        total_bytes_sent=10240,
        total_bytes_received=20480,
        connection_rate=10.0,
        bytes_rate=5120.0,
        port_concentration=0.8,
        is_multi_port=True,
        is_multi_dst=False,
    )


@pytest.fixture
def port_scan_vector() -> FeatureVector:
    """Create a FeatureVector that should trigger port scan detection."""
    now = datetime.now(UTC)
    return FeatureVector(
        event_id=uuid4(),
        window_start=now - timedelta(seconds=60),
        window_end=now,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        connection_count=25,
        unique_dst_ports=15,
        connection_rate=2.5,
    )


@pytest.fixture
def horizontal_scan_vector() -> FeatureVector:
    """Create a FeatureVector that should trigger horizontal scan detection."""
    now = datetime.now(UTC)
    return FeatureVector(
        event_id=uuid4(),
        window_start=now - timedelta(seconds=60),
        window_end=now,
        src_ip="192.168.1.100",
        dst_port=80,
        connection_count=20,
        unique_dst_ips=10,
        connection_rate=3.0,
        is_multi_dst=True,
    )


class TestDetectorRegistry:
    """Tests for DetectorRegistry class."""

    def test_register_detector(self) -> None:
        """Test detector registration."""
        registry = DetectorRegistry()
        detector = PortScanDetector()

        registry.register(detector)
        assert "port_scan" in registry
        assert len(registry) == 1

    def test_register_duplicate_raises(self) -> None:
        """Test registering duplicate detector raises error."""
        registry = DetectorRegistry()
        detector1 = PortScanDetector()
        detector2 = PortScanDetector()

        registry.register(detector1)
        with pytest.raises(ValueError):
            registry.register(detector2)

    def test_unregister_detector(self) -> None:
        """Test detector unregistration."""
        registry = DetectorRegistry()
        detector = PortScanDetector()
        registry.register(detector)

        registry.unregister("port_scan")
        assert "port_scan" not in registry
        assert len(registry) == 0

    def test_get_detector(self) -> None:
        """Test getting detector by name."""
        registry = DetectorRegistry()
        detector = PortScanDetector()
        registry.register(detector)

        retrieved = registry.get("port_scan")
        assert retrieved is detector

    def test_get_enabled_detectors(self) -> None:
        """Test getting enabled detectors."""
        registry = DetectorRegistry()
        detector1 = PortScanDetector()
        detector2 = HorizontalScanDetector()

        registry.register(detector1)
        registry.register(detector2)

        enabled = registry.get_enabled()
        assert len(enabled) == 2

        detector2.disable()
        enabled = registry.get_enabled()
        assert len(enabled) == 1


class TestPortScanDetector:
    """Tests for PortScanDetector."""

    def test_detect_port_scan(self, port_scan_vector: FeatureVector) -> None:
        """Test port scan detection."""
        detector = PortScanDetector(min_unique_ports=10, min_connection_rate=1.0)
        result = detector.detect(port_scan_vector)

        assert result.matched is True
        assert result.severity in (Severity.MEDIUM, Severity.HIGH)
        assert result.confidence > 0.0

    def test_no_false_positive(self, sample_feature_vector: FeatureVector) -> None:
        """Test no false positive for normal traffic."""
        detector = PortScanDetector(min_unique_ports=10, min_connection_rate=1.0)
        result = detector.detect(sample_feature_vector)

        assert result.matched is False

    def test_disabled_detector(self, port_scan_vector: FeatureVector) -> None:
        """Test disabled detector returns no match."""
        detector = PortScanDetector()
        detector.disable()
        result = detector.detect(port_scan_vector)

        assert result.matched is False
        assert result.confidence == 0.0


class TestHorizontalScanDetector:
    """Tests for HorizontalScanDetector."""

    def test_detect_horizontal_scan(self, horizontal_scan_vector: FeatureVector) -> None:
        """Test horizontal scan detection."""
        detector = HorizontalScanDetector(min_unique_dst_ips=5, min_connection_rate=2.0)
        result = detector.detect(horizontal_scan_vector)

        assert result.matched is True
        assert result.severity in (Severity.MEDIUM, Severity.HIGH)

    def test_no_detection_single_dst(self, sample_feature_vector: FeatureVector) -> None:
        """Test no detection for single destination."""
        detector = HorizontalScanDetector()
        result = detector.detect(sample_feature_vector)

        assert result.matched is False


class TestVerticalScanDetector:
    """Tests for VerticalScanDetector."""

    def test_detect_vertical_scan(self) -> None:
        """Test vertical scan detection."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=uuid4(),
            window_start=now - timedelta(seconds=60),
            window_end=now,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            connection_count=30,
            unique_dst_ports=15,
            unique_dst_ips=1,
            connection_rate=3.0,
            is_multi_port=True,
        )

        detector = VerticalScanDetector(min_unique_ports=10, min_connection_rate=2.0)
        result = detector.detect(vector)

        assert result.matched is True
        assert "vertical" in result.description.lower() or "scan" in result.description.lower()

    def test_no_detection_multi_dst(self) -> None:
        """Test no detection for multiple destinations."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=uuid4(),
            window_start=now - timedelta(seconds=60),
            window_end=now,
            src_ip="192.168.1.100",
            connection_count=30,
            unique_dst_ports=15,
            unique_dst_ips=5,
            connection_rate=3.0,
            is_multi_port=True,
        )

        detector = VerticalScanDetector()
        result = detector.detect(vector)

        assert result.matched is False


class TestSynScanDetector:
    """Tests for SynScanDetector."""

    def test_detect_syn_scan(self) -> None:
        """Test SYN scan detection."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=uuid4(),
            window_start=now - timedelta(seconds=60),
            window_end=now,
            src_ip="192.168.1.100",
            connection_count=20,
            syn_count=18,
            failed_connections=15,
        )

        detector = SynScanDetector(min_syn_ratio=0.7, min_syn_count=10)
        result = detector.detect(vector)

        assert result.matched is True
        assert result.severity in (Severity.MEDIUM, Severity.HIGH)

    def test_no_detection_low_syn_ratio(self) -> None:
        """Test no detection with low SYN ratio."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=uuid4(),
            window_start=now - timedelta(seconds=60),
            window_end=now,
            src_ip="192.168.1.100",
            connection_count=20,
            syn_count=5,
            failed_connections=2,
        )

        detector = SynScanDetector()
        result = detector.detect(vector)

        assert result.matched is False


class TestFailedConnectionsDetector:
    """Tests for FailedConnectionsDetector."""

    def test_detect_high_failures(self) -> None:
        """Test detection of high failure rate."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=uuid4(),
            window_start=now - timedelta(seconds=60),
            window_end=now,
            src_ip="192.168.1.100",
            connection_count=20,
            failed_connections=15,
        )

        detector = FailedConnectionsDetector(min_failed_ratio=0.5, min_failed_count=10)
        result = detector.detect(vector)

        assert result.matched is True

    def test_no_detection_low_failures(self) -> None:
        """Test no detection with low failure rate."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=uuid4(),
            window_start=now - timedelta(seconds=60),
            window_end=now,
            src_ip="192.168.1.100",
            connection_count=20,
            failed_connections=2,
        )

        detector = FailedConnectionsDetector()
        result = detector.detect(vector)

        assert result.matched is False


class TestConnectionFloodDetector:
    """Tests for ConnectionFloodDetector."""

    def test_detect_connection_flood(self) -> None:
        """Test connection flood detection."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=uuid4(),
            window_start=now - timedelta(seconds=10),
            window_end=now,
            src_ip="192.168.1.100",
            connection_count=50,
            connection_rate=15.0,
        )

        detector = ConnectionFloodDetector(min_connection_rate=10.0, min_connection_count=20)
        result = detector.detect(vector)

        assert result.matched is True
        assert result.severity in (Severity.MEDIUM, Severity.HIGH)

    def test_no_detection_low_rate(self) -> None:
        """Test no detection with low connection rate."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=uuid4(),
            window_start=now - timedelta(seconds=60),
            window_end=now,
            src_ip="192.168.1.100",
            connection_count=10,
            connection_rate=2.0,
        )

        detector = ConnectionFloodDetector()
        result = detector.detect(vector)

        assert result.matched is False


class TestLongConnectionDetector:
    """Tests for LongConnectionDetector."""

    def test_detect_long_connection(self) -> None:
        """Test long connection detection."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=uuid4(),
            window_start=now - timedelta(seconds=60),
            window_end=now,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            max_duration=7200.0,  # 2 hours
            avg_duration=3600.0,
            total_bytes_sent=2 * 1024 * 1024,
            total_bytes_received=3 * 1024 * 1024,
        )

        detector = LongConnectionDetector(
            min_duration_seconds=3600.0, min_bytes_transferred=1024 * 1024
        )
        result = detector.detect(vector)

        assert result.matched is True

    def test_no_detection_short_connection(self) -> None:
        """Test no detection for short connections."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=uuid4(),
            window_start=now - timedelta(seconds=60),
            window_end=now,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            max_duration=300.0,  # 5 minutes
            avg_duration=120.0,
            total_bytes_sent=1024,
            total_bytes_received=2048,
        )

        detector = LongConnectionDetector()
        result = detector.detect(vector)

        assert result.matched is False


class TestDetectionManager:
    """Tests for DetectionManager class."""

    def test_process_feature_vector(self, sample_feature_vector: FeatureVector) -> None:
        """Test processing a feature vector."""
        manager = DetectionManager()
        detector = PortScanDetector()
        manager.register_detector(detector)

        results = manager.process_feature_vector(sample_feature_vector)
        assert isinstance(results, list)

    def test_multiple_detectors(self, sample_feature_vector: FeatureVector) -> None:
        """Test processing with multiple detectors."""
        manager = DetectionManager()
        manager.register_detector(PortScanDetector())
        manager.register_detector(HorizontalScanDetector())
        manager.register_detector(SynScanDetector())

        results = manager.process_feature_vector(sample_feature_vector)
        assert len(results) == 3  # One result per detector

    def test_statistics(self, sample_feature_vector: FeatureVector) -> None:
        """Test detection manager statistics."""
        manager = DetectionManager()
        manager.register_detector(PortScanDetector())

        manager.process_feature_vector(sample_feature_vector)
        stats = manager.get_statistics()

        assert stats["processed_count"] == 1
        assert stats["detector_count"] == 1
        assert stats["enabled_detector_count"] == 1
