"""Regression tests for source-event provenance on aggregate detections."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.detectors.port_scan import PortScanDetector
from argusprowl.feature_engineering.feature_extractor import FeatureExtractor
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.models.normalized_event import NormalizedEvent


def _network_event(timestamp: datetime, destination: str, port: int) -> NormalizedEvent:
    return NormalizedEvent(
        source_type="zeek",
        event_type="network_connection",
        timestamp=timestamp,
        src_ip="192.0.2.10",
        src_port=41000 + port,
        dst_ip=destination,
        dst_port=port,
        protocol="tcp",
    )


def test_feature_extractor_preserves_window_contributor_event_ids() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    events = [
        _network_event(start + timedelta(seconds=index), f"198.51.100.{index + 1}", 1000 + index)
        for index in range(3)
    ]
    extractor = FeatureExtractor(window_size_seconds=60, max_events_per_window=100)

    vector = None
    for event in events:
        vector = extractor.extract(event)

    assert vector is not None
    assert vector.event_id == events[-1].event_id
    assert vector.contributing_event_ids == tuple(event.event_id for event in events[:-1])
    assert vector.event_id not in vector.contributing_event_ids


def test_feature_vector_detector_uses_real_source_event_id_and_contributors() -> None:
    source_event_id = uuid4()
    contributor_ids = (uuid4(), uuid4())
    now = datetime(2026, 1, 1, tzinfo=UTC)
    vector = FeatureVector(
        event_id=source_event_id,
        contributing_event_ids=contributor_ids,
        window_start=now - timedelta(seconds=60),
        window_end=now,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        connection_count=20,
        unique_dst_ports=12,
        unique_dst_ips=4,
        connection_rate=3.0,
        port_concentration=0.2,
    )
    manager = DetectionManager()
    manager.register_detector(PortScanDetector(min_unique_ports=10, min_connection_rate=1.0))

    results = manager.process_feature_vector(vector)

    assert len(results) == 1
    assert results[0].matched is True
    assert results[0].event_id == source_event_id
    assert results[0].event_id != vector.vector_id
    assert results[0].contributing_event_ids == contributor_ids
