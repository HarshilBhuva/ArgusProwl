"""Tests for temporal engine and beaconing detector."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from argusprowl.detection.detectors.beaconing_detector import BeaconingDetector
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.temporal.engine import TemporalEngine
from argusprowl.temporal.periodicity import (
    calculate_coefficient_of_variation,
    calculate_periodicity_score,
    classify_periodicity,
)
from argusprowl.temporal.temporal_state import TemporalBucket, TemporalObservation

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    dst_ip: str = "203.0.113.10",
    dst_port: int = 8443,
    src_ip: str | None = "192.168.1.1",
    timestamp: datetime | None = None,
    process_name: str | None = None,
    protocol: str | None = "TCP",
    attributes: dict[str, Any] | None = None,
) -> NormalizedEvent:
    """Create a minimal NormalizedEvent for temporal testing."""
    attrs = {"direction": "outbound"}
    if attributes is not None:
        attrs.update(attributes)
    return NormalizedEvent(
        source_type="zeek",
        event_type="network_connection",
        timestamp=timestamp or datetime.now(UTC),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=54321,
        dst_port=dst_port,
        protocol=protocol,
        process_name=process_name,
        attributes=attrs,
    )


def _make_observations(
    count: int,
    interval_seconds: float,
    dst_ip: str = "203.0.113.10",
    dst_port: int = 443,
    start_time: datetime | None = None,
) -> list[NormalizedEvent]:
    """Create a list of observations with regular intervals."""
    base = start_time or datetime.now(UTC)
    return [
        _make_event(
            dst_ip=dst_ip,
            dst_port=dst_port,
            timestamp=base + timedelta(seconds=i * interval_seconds),
        )
        for i in range(count)
    ]


def _make_irregular_observations(
    count: int,
    dst_ip: str = "203.0.113.10",
    dst_port: int = 443,
    start_time: datetime | None = None,
) -> list[NormalizedEvent]:
    """Create observations with irregular intervals."""
    base = start_time or datetime.now(UTC)
    # Irregular intervals: 10, 50, 5, 80, 15, 70, 8, 60, 12, 55
    intervals = [10, 50, 5, 80, 15, 70, 8, 60, 12, 55]
    return [
        _make_event(
            dst_ip=dst_ip,
            dst_port=dst_port,
            timestamp=base + timedelta(seconds=sum(intervals[: i + 1])),
        )
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# TemporalObservation tests
# ---------------------------------------------------------------------------


class TestTemporalObservation:
    def test_creates_with_required_fields(self) -> None:
        obs = TemporalObservation(
            event_id=uuid4(),
            timestamp=datetime.now(UTC),
            dst_ip="1.2.3.4",
            dst_port=443,
        )
        assert obs.dst_ip == "1.2.3.4"
        assert obs.dst_port == 443
        assert obs.src_ip is None
        assert obs.process_name is None

    def test_creates_with_optional_fields(self) -> None:
        obs = TemporalObservation(
            event_id=uuid4(),
            timestamp=datetime.now(UTC),
            dst_ip="1.2.3.4",
            dst_port=80,
            src_ip="5.6.7.8",
            process_name="chrome",
            protocol="TCP",
        )
        assert obs.src_ip == "5.6.7.8"
        assert obs.process_name == "chrome"
        assert obs.protocol == "TCP"


# ---------------------------------------------------------------------------
# TemporalBucket tests
# ---------------------------------------------------------------------------


class TestTemporalBucket:
    def test_empty_bucket(self) -> None:
        bucket = TemporalBucket(key=("1.2.3.4", 443))
        assert len(bucket) == 0
        stats = bucket.get_stats()
        assert stats["count"] == 0
        assert stats["intervals"] == []

    def test_single_observation(self) -> None:
        bucket = TemporalBucket(key=("1.2.3.4", 443))
        obs = TemporalObservation(
            event_id=uuid4(),
            timestamp=datetime.now(UTC),
            dst_ip="1.2.3.4",
            dst_port=443,
        )
        bucket.add(obs)
        assert len(bucket) == 1
        assert bucket.get_interval_seconds() == []

    def test_two_observations(self) -> None:
        bucket = TemporalBucket(key=("1.2.3.4", 443))
        now = datetime.now(UTC)
        obs1 = TemporalObservation(event_id=uuid4(), timestamp=now, dst_ip="1.2.3.4", dst_port=443)
        obs2 = TemporalObservation(
            event_id=uuid4(), timestamp=now + timedelta(seconds=60), dst_ip="1.2.3.4", dst_port=443
        )
        bucket.add(obs1)
        bucket.add(obs2)
        assert len(bucket) == 2
        intervals = bucket.get_interval_seconds()
        assert len(intervals) == 1
        assert intervals[0] == 60.0

    def test_interval_calculation(self) -> None:
        bucket = TemporalBucket(key=("1.2.3.4", 443))
        now = datetime.now(UTC)
        for i in range(5):
            obs = TemporalObservation(
                event_id=uuid4(),
                timestamp=now + timedelta(seconds=i * 10),
                dst_ip="1.2.3.4",
                dst_port=443,
            )
            bucket.add(obs)
        intervals = bucket.get_interval_seconds()
        assert len(intervals) == 4
        assert all(iv == 10.0 for iv in intervals)

    def test_mean_interval(self) -> None:
        bucket = TemporalBucket(key=("1.2.3.4", 443))
        now = datetime.now(UTC)
        for i in range(5):
            obs = TemporalObservation(
                event_id=uuid4(),
                timestamp=now + timedelta(seconds=i * 30),
                dst_ip="1.2.3.4",
                dst_port=443,
            )
            bucket.add(obs)
        stats = bucket.get_stats()
        assert stats["mean_interval"] == 30.0

    def test_window_expiration(self) -> None:
        bucket = TemporalBucket(
            key=("1.2.3.4", 443),
            window_duration=timedelta(seconds=100),
        )
        now = datetime.now(UTC)
        # Add old observation
        old_obs = TemporalObservation(
            event_id=uuid4(),
            timestamp=now - timedelta(seconds=200),
            dst_ip="1.2.3.4",
            dst_port=443,
        )
        bucket.add(old_obs)
        # Add recent observation
        new_obs = TemporalObservation(
            event_id=uuid4(),
            timestamp=now,
            dst_ip="1.2.3.4",
            dst_port=443,
        )
        bucket.add(new_obs)
        # Old observation should be expired
        assert len(bucket) == 1

    def test_max_observation_bound(self) -> None:
        bucket = TemporalBucket(
            key=("1.2.3.4", 443),
            max_observations=5,
        )
        now = datetime.now(UTC)
        for i in range(10):
            obs = TemporalObservation(
                event_id=uuid4(),
                timestamp=now + timedelta(seconds=i),
                dst_ip="1.2.3.4",
                dst_port=443,
            )
            bucket.add(obs)
        assert len(bucket) == 5

    def test_stats_serialization(self) -> None:
        bucket = TemporalBucket(key=("1.2.3.4", 443))
        now = datetime.now(UTC)
        for i in range(3):
            obs = TemporalObservation(
                event_id=uuid4(),
                timestamp=now + timedelta(seconds=i * 10),
                dst_ip="1.2.3.4",
                dst_port=443,
            )
            bucket.add(obs)
        stats = bucket.get_stats()
        assert "first_seen" in stats
        assert "last_seen" in stats
        assert "duration_seconds" in stats
        assert "periodicity_score" not in stats  # That's in the engine


# ---------------------------------------------------------------------------
# Periodicity calculation tests
# ---------------------------------------------------------------------------


class TestPeriodicity:
    def test_empty_intervals(self) -> None:
        assert calculate_periodicity_score([]) == 0.0

    def test_single_interval(self) -> None:
        assert calculate_periodicity_score([10.0]) == 0.0

    def test_perfectly_periodic(self) -> None:
        intervals = [10.0, 10.0, 10.0, 10.0, 10.0]
        score = calculate_periodicity_score(intervals)
        assert score > 0.9  # Very high periodicity

    def test_low_periodicity(self) -> None:
        intervals = [1.0, 100.0, 2.0, 90.0, 3.0]
        score = calculate_periodicity_score(intervals)
        assert score < 0.5  # Low periodicity

    def test_moderate_periodicity(self) -> None:
        intervals = [10.0, 12.0, 9.0, 11.0, 10.5]
        score = calculate_periodicity_score(intervals)
        assert 0.5 < score < 0.9

    def test_coefficient_of_variation(self) -> None:
        assert calculate_coefficient_of_variation(0.0, 10.0) == 0.0
        assert calculate_coefficient_of_variation(1.0, 10.0) == 0.1
        assert calculate_coefficient_of_variation(5.0, 10.0) == 0.5

    def test_classify_none(self) -> None:
        assert classify_periodicity(0.0) == "none"
        assert classify_periodicity(0.2) == "none"

    def test_classify_low(self) -> None:
        assert classify_periodicity(0.4) == "low"

    def test_classify_moderate(self) -> None:
        assert classify_periodicity(0.6) == "moderate"

    def test_classify_high(self) -> None:
        assert classify_periodicity(0.8) == "high"

    def test_classify_very_high(self) -> None:
        assert classify_periodicity(0.95) == "very_high"


# ---------------------------------------------------------------------------
# TemporalEngine tests
# ---------------------------------------------------------------------------


class TestTemporalEngine:
    def test_empty_engine(self) -> None:
        engine = TemporalEngine()
        assert engine.get_key_count() == 0
        assert engine.get_analysis("1.2.3.4", 443) is None

    def test_single_observation(self) -> None:
        engine = TemporalEngine()
        event = _make_event()
        engine.observe(event)
        assert engine.get_key_count() == 1
        # Should not have enough for analysis
        assert engine.get_analysis("203.0.113.10", 443) is None

    def test_two_observations(self) -> None:
        engine = TemporalEngine()
        now = datetime.now(UTC)
        event1 = _make_event(timestamp=now)
        event2 = _make_event(timestamp=now + timedelta(seconds=60))
        engine.observe(event1)
        engine.observe(event2)
        assert engine.get_key_count() == 1
        analysis = engine.get_analysis("203.0.113.10", 8443)
        assert analysis is not None
        assert analysis["count"] == 2

    def test_interval_calculation(self) -> None:
        engine = TemporalEngine()
        now = datetime.now(UTC)
        for i in range(5):
            event = _make_event(timestamp=now + timedelta(seconds=i * 10))
            engine.observe(event)
        analysis = engine.get_analysis("203.0.113.10", 8443)
        assert analysis["mean_interval"] == 10.0

    def test_max_keys_bound(self) -> None:
        engine = TemporalEngine(max_keys=3)
        for i in range(10):
            event = _make_event(dst_ip=f"10.0.0.{i}", dst_port=443)
            engine.observe(event)
        assert engine.get_key_count() == 3

    def test_deterministic_eviction(self) -> None:
        engine = TemporalEngine(max_keys=2)
        # Add 3 events to different destinations
        event1 = _make_event(dst_ip="1.1.1.1", dst_port=443)
        event2 = _make_event(dst_ip="2.2.2.2", dst_port=443)
        event3 = _make_event(dst_ip="3.3.3.3", dst_port=443)
        engine.observe(event1)
        engine.observe(event2)
        engine.observe(event3)
        # First added (1.1.1.1) should be evicted (LRU policy)
        # Only 2 keys should remain
        assert engine.get_key_count() == 2
        # Evicted key should not be accessible
        assert engine.get_analysis("1.1.1.1", 443) is None

    def test_window_expiration(self) -> None:
        engine = TemporalEngine(window_duration=timedelta(seconds=10))
        now = datetime.now(UTC)
        # Add old event
        old_event = _make_event(dst_ip="1.1.1.1", timestamp=now - timedelta(seconds=100))
        engine.observe(old_event)
        # Add recent event to same destination
        new_event = _make_event(dst_ip="1.1.1.1", timestamp=now)
        engine.observe(new_event)
        # Old event should be expired (bucket should have only 1 observation)
        analysis = engine.get_analysis("1.1.1.1", 443)
        assert analysis is None  # Single observation, no analysis
        # Key should still exist
        assert engine.get_key_count() == 1

    def test_clear(self) -> None:
        engine = TemporalEngine()
        engine.observe(_make_event())
        assert engine.get_key_count() == 1
        engine.clear()
        assert engine.get_key_count() == 0

    def test_no_dst_ip(self) -> None:
        engine = TemporalEngine()
        event = _make_event(dst_ip=None)
        engine.observe(event)
        assert engine.get_key_count() == 0

    def test_get_all_analyses(self) -> None:
        engine = TemporalEngine()
        now = datetime.now(UTC)
        # Add regular observations to one destination
        for i in range(5):
            engine.observe(_make_event(timestamp=now + timedelta(seconds=i * 10), dst_ip="1.1.1.1"))
        # Add regular observations to another
        for i in range(5):
            engine.observe(_make_event(timestamp=now + timedelta(seconds=i * 10), dst_ip="2.2.2.2"))
        analyses = engine.get_all_analyses()
        assert len(analyses) == 2


# ---------------------------------------------------------------------------
# BeaconingDetector tests
# ---------------------------------------------------------------------------


class TestBeaconingDetector:
    def test_no_match_insufficient_observations(self) -> None:
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=10,
        )
        event = _make_event()
        engine.observe(event)
        result = detector.detect(event)
        assert not result.matched

    def test_no_match_insufficient_duration(self) -> None:
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=2,
            min_duration_seconds=300.0,
        )
        now = datetime.now(UTC)
        # Add 2 observations 10 seconds apart
        engine.observe(_make_event(timestamp=now))
        engine.observe(_make_event(timestamp=now + timedelta(seconds=10)))
        result = detector.detect(_make_event(timestamp=now + timedelta(seconds=20)))
        assert not result.matched

    def test_no_match_low_periodicity(self) -> None:
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=2,
            min_duration_seconds=1.0,
            periodicity_threshold=0.9,
        )
        now = datetime.now(UTC)
        # Add irregular observations
        for i, _interval in enumerate([1, 100, 2, 90, 3]):
            engine.observe(
                _make_event(timestamp=now + timedelta(seconds=sum([1, 100, 2, 90, 3][: i + 1])))
            )
        result = detector.detect(_make_event(timestamp=now + timedelta(seconds=200)))
        assert not result.matched

    def test_match_regular_beacon(self) -> None:
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=10,
            min_duration_seconds=1.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.3,
        )
        now = datetime.now(UTC)
        # Add regular 60-second beacon
        for i in range(15):
            engine.observe(_make_event(timestamp=now + timedelta(seconds=i * 60)))
        # Trigger detection
        event = _make_event(timestamp=now + timedelta(seconds=15 * 60))
        result = detector.detect(event)
        assert result.matched
        assert result.rule_id == "TH-NET-BEACON-001"
        assert result.confidence >= 0.5
        assert len(result.evidence) > 0
        assert result.evidence[0]["field"] == "destination"

    def test_match_slightly_jittered_beacon(self) -> None:
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=10,
            min_duration_seconds=1.0,
            periodicity_threshold=0.5,
        )
        now = datetime.now(UTC)
        # Add slightly jittered observations (±10% around 60s)
        import random

        random.seed(42)
        for i in range(15):
            jitter = random.uniform(-6, 6)
            engine.observe(
                _make_event(dst_port=8443, timestamp=now + timedelta(seconds=i * 60 + jitter))
            )
        event = _make_event(dst_port=8443, timestamp=now + timedelta(seconds=15 * 60))
        result = detector.detect(event)
        assert result.matched

    def test_evidence_structure(self) -> None:
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=10,
            min_duration_seconds=1.0,
        )
        now = datetime.now(UTC)
        for i in range(15):
            engine.observe(_make_event(timestamp=now + timedelta(seconds=i * 60)))
        event = _make_event(timestamp=now + timedelta(seconds=15 * 60))
        result = detector.detect(event)
        # Check evidence fields
        evidence_fields = {e["field"] for e in result.evidence}
        assert "destination" in evidence_fields
        assert "destination_port" in evidence_fields
        assert "observation_count" in evidence_fields
        assert "periodicity_score" in evidence_fields
        assert "mean_interval" in evidence_fields

    def test_detection_result_serialization(self) -> None:
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=10,
            min_duration_seconds=1.0,
        )
        now = datetime.now(UTC)
        for i in range(15):
            engine.observe(_make_event(timestamp=now + timedelta(seconds=i * 60)))
        event = _make_event(timestamp=now + timedelta(seconds=15 * 60))
        result = detector.detect(event)
        # Should serialize without error
        d = result.to_dict()
        assert d["rule_id"] == "TH-NET-BEACON-001"
        assert d["matched"] is True

    def test_no_match_no_dst_ip(self) -> None:
        engine = TemporalEngine()
        detector = BeaconingDetector(temporal_engine=engine)
        event = _make_event(dst_ip=None)
        result = detector.detect(event)
        assert not result.matched

    def test_properties(self) -> None:
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=5,
            min_duration_seconds=100.0,
            periodicity_threshold=0.8,
            confidence_threshold=0.7,
            version=2,
        )
        assert detector.name == "beaconing_detector"
        assert detector.rule_id == "TH-NET-BEACON-001"
        assert detector.version == 2
        assert detector.is_enabled() is True
        assert detector.detections_count == 0


# ---------------------------------------------------------------------------
# False positive tests
# ---------------------------------------------------------------------------


class TestFalsePositives:
    def test_benign_1_regular_service_polling(self) -> None:
        """BENIGN 1 — Regular service polling.

        same process, same destination, every 60s.
        Expected: high periodicity, LOW C2 confidence, no high-severity alert.
        """
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=10,
            min_duration_seconds=60.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.8,  # High threshold for strong alert
        )
        now = datetime.now(UTC)
        # Regular 60-second polling to HTTP port (80)
        for i in range(15):
            engine.observe(
                _make_event(
                    dst_ip="10.0.0.1",
                    dst_port=80,
                    timestamp=now + timedelta(seconds=i * 60),
                    process_name="updater.exe",
                )
            )
        event = _make_event(
            dst_ip="10.0.0.1",
            dst_port=80,
            timestamp=now + timedelta(seconds=15 * 60),
            process_name="updater.exe",
        )
        result = detector.detect(event)
        # Should not match strong alert threshold due to negative evidence (port 80)
        assert not result.matched or result.confidence < 0.8

    def test_benign_2_regular_https(self) -> None:
        """BENIGN 2 — Regular HTTPS.

        process -> HTTPS -> same destination -> every 60s.
        Expected: periodic = true, C2 confidence remains below strong-alert threshold.
        """
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=10,
            min_duration_seconds=60.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.8,
        )
        now = datetime.now(UTC)
        for i in range(15):
            engine.observe(
                _make_event(
                    dst_ip="142.250.80.46",
                    dst_port=443,
                    timestamp=now + timedelta(seconds=i * 60),
                    process_name="chrome.exe",
                )
            )
        event = _make_event(
            dst_ip="142.250.80.46",
            dst_port=443,
            timestamp=now + timedelta(seconds=15 * 60),
            process_name="chrome.exe",
        )
        result = detector.detect(event)
        # Should not match strong alert threshold due to negative evidence (port 443)
        assert not result.matched or result.confidence < 0.8

    def test_benign_3_irregular_network_activity(self) -> None:
        """BENIGN 3 — Irregular network activity.

        Expected: low periodicity, no strong beaconing detection.
        """
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=5,
            min_duration_seconds=60.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.5,
        )
        now = datetime.now(UTC)
        # Irregular intervals
        intervals = [10, 47, 133, 22, 91]
        cumulative = 0
        for _i, interval in enumerate(intervals):
            cumulative += interval
            engine.observe(
                _make_event(
                    dst_ip="93.184.216.34",
                    dst_port=443,
                    timestamp=now + timedelta(seconds=cumulative),
                    process_name="firefox.exe",
                )
            )
        event = _make_event(
            dst_ip="93.184.216.34",
            dst_port=443,
            timestamp=now + timedelta(seconds=cumulative + 50),
            process_name="firefox.exe",
        )
        result = detector.detect(event)
        assert not result.matched

    def test_benign_4_insufficient_observations(self) -> None:
        """BENIGN 4 — Insufficient observations.

        Expected: insufficient evidence, no high-confidence detection.
        """
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=10,
            min_duration_seconds=60.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.5,
        )
        now = datetime.now(UTC)
        # Only 3 observations
        for i in range(3):
            engine.observe(
                _make_event(
                    dst_ip="203.0.113.50",
                    dst_port=8443,
                    timestamp=now + timedelta(seconds=i * 60),
                    process_name="malware.exe",
                )
            )
        event = _make_event(
            dst_ip="203.0.113.50",
            dst_port=8443,
            timestamp=now + timedelta(seconds=3 * 60),
            process_name="malware.exe",
        )
        result = detector.detect(event)
        assert not result.matched

    def test_benign_ntp_traffic(self) -> None:
        """NTP is highly periodic but benign."""
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=10,
            min_duration_seconds=60.0,
            periodicity_threshold=0.9,
            confidence_threshold=0.5,
        )
        now = datetime.now(UTC)
        # NTP polls every 64 seconds with very low jitter
        for i in range(15):
            engine.observe(
                _make_event(
                    dst_ip="129.6.15.28",  # NTP server
                    dst_port=123,
                    timestamp=now + timedelta(seconds=i * 64),
                    process_name="ntpd",
                )
            )
        event = _make_event(
            dst_ip="129.6.15.28",
            dst_port=123,
            timestamp=now + timedelta(seconds=15 * 64),
            process_name="ntpd",
        )
        result = detector.detect(event)
        # NTP port 123 subtracts 0.5 confidence, so it should not match
        assert not result.matched


# ---------------------------------------------------------------------------
# Positive tests
# ---------------------------------------------------------------------------


class TestPositiveScenarios:
    def test_positive_1_stable_beacon(self) -> None:
        """POSITIVE 1 — Stable beacon.

        same host, process, destination, regular intervals, many observations.
        Expected: strong beaconing evidence.
        """
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=10,
            min_duration_seconds=60.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.6,
        )
        now = datetime.now(UTC)
        # Very regular 60-second beacon to suspicious destination
        for i in range(20):
            engine.observe(
                _make_event(
                    dst_ip="203.0.113.50",
                    dst_port=8443,
                    timestamp=now + timedelta(seconds=i * 60),
                    process_name="svchost.exe",
                    attributes={"direction": "outbound"},
                )
            )
        event = _make_event(
            dst_ip="203.0.113.50",
            dst_port=8443,
            timestamp=now + timedelta(seconds=20 * 60),
            process_name="svchost.exe",
            attributes={"direction": "outbound"},
        )
        result = detector.detect(event)
        assert result.matched
        assert result.confidence >= 0.7  # High confidence due to process + outbound + many obs
        assert result.evidence[0]["observed"] == "203.0.113.50"
        assert result.evidence[1]["observed"] == 8443

    def test_positive_2_jittered_beacon(self) -> None:
        """POSITIVE 2 — Jittered beacon.

        Expected: strong periodicity, positive beaconing assessment.
        """
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=5,
            min_duration_seconds=60.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.5,
        )
        now = datetime.now(UTC)
        # Jittered intervals: 60s, 63s, 58s, 61s, 65s, 59s
        intervals = [60, 63, 58, 61, 65, 59]
        cumulative = 0
        for _i, interval in enumerate(intervals):
            cumulative += interval
            engine.observe(
                _make_event(
                    dst_ip="203.0.113.50",
                    dst_port=8443,
                    timestamp=now + timedelta(seconds=cumulative),
                    process_name="malware.exe",
                )
            )
        event = _make_event(
            dst_ip="203.0.113.50",
            dst_port=8443,
            timestamp=now + timedelta(seconds=cumulative + 60),
            process_name="malware.exe",
        )
        result = detector.detect(event)
        assert result.matched
        assert result.confidence >= 0.5

    def test_positive_3_process_correlated_beacon(self) -> None:
        """POSITIVE 3 — Process-correlated beacon.

        Expected: stronger confidence than periodic network behavior alone.
        """
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=10,
            min_duration_seconds=60.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.5,
        )
        now = datetime.now(UTC)

        # Scenario A: No process attribution
        for i in range(15):
            engine.observe(
                _make_event(
                    dst_ip="203.0.113.50",
                    dst_port=8443,
                    timestamp=now + timedelta(seconds=i * 60),
                    process_name=None,
                )
            )
        event_a = _make_event(
            dst_ip="203.0.113.50",
            dst_port=8443,
            timestamp=now + timedelta(seconds=15 * 60),
            process_name=None,
        )
        result_a = detector.detect(event_a)

        engine.clear()

        # Scenario B: With process attribution
        for i in range(15):
            engine.observe(
                _make_event(
                    dst_ip="203.0.113.50",
                    dst_port=8443,
                    timestamp=now + timedelta(seconds=i * 60),
                    process_name="malware.exe",
                )
            )
        event_b = _make_event(
            dst_ip="203.0.113.50",
            dst_port=8443,
            timestamp=now + timedelta(seconds=15 * 60),
            process_name="malware.exe",
        )
        result_b = detector.detect(event_b)

        assert result_a.matched
        assert result_b.matched
        # Process attribution should increase confidence
        assert result_b.confidence > result_a.confidence


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_replay_compatibility(self) -> None:
        """Temporal engine works the same in replay and live mode."""
        engine = TemporalEngine()
        detector = BeaconingDetector(
            temporal_engine=engine,
            min_observations=10,
            min_duration_seconds=1.0,
        )
        now = datetime.now(UTC)
        # Simulate replay: add events in order
        for i in range(15):
            event = _make_event(timestamp=now + timedelta(seconds=i * 60))
            engine.observe(event)
            result = detector.detect(event)
        # Last event should trigger
        assert result.matched

    def test_concurrent_observation(self) -> None:
        """Temporal engine handles concurrent observations safely."""
        import threading

        engine = TemporalEngine(max_keys=100)
        threads = []
        for t in range(10):

            def observe(worker_index: int = t) -> None:
                for i in range(20):
                    engine.observe(_make_event(dst_ip=f"10.0.{worker_index}.{i % 256}"))

            threads.append(threading.Thread(target=observe))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert engine.get_key_count() == 100  # Capped at max_keys
