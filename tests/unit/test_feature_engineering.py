"""Tests for feature engineering module."""

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from argusprowl.feature_engineering.aggregators import (
    aggregate_by_dst_ip,
    aggregate_by_dst_port,
    aggregate_by_src_ip,
    aggregate_connection_features,
)
from argusprowl.feature_engineering.feature_extractor import FeatureExtractor
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.feature_engineering.sliding_window import SlidingWindow
from argusprowl.feature_engineering.statistics import (
    calculate_concentration,
    calculate_entropy,
    calculate_mean,
    calculate_min_max,
    calculate_percentile,
    calculate_rate,
    calculate_std_dev,
)
from argusprowl.models.normalized_event import NormalizedEvent


@pytest.fixture
def sample_normalized_event() -> NormalizedEvent:
    """Create a sample NormalizedEvent for testing."""
    return NormalizedEvent(
        source_type="zeek",
        event_type="network_connection",
        timestamp=datetime.now(UTC),
        src_ip="192.168.1.100",
        src_port=12345,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="tcp",
        attributes={
            "uid": "C12345",
            "service": "http",
            "duration": 1.5,
            "orig_bytes": 1024,
            "resp_bytes": 2048,
            "conn_state": "SF",
            "history": "ShADadfF",
            "orig_pkts": 10,
            "resp_pkts": 8,
        },
    )


@pytest.fixture
def sample_normalized_events() -> list[NormalizedEvent]:
    """Create multiple sample NormalizedEvents for testing."""
    base_time = datetime.now(UTC)
    events = []
    for i in range(5):
        event = NormalizedEvent(
            source_type="zeek",
            event_type="network_connection",
            timestamp=base_time + timedelta(seconds=i),
            src_ip="192.168.1.100",
            src_port=12345 + i,
            dst_ip=f"10.0.0.{i + 1}",
            dst_port=[80, 443, 22, 8080, 3306][i],
            protocol="tcp",
            attributes={
                "uid": f"C{i + 1}",
                "service": ["http", "https", "ssh", "http", "mysql"][i],
                "duration": 1.0 + i * 0.5,
                "orig_bytes": 1024 * (i + 1),
                "resp_bytes": 2048 * (i + 1),
                "conn_state": "SF",
                "history": "ShADadfF",
                "orig_pkts": 10 + i,
                "resp_pkts": 8 + i,
            },
        )
        events.append(event)
    return events


class TestStatistics:
    """Tests for statistical calculation functions."""

    def test_calculate_mean_empty(self) -> None:
        """Test mean of empty sequence."""
        assert calculate_mean([]) == 0.0

    def test_calculate_mean_single_value(self) -> None:
        """Test mean of single value."""
        assert calculate_mean([5.0]) == 5.0

    def test_calculate_mean_multiple_values(self) -> None:
        """Test mean of multiple values."""
        assert calculate_mean([1.0, 2.0, 3.0, 4.0, 5.0]) == 3.0

    def test_calculate_std_dev_empty(self) -> None:
        """Test std dev of empty sequence."""
        assert calculate_std_dev([]) == 0.0

    def test_calculate_std_dev_single_value(self) -> None:
        """Test std dev of single value."""
        assert calculate_std_dev([5.0]) == 0.0

    def test_calculate_std_dev_multiple_values(self) -> None:
        """Test std dev of multiple values."""
        values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
        mean = calculate_mean(values)
        std = calculate_std_dev(values, mean)
        assert abs(std - 2.0) < 0.01  # Approximately 2.0

    def test_calculate_min_max_empty(self) -> None:
        """Test min/max of empty sequence."""
        min_val, max_val = calculate_min_max([])
        assert min_val == 0.0
        assert max_val == 0.0

    def test_calculate_min_max_values(self) -> None:
        """Test min/max calculation."""
        min_val, max_val = calculate_min_max([3.0, 1.0, 4.0, 1.0, 5.0])
        assert min_val == 1.0
        assert max_val == 5.0

    def test_calculate_percentile_empty(self) -> None:
        """Test percentile of empty sequence."""
        assert calculate_percentile([], 50) == 0.0

    def test_calculate_percentile_median(self) -> None:
        """Test median calculation."""
        assert calculate_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 50) == 3.0

    def test_calculate_entropy_empty(self) -> None:
        """Test entropy of empty sequence."""
        assert calculate_entropy([]) == 0.0

    def test_calculate_entropy_uniform(self) -> None:
        """Test entropy of uniform distribution."""
        # Uniform distribution has maximum entropy
        entropy = calculate_entropy([1, 1, 1, 1])
        assert entropy > 0

    def test_calculate_entropy_skewed(self) -> None:
        """Test entropy of skewed distribution."""
        # Skewed distribution has lower entropy
        entropy = calculate_entropy([10, 1, 1, 1])
        assert entropy > 0

    def test_calculate_concentration_empty(self) -> None:
        """Test concentration of empty dict."""
        assert calculate_concentration({}) == 0.0

    def test_calculate_concentration_uniform(self) -> None:
        """Test concentration of uniform distribution."""
        assert calculate_concentration({"a": 1, "b": 1, "c": 1}) == pytest.approx(1 / 3)

    def test_calculate_concentration_skewed(self) -> None:
        """Test concentration of skewed distribution."""
        assert calculate_concentration({"a": 10, "b": 1, "c": 1}) == pytest.approx(10 / 12)

    def test_calculate_rate_zero_window(self) -> None:
        """Test rate with zero window."""
        assert calculate_rate(10, 0) == 0.0

    def test_calculate_rate_negative_window(self) -> None:
        """Test rate with negative window."""
        assert calculate_rate(10, -5) == 0.0

    def test_calculate_rate_normal(self) -> None:
        """Test rate calculation."""
        assert calculate_rate(100, 10) == 10.0


class TestSlidingWindow:
    """Tests for SlidingWindow class."""

    def test_init_invalid_window_size(self) -> None:
        """Test initialization with invalid window size."""
        with pytest.raises(ValueError):
            SlidingWindow(window_size_seconds=0)

        with pytest.raises(ValueError):
            SlidingWindow(window_size_seconds=-5)

    def test_add_and_get_events(self, sample_normalized_event: NormalizedEvent) -> None:
        """Test adding and retrieving events."""
        window = SlidingWindow(window_size_seconds=60.0)
        window.add(sample_normalized_event)
        events = window.get_events()
        assert len(events) == 1
        assert events[0].attributes["uid"] == sample_normalized_event.attributes["uid"]

    def test_event_eviction(self) -> None:
        """Test automatic eviction of expired events."""
        window = SlidingWindow(window_size_seconds=1.0)  # 1 second window

        # Add event at time T
        event1 = NormalizedEvent(
            source_type="zeek",
            event_type="connection",
            timestamp=datetime.now(UTC),
            attributes={"uid": "C1"},
            src_ip="192.168.1.1",
        )
        window.add(event1)

        # Add event at time T+2 (should evict first)
        time.sleep(0.1)
        event2 = NormalizedEvent(
            source_type="zeek",
            event_type="connection",
            timestamp=datetime.now(UTC),
            attributes={"uid": "C2"},
            src_ip="192.168.1.1",
        )
        window.add(event2)

        # First event should be evicted
        events = window.get_events()
        assert len(events) == 1
        assert events[0].attributes["uid"] == "C2"

    def test_max_events_limit(self) -> None:
        """Test max_events limit enforcement."""
        window = SlidingWindow(window_size_seconds=3600.0, max_events=3)

        for i in range(5):
            event = NormalizedEvent(
                source_type="zeek",
                event_type="connection",
                timestamp=datetime.now(UTC),
                attributes={"uid": f"C{i}"},
                src_ip="192.168.1.1",
            )
            window.add(event)

        events = window.get_events()
        assert len(events) == 3
        assert events[0].attributes["uid"] == "C2"  # First two should be evicted
        assert events[-1].attributes["uid"] == "C4"

    def test_clear_window(self, sample_normalized_event: NormalizedEvent) -> None:
        """Test clearing window."""
        window = SlidingWindow(window_size_seconds=60.0)
        window.add(sample_normalized_event)
        window.clear()
        assert window.is_empty
        assert len(window) == 0

    def test_thread_safety(self, sample_normalized_event: NormalizedEvent) -> None:
        """Test thread-safe operations."""
        window = SlidingWindow(window_size_seconds=60.0)

        def add_events():
            for _ in range(100):
                window.add(sample_normalized_event)

        threads = [threading.Thread(target=add_events) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All events should be present
        assert len(window) == 500

    def test_aggregate(self, sample_normalized_events: list[NormalizedEvent]) -> None:
        """Test aggregation function."""
        window = SlidingWindow(window_size_seconds=3600.0)
        for event in sample_normalized_events:
            window.add(event)

        result = window.aggregate(aggregate_connection_features)
        assert result["connection_count"] == 5
        assert result["unique_dst_ips"] == 5


class TestAggregators:
    """Tests for aggregation functions."""

    def test_aggregate_connection_features_empty(self) -> None:
        """Test aggregation with empty event list."""
        result = aggregate_connection_features([])
        assert result == {}

    def test_aggregate_connection_features_single(
        self, sample_normalized_event: NormalizedEvent
    ) -> None:
        """Test aggregation with single event."""
        result = aggregate_connection_features([sample_normalized_event])
        assert result["connection_count"] == 1
        assert result["unique_dst_ports"] == 1
        assert result["unique_dst_ips"] == 1

    def test_aggregate_connection_features_multiple(
        self, sample_normalized_events: list[NormalizedEvent]
    ) -> None:
        """Test aggregation with multiple events."""
        result = aggregate_connection_features(sample_normalized_events)
        assert result["connection_count"] == 5
        assert result["unique_dst_ports"] == 5
        assert result["unique_dst_ips"] == 5
        assert result["total_bytes_sent"] > 0
        assert result["connection_rate"] > 0

    def test_aggregate_by_src_ip(self, sample_normalized_events: list[NormalizedEvent]) -> None:
        """Test grouping by source IP."""
        result = aggregate_by_src_ip(sample_normalized_events)
        assert len(result) == 1
        assert "192.168.1.100" in result
        assert len(result["192.168.1.100"]) == 5

    def test_aggregate_by_dst_port(self, sample_normalized_events: list[NormalizedEvent]) -> None:
        """Test grouping by destination port."""
        result = aggregate_by_dst_port(sample_normalized_events)
        assert len(result) == 5
        assert 80 in result
        assert 443 in result

    def test_aggregate_by_dst_ip(self, sample_normalized_events: list[NormalizedEvent]) -> None:
        """Test grouping by destination IP."""
        result = aggregate_by_dst_ip(sample_normalized_events)
        assert len(result) == 5

    def test_conn_state_sf_is_success_not_failure(self) -> None:
        """SF (normal close) must not be counted as a failed connection."""
        base = datetime.now(UTC)
        events = [
            NormalizedEvent(
                source_type="zeek",
                event_type="network_connection",
                timestamp=base + timedelta(seconds=i),
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                dst_port=80,
                attributes={"uid": f"SF{i}", "conn_state": "SF"},
            )
            for i in range(10)
        ]
        result = aggregate_connection_features(events)
        assert result["connection_count"] == 10
        assert result["failed_connections"] == 0

    def test_conn_state_oth_is_a_failure(self) -> None:
        """OTH (partial/unclassifiable) is treated as a failure."""
        event = NormalizedEvent(
            source_type="zeek",
            event_type="network_connection",
            timestamp=datetime.now(UTC),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=80,
            attributes={"uid": "OTH1", "conn_state": "OTH"},
        )
        result = aggregate_connection_features([event])
        assert result["failed_connections"] == 1


class TestFeatureExtractor:
    """Tests for FeatureExtractor class."""

    def test_extract_single_event(self, sample_normalized_event: NormalizedEvent) -> None:
        """Test feature extraction from single event."""
        extractor = FeatureExtractor(window_size_seconds=60.0)
        vector = extractor.extract(sample_normalized_event)
        assert vector is not None
        assert vector.src_ip == sample_normalized_event.src_ip
        assert vector.connection_count == 1

    def test_extract_single_normalized_event(
        self, sample_normalized_event: NormalizedEvent
    ) -> None:
        """Test feature extraction from single NormalizedEvent."""
        extractor = FeatureExtractor(window_size_seconds=60.0)
        vector = extractor.extract(sample_normalized_event)
        assert vector is not None
        assert vector.src_ip == sample_normalized_event.src_ip
        assert vector.connection_count == 1

    def test_extract_batch(self, sample_normalized_events: list[NormalizedEvent]) -> None:
        """Test batch feature extraction."""
        extractor = FeatureExtractor(window_size_seconds=3600.0)
        vectors = extractor.extract_batch(sample_normalized_events)
        assert len(vectors) == 5

    def test_extract_batch_normalized(
        self, sample_normalized_events: list[NormalizedEvent]
    ) -> None:
        """Test batch feature extraction with NormalizedEvents."""
        extractor = FeatureExtractor(window_size_seconds=3600.0)
        vectors = extractor.extract_batch(sample_normalized_events)
        assert len(vectors) == 5

    def test_window_per_source_ip(self) -> None:
        """Test separate windows per source IP."""
        extractor = FeatureExtractor(window_size_seconds=60.0)

        event1 = NormalizedEvent(
            source_type="zeek",
            event_type="connection",
            timestamp=datetime.now(UTC),
            attributes={"uid": "C1"},
            src_ip="192.168.1.1",
        )
        event2 = NormalizedEvent(
            source_type="zeek",
            event_type="connection",
            timestamp=datetime.now(UTC),
            attributes={"uid": "C2"},
            src_ip="192.168.1.2",
        )

        extractor.extract(event1)
        extractor.extract(event2)

        assert extractor.active_window_count == 2

    def test_window_per_source_ip_normalized(
        self, sample_normalized_event: NormalizedEvent
    ) -> None:
        """Test separate windows per source IP with NormalizedEvents."""
        extractor = FeatureExtractor(window_size_seconds=60.0)

        event1 = NormalizedEvent(
            source_type="zeek",
            event_type="connection",
            timestamp=datetime.now(UTC),
            src_ip="192.168.1.1",
        )
        event2 = NormalizedEvent(
            source_type="zeek",
            event_type="connection",
            timestamp=datetime.now(UTC),
            src_ip="192.168.1.2",
        )

        extractor.extract(event1)
        extractor.extract(event2)

        assert extractor.active_window_count == 2

    def test_clear_window(self, sample_normalized_event: NormalizedEvent) -> None:
        """Test clearing specific window."""
        extractor = FeatureExtractor(window_size_seconds=60.0)
        extractor.extract(sample_normalized_event)
        assert extractor.active_window_count == 1

        extractor.clear_window(sample_normalized_event.src_ip)
        assert extractor.active_window_count == 0

    def test_clear_all_windows(self, sample_normalized_events: list[NormalizedEvent]) -> None:
        """Test clearing all windows."""
        extractor = FeatureExtractor(window_size_seconds=3600.0)
        extractor.extract_batch(sample_normalized_events)
        assert extractor.active_window_count > 0

        extractor.clear_all_windows()
        assert extractor.active_window_count == 0

    def test_extract_skips_events_without_src_ip(self) -> None:
        """Events without a source IP must not crash extraction or pool every
        anonymous observation into a single None-keyed global window.
        """
        extractor = FeatureExtractor(window_size_seconds=60.0)
        anonymous_event = NormalizedEvent(
            source_type="zeek",
            event_type="dns_query",
            timestamp=datetime.now(UTC),
            src_ip=None,
            dst_ip="8.8.8.8",
            dst_port=53,
            attributes={"uid": "anon1"},
        )
        named_event = NormalizedEvent(
            source_type="zeek",
            event_type="network_connection",
            timestamp=datetime.now(UTC),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=80,
            attributes={"uid": "named1"},
        )
        assert extractor.extract(anonymous_event) is None
        assert extractor.extract(named_event) is not None
        assert extractor.active_window_count == 1
        assert None not in extractor.get_active_windows()


class TestFeatureVector:
    """Tests for FeatureVector model."""

    def test_valid_feature_vector(self, sample_normalized_event: NormalizedEvent) -> None:
        """Test valid feature vector creation."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=sample_normalized_event.event_id,
            window_start=now,
            window_end=now + timedelta(seconds=60),
            src_ip="192.168.1.1",
            connection_count=10,
        )
        assert vector.connection_count == 10
        assert vector.src_ip == "192.168.1.1"

    def test_invalid_window_times(self, sample_normalized_event: NormalizedEvent) -> None:
        """Test invalid window times."""
        now = datetime.now(UTC)
        with pytest.raises(ValueError):
            FeatureVector(
                event_id=sample_normalized_event.event_id,
                window_start=now + timedelta(seconds=60),
                window_end=now,
                src_ip="192.168.1.1",
            )

    def test_invalid_connection_count(self, sample_normalized_event: NormalizedEvent) -> None:
        """Test negative connection count."""
        now = datetime.now(UTC)
        with pytest.raises(ValueError):
            FeatureVector(
                event_id=sample_normalized_event.event_id,
                window_start=now,
                window_end=now + timedelta(seconds=60),
                src_ip="192.168.1.1",
                connection_count=-1,
            )

    def test_invalid_port_concentration(self, sample_normalized_event: NormalizedEvent) -> None:
        """Test invalid port concentration."""
        now = datetime.now(UTC)
        with pytest.raises(ValueError):
            FeatureVector(
                event_id=sample_normalized_event.event_id,
                window_start=now,
                window_end=now + timedelta(seconds=60),
                src_ip="192.168.1.1",
                port_concentration=1.5,
            )

    def test_get_feature(self, sample_normalized_event: NormalizedEvent) -> None:
        """Test getting custom features."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=sample_normalized_event.event_id,
            window_start=now,
            window_end=now + timedelta(seconds=60),
            src_ip="192.168.1.1",
            features={"custom_feature": 42},
        )
        assert vector.get_feature("custom_feature") == 42
        assert vector.get_feature("nonexistent", "default") == "default"

    def test_to_dict(self, sample_normalized_event: NormalizedEvent) -> None:
        """Test conversion to dictionary."""
        now = datetime.now(UTC)
        vector = FeatureVector(
            event_id=sample_normalized_event.event_id,
            window_start=now,
            window_end=now + timedelta(seconds=60),
            src_ip="192.168.1.1",
            connection_count=10,
        )
        result = vector.to_dict()
        assert result["src_ip"] == "192.168.1.1"
        assert result["connection_count"] == 10
        assert "vector_id" in result
        assert "created_at" in result
