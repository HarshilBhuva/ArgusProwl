"""Tests for CrossDetectorCorrelator."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.detection.cross_detector_correlator import CrossDetectorCorrelator
from argusprowl.exceptions.exceptions import DetectionError
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent


def create_event(
    timestamp: datetime,
    src_ip: str = "192.168.1.1",
    event_type: str = "connection",
    **kwargs,
) -> NormalizedEvent:
    """Helper to create a normalized event."""
    return NormalizedEvent(
        event_id=uuid4(),
        timestamp=timestamp,
        event_type=event_type,
        source_type="test",
        src_ip=src_ip,
        **kwargs,
    )


def create_detection_result(
    rule_id: str,
    event_id: uuid4,
    matched: bool = True,
    confidence: float = 0.7,
) -> DetectionResult:
    """Helper to create a DetectionResult."""
    return DetectionResult(
        rule_id=rule_id,
        event_id=event_id,
        matched=matched,
        severity=Severity.MEDIUM,
        confidence=confidence,
    )


class TestCrossDetectorCorrelator:
    """Tests for CrossDetectorCorrelator."""

    def test_basic_correlation(self):
        """Test that a basic 2-rule correlation completes correctly."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_a detection
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        results = correlator.process(event1, [result_a])
        assert len(results) == 0  # Not complete yet

        # Event 2: rule_b detection completes correlation
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 1
        assert results[0].matched
        assert "rule_a" in results[0].description
        assert "rule_b" in results[0].description

    def test_wrong_order_no_correlation(self):
        """Test that wrong order doesn't complete correlation."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_b detection (wrong order)
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event1.event_id)
        results = correlator.process(event1, [result_b])
        assert len(results) == 0  # Not complete

        # Event 2: rule_a detection (correct order now)
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event2.event_id)
        results = correlator.process(event2, [result_a])
        assert len(results) == 0  # Still not complete (wrong order)

    def test_outside_timespan_no_correlation(self):
        """Test that events outside timespan don't correlate."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(seconds=1),
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_a detection
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Event 2: rule_b detection (outside timespan)
        event2 = create_event(t0 + timedelta(seconds=2), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 0  # Outside timespan

    def test_different_groups_no_correlation(self):
        """Test that different groups don't correlate."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_a detection for group 1
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Event 2: rule_b detection for group 2 (different src_ip)
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.2")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 0  # Different groups

    def test_duplicate_detections(self):
        """Test that duplicate detections are handled correctly."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_a detection
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Event 2: rule_b detection (first correlation)
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 1
        assert results[0].matched

        # Event 3: rule_b detection again (should not re-trigger)
        event3 = create_event(t0 + timedelta(seconds=2), src_ip="192.168.1.1")
        result_b2 = create_detection_result("rule_b", event3.event_id)
        results = correlator.process(event3, [result_b2])
        assert len(results) == 0  # Already correlated

    def test_rearm(self):
        """Test that correlation can re-arm after completion."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # First correlation
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 1
        assert results[0].matched

        # Second correlation (re-arm)
        event3 = create_event(t0 + timedelta(seconds=2), src_ip="192.168.1.1")
        result_a2 = create_detection_result("rule_a", event3.event_id)
        correlator.process(event3, [result_a2])

        event4 = create_event(t0 + timedelta(seconds=3), src_ip="192.168.1.1")
        result_b2 = create_detection_result("rule_b", event4.event_id)
        results = correlator.process(event4, [result_b2])
        assert len(results) == 1
        assert results[0].matched

    def test_bounded_state(self):
        """Test that state is bounded and old entries are evicted."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            max_entries=100,
        )
        t0 = datetime.now(UTC)

        # Add many events
        for i in range(200):
            event = create_event(t0 + timedelta(seconds=i), src_ip=f"192.168.1.{i % 256}")
            result_a = create_detection_result("rule_a", event.event_id)
            correlator.process(event, [result_a])

        # State should be bounded
        assert correlator.get_state_entries() <= 100

    def test_missing_grouping_fields(self):
        """Test that missing grouping fields are handled."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_a detection without src_ip
        event1 = create_event(t0, src_ip=None)
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Event 2: rule_b detection without src_ip (should still correlate)
        event2 = create_event(t0 + timedelta(seconds=1), src_ip=None)
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 1
        assert results[0].matched

    def test_three_rule_sequence(self):
        """Test a 3-rule correlation sequence."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b", "rule_c"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_a
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Event 2: rule_b
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        correlator.process(event2, [result_b])

        # Event 3: rule_c (completes sequence)
        event3 = create_event(t0 + timedelta(seconds=2), src_ip="192.168.1.1")
        result_c = create_detection_result("rule_c", event3.event_id)
        results = correlator.process(event3, [result_c])
        assert len(results) == 1
        assert results[0].matched
        assert "rule_a" in results[0].description
        assert "rule_b" in results[0].description
        assert "rule_c" in results[0].description

    def test_disabled_correlator(self):
        """Test that disabled correlator doesn't produce results."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            enabled=False,
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 0  # Disabled

    def test_enable_disable(self):
        """Test enable/disable functionality."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            enabled=False,
        )
        assert not correlator.is_enabled()

        correlator.enable()
        assert correlator.is_enabled()

        correlator.disable()
        assert not correlator.is_enabled()

    def test_parse_timespan(self):
        """Test timespan parsing."""
        assert CrossDetectorCorrelator.parse_timespan("5s") == timedelta(seconds=5)
        assert CrossDetectorCorrelator.parse_timespan("10m") == timedelta(minutes=10)
        assert CrossDetectorCorrelator.parse_timespan("2h") == timedelta(hours=2)
        assert CrossDetectorCorrelator.parse_timespan("1d") == timedelta(days=1)

    def test_invalid_timespan(self):
        """Test invalid timespan raises error."""
        with pytest.raises(DetectionError):
            CrossDetectorCorrelator.parse_timespan("invalid")

    def test_invalid_timespan_format(self):
        """Test invalid timespan format raises error."""
        with pytest.raises(DetectionError):
            CrossDetectorCorrelator.parse_timespan("5x")

    def test_invalid_sequence_length(self):
        """Test that sequence with less than 2 rules raises error."""
        with pytest.raises(ValueError):
            CrossDetectorCorrelator(sequence=["rule_a"])

    def test_invalid_timespan_length(self):
        """Test that timespan exceeding maximum raises error."""
        with pytest.raises(ValueError):
            CrossDetectorCorrelator(
                sequence=["rule_a", "rule_b"],
                timespan=timedelta(days=31),
            )

    def test_evidence_structure(self):
        """Test that correlation result has correct evidence structure."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])

        assert len(results) == 1
        assert "correlation_sequence" in results[0].evidence[0]["field"]
        assert "src_ip" in results[0].evidence[1]["field"]

    def test_metadata_structure(self):
        """Test that correlation result has correct metadata."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])

        assert len(results) == 1
        assert "step_count" in results[0].metadata
        assert results[0].metadata["step_count"] == 2
        assert "sequence" in results[0].metadata
        assert results[0].metadata["sequence"] == ["rule_a", "rule_b"]

    def test_confidence_preserved(self):
        """Test that correlation result has correct confidence."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            confidence=0.9,
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])

        assert len(results) == 1
        assert results[0].confidence == 0.9

    def test_severity_is_high(self):
        """Test that correlation result has HIGH severity."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])

        assert len(results) == 1
        assert results[0].severity == Severity.HIGH

    def test_contributing_event_ids(self):
        """Test that correlation result has correct contributing event IDs."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])

        assert len(results) == 1
        assert len(results[0].contributing_event_ids) == 2
        # contributing_event_ids contains result_ids, not event_ids
        assert result_a.result_id in results[0].contributing_event_ids
        assert result_b.result_id in results[0].contributing_event_ids

    def test_detection_count(self):
        """Test that detection count is incremented."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        correlator.process(event2, [result_b])

        assert correlator.detections_count == 1

    def test_state_keys(self):
        """Test that state keys count is correct."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        assert correlator.get_state_keys() == 1

    def test_state_entries(self):
        """Test that state entries count is correct."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        assert correlator.get_state_entries() == 1

    def test_multiple_groups(self):
        """Test that multiple groups are tracked independently."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        # Group 1
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Group 2
        event2 = create_event(t0, src_ip="192.168.1.2")
        result_a2 = create_detection_result("rule_a", event2.event_id)
        correlator.process(event2, [result_a2])

        assert correlator.get_state_keys() == 2

    def test_expiration(self):
        """Test that old entries are expired."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(seconds=1),
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_a detection
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Wait for expiration
        import time

        time.sleep(1.1)

        # Event 2: rule_b detection (after expiration)
        event2 = create_event(datetime.now(UTC), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 0  # Expired

    def test_no_matching_result(self):
        """Test that non-matching results don't trigger correlation."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_a detection
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Event 2: non-matching result
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_c = create_detection_result("rule_c", event2.event_id)
        results = correlator.process(event2, [result_c])
        assert len(results) == 0  # Not in sequence

    def test_empty_results(self):
        """Test that empty results don't cause errors."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        results = correlator.process(event1, [])
        assert len(results) == 0

    def test_all_unmatched_results(self):
        """Test that all unmatched results don't cause errors."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id, matched=False)
        results = correlator.process(event1, [result_a])
        assert len(results) == 0  # Not matched

    def test_different_event_types(self):
        """Test correlation with different event types."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_a with event_type "login"
        event1 = create_event(t0, src_ip="192.168.1.1", event_type="login")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Event 2: rule_b with event_type "connection"
        event2 = create_event(
            t0 + timedelta(seconds=1), src_ip="192.168.1.1", event_type="connection"
        )
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 1
        assert results[0].matched

    def test_hostname_grouping(self):
        """Test correlation with hostname grouping."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            group_by=["hostname"],
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_a detection
        event1 = create_event(t0, src_ip="192.168.1.1", hostname="host1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Event 2: rule_b detection for different hostname
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1", hostname="host2")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 0  # Different hostname

    def test_username_grouping(self):
        """Test correlation with username grouping."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            group_by=["username"],
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_a detection
        event1 = create_event(t0, src_ip="192.168.1.1", username="admin")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Event 2: rule_b detection for different username
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1", username="user")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 0  # Different username

    def test_dst_ip_grouping(self):
        """Test correlation with dst_ip grouping."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            group_by=["dst_ip"],
        )
        t0 = datetime.now(UTC)

        # Event 1: rule_a detection
        event1 = create_event(t0, src_ip="192.168.1.1", dst_ip="10.0.0.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Event 2: rule_b detection for different dst_ip
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1", dst_ip="10.0.0.2")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 0  # Different dst_ip

    def test_multiple_correlations_same_group(self):
        """Test multiple correlations in the same group."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # First correlation
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 1

        # Second correlation (re-arm)
        event3 = create_event(t0 + timedelta(seconds=2), src_ip="192.168.1.1")
        result_a2 = create_detection_result("rule_a", event3.event_id)
        correlator.process(event3, [result_a2])

        event4 = create_event(t0 + timedelta(seconds=3), src_ip="192.168.1.1")
        result_b2 = create_detection_result("rule_b", event4.event_id)
        results = correlator.process(event4, [result_b2])
        assert len(results) == 1

    def test_concurrent_processing(self):
        """Test that concurrent processing is thread-safe."""
        import threading

        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        errors = []

        def process_event(i):
            try:
                event = create_event(t0 + timedelta(seconds=i), src_ip=f"192.168.1.{i % 10}")
                result_a = create_detection_result("rule_a", event.event_id)
                correlator.process(event, [result_a])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=process_event, args=(i,)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

    def test_large_sequence(self):
        """Test correlation with a large sequence."""
        sequence = [f"rule_{i}" for i in range(10)]
        correlator = CrossDetectorCorrelator(
            sequence=sequence,
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Process all steps
        for i, rule_id in enumerate(sequence):
            event = create_event(t0 + timedelta(seconds=i), src_ip="192.168.1.1")
            result = create_detection_result(rule_id, event.event_id)
            if i < len(sequence) - 1:
                results = correlator.process(event, [result])
                assert len(results) == 0
            else:
                results = correlator.process(event, [result])
                assert len(results) == 1
                assert results[0].matched

    def test_description_format(self):
        """Test that description has correct format."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])

        assert len(results) == 1
        assert "Cross-detector correlation completed" in results[0].description
        assert "rule_a" in results[0].description
        assert "rule_b" in results[0].description

    def test_explanation_format(self):
        """Test that explanation has correct format."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])

        assert len(results) == 1
        assert "correlation between 2 detectors" in results[0].explanation
        assert "rule_a" in results[0].explanation
        assert "rule_b" in results[0].explanation
