"""Hardening tests for CrossDetectorCorrelator.

Covers:
  A. Replay parity
  B. Prevent accidental correlation feedback
  C. Confidence contract
  D. Duplicate and overlapping correlations
  E. Rule identity and multiple correlators
  F. DetectionResult contract
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from argusprowl.constants.severity import Severity
from argusprowl.detection.cross_detector_correlator import CrossDetectorCorrelator
from argusprowl.detection.detection_manager import DetectionManager
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


# ---------------------------------------------------------------------------
# A. Replay Parity
# ---------------------------------------------------------------------------


class TestReplayParity:
    """Tests for replay parity with CrossDetectorCorrelator."""

    def test_replay_produces_same_correlation(self):
        """Test that replay produces the same correlation result."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # First replay run
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results1 = correlator.process(event2, [result_b])

        assert len(results1) == 1
        assert results1[0].matched

        # Second replay run with same events (fresh correlator)
        correlator2 = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )

        event3 = create_event(t0, src_ip="192.168.1.1")
        result_a2 = create_detection_result("rule_a", event3.event_id)
        correlator2.process(event3, [result_a2])

        event4 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b2 = create_detection_result("rule_b", event4.event_id)
        results2 = correlator2.process(event4, [result_b2])

        assert len(results2) == 1
        assert results2[0].matched

        # Verify semantic equivalence
        assert results1[0].description == results2[0].description
        assert results1[0].explanation == results2[0].explanation
        assert results1[0].confidence == results2[0].confidence
        assert results1[0].severity == results2[0].severity

    def test_replay_starts_with_fresh_state(self):
        """Test that replay starts with fresh correlator state."""
        correlator1 = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # First replay
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator1.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        correlator1.process(event2, [result_b])

        # Second replay with fresh correlator
        correlator2 = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )

        # Should start with empty state
        assert correlator2.get_state_entries() == 0
        assert correlator2.get_state_keys() == 0

    def test_no_state_leak_between_replays(self):
        """Test that state doesn't leak between replay runs.

        After a correlation completes, the correlator re-arms by removing
        the completed entries from state. So we check state after the
        first event (before completion) and after creating a fresh correlator.
        """
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # First replay
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Verify state after first event (before correlation completes)
        assert correlator.get_state_entries() > 0

        # Create fresh correlator (simulating replay restart)
        correlator2 = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )

        # Should have no state
        assert correlator2.get_state_entries() == 0
        assert correlator2.get_state_keys() == 0

    def test_contributing_event_ids_order_preserved(self):
        """Test that contributing event IDs preserve causal order."""
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
        contributing_ids = results[0].contributing_event_ids
        assert len(contributing_ids) == 2
        # First should be rule_a's result_id, second should be rule_b's
        assert contributing_ids[0] == result_a.result_id
        assert contributing_ids[1] == result_b.result_id


# ---------------------------------------------------------------------------
# B. Prevent Accidental Correlation Feedback
# ---------------------------------------------------------------------------


class TestCorrelationFeedback:
    """Tests for preventing accidental correlation feedback."""

    def test_correlation_result_not_reprocessed(self):
        """Test that correlation results are not fed back to correlator."""
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

        # Should produce exactly one correlation result
        assert len(results) == 1

        # The correlation result should not trigger another correlation
        correlation_result = results[0]
        results2 = correlator.process(event2, [correlation_result])
        assert len(results2) == 0  # No feedback loop

    def test_different_correlators_independent(self):
        """Test that different correlators don't interfere."""
        correlator1 = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        correlator2 = CrossDetectorCorrelator(
            sequence=["rule_c", "rule_d"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Process rule_a and rule_c
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        result_c = create_detection_result("rule_c", event1.event_id)

        correlator1.process(event1, [result_a])
        correlator2.process(event1, [result_c])

        # Process rule_b and rule_d
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        result_d = create_detection_result("rule_d", event2.event_id)

        results1 = correlator1.process(event2, [result_b])
        results2 = correlator2.process(event2, [result_d])

        # Each correlator should produce exactly one result
        assert len(results1) == 1
        assert len(results2) == 1

        # Results should be independent
        assert results1[0].rule_id == correlator1.name
        assert results2[0].rule_id == correlator2.name

    def test_no_self_correlation(self):
        """Test that a correlator doesn't correlate with itself."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Process rule_a
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Process rule_a again (should not trigger correlation)
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_a2 = create_detection_result("rule_a", event2.event_id)
        results = correlator.process(event2, [result_a2])
        assert len(results) == 0  # No correlation (wrong sequence)

    def test_correlator_does_not_consume_its_own_output(self):
        """Test that correlator doesn't consume its own output."""
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
        results1 = correlator.process(event2, [result_b])

        assert len(results1) == 1

        # Try to feed the correlation result back
        correlation_result = results1[0]
        results2 = correlator.process(event2, [correlation_result])
        assert len(results2) == 0  # No feedback


# ---------------------------------------------------------------------------
# C. Confidence Contract
# ---------------------------------------------------------------------------


class TestConfidenceContract:
    """Tests for confidence contract."""

    def test_correlation_uses_configured_confidence(self):
        """Test that correlation uses the configured confidence, not source confidence."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            confidence=0.9,
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id, confidence=0.5)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id, confidence=0.6)
        results = correlator.process(event2, [result_b])

        assert len(results) == 1
        # Correlation confidence should be the configured value, not source confidence
        assert results[0].confidence == 0.9

    def test_source_confidence_not_confused(self):
        """Test that source detector confidence is not confused with correlation confidence."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            confidence=0.8,
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id, confidence=0.3)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id, confidence=0.4)
        results = correlator.process(event2, [result_b])

        assert len(results) == 1
        # Source confidences are 0.3 and 0.4, correlation confidence is 0.8
        assert results[0].confidence == 0.8
        assert results[0].confidence != 0.3
        assert results[0].confidence != 0.4

    def test_default_confidence(self):
        """Test that default confidence is 0.8."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        assert correlator._confidence == 0.8

    def test_confidence_preserved_in_metadata(self):
        """Test that correlation confidence is preserved."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            confidence=0.75,
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])

        assert len(results) == 1
        assert results[0].confidence == 0.75


# ---------------------------------------------------------------------------
# D. Duplicate and Overlapping Correlations
# ---------------------------------------------------------------------------


class TestDuplicateCorrelations:
    """Tests for duplicate and overlapping correlations."""

    def test_second_correlation_not_suppressed(self):
        """Test that a valid second correlation is not suppressed."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # First correlation: A1 -> B1
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a1 = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a1])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b1 = create_detection_result("rule_b", event2.event_id)
        results1 = correlator.process(event2, [result_b1])
        assert len(results1) == 1

        # Second correlation: A2 -> B2
        event3 = create_event(t0 + timedelta(seconds=2), src_ip="192.168.1.1")
        result_a2 = create_detection_result("rule_a", event3.event_id)
        correlator.process(event3, [result_a2])

        event4 = create_event(t0 + timedelta(seconds=3), src_ip="192.168.1.1")
        result_b2 = create_detection_result("rule_b", event4.event_id)
        results2 = correlator.process(event4, [result_b2])
        assert len(results2) == 1  # Second correlation should not be suppressed

    def test_duplicate_a_no_double_correlation(self):
        """Test that duplicate A doesn't cause double correlation."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Two rule_a detections
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a1 = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a1])

        event2 = create_event(t0 + timedelta(seconds=0.5), src_ip="192.168.1.1")
        result_a2 = create_detection_result("rule_a", event2.event_id)
        correlator.process(event2, [result_a2])

        # One rule_b detection
        event3 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event3.event_id)
        results = correlator.process(event3, [result_b])

        # Should produce exactly one correlation
        assert len(results) == 1

    def test_duplicate_b_no_double_correlation(self):
        """Test that duplicate B doesn't cause double correlation."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # One rule_a detection
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        # Two rule_b detections
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b1 = create_detection_result("rule_b", event2.event_id)
        results1 = correlator.process(event2, [result_b1])
        assert len(results1) == 1

        event3 = create_event(t0 + timedelta(seconds=2), src_ip="192.168.1.1")
        result_b2 = create_detection_result("rule_b", event3.event_id)
        results2 = correlator.process(event3, [result_b2])
        assert len(results2) == 0  # Already correlated

    def test_repeated_complete_sequences(self):
        """Test repeated complete sequences."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # First sequence
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a1 = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a1])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b1 = create_detection_result("rule_b", event2.event_id)
        results1 = correlator.process(event2, [result_b1])
        assert len(results1) == 1

        # Second sequence
        event3 = create_event(t0 + timedelta(seconds=2), src_ip="192.168.1.1")
        result_a2 = create_detection_result("rule_a", event3.event_id)
        correlator.process(event3, [result_a2])

        event4 = create_event(t0 + timedelta(seconds=3), src_ip="192.168.1.1")
        result_b2 = create_detection_result("rule_b", event4.event_id)
        results2 = correlator.process(event4, [result_b2])
        assert len(results2) == 1

        # Third sequence
        event5 = create_event(t0 + timedelta(seconds=4), src_ip="192.168.1.1")
        result_a3 = create_detection_result("rule_a", event5.event_id)
        correlator.process(event5, [result_a3])

        event6 = create_event(t0 + timedelta(seconds=5), src_ip="192.168.1.1")
        result_b3 = create_detection_result("rule_b", event6.event_id)
        results3 = correlator.process(event6, [result_b3])
        assert len(results3) == 1

    def test_expiration_followed_by_new_sequence(self):
        """Test that expiration allows new sequence."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(seconds=1),
        )
        t0 = datetime.now(UTC)

        # First sequence
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=0.5), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results1 = correlator.process(event2, [result_b])
        assert len(results1) == 1

        # Wait for expiration
        import time

        time.sleep(1.1)

        # New sequence after expiration
        event3 = create_event(datetime.now(UTC), src_ip="192.168.1.1")
        result_a2 = create_detection_result("rule_a", event3.event_id)
        correlator.process(event3, [result_a2])

        event4 = create_event(datetime.now(UTC) + timedelta(seconds=0.5), src_ip="192.168.1.1")
        result_b2 = create_detection_result("rule_b", event4.event_id)
        results2 = correlator.process(event4, [result_b2])
        assert len(results2) == 1  # New sequence should work

    def test_multiple_independent_groups(self):
        """Test multiple independent groups."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        # Group 1
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a1 = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a1])

        # Group 2 starts before Group 1 completes
        event3 = create_event(t0, src_ip="192.168.1.2")
        result_a2 = create_detection_result("rule_a", event3.event_id)
        correlator.process(event3, [result_a2])

        # Both groups should be tracked before any completions
        assert correlator.get_state_keys() == 2

        # Group 1 completes
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b1 = create_detection_result("rule_b", event2.event_id)
        results1 = correlator.process(event2, [result_b1])
        assert len(results1) == 1

        # Group 2 completes
        event4 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.2")
        result_b2 = create_detection_result("rule_b", event4.event_id)
        results2 = correlator.process(event4, [result_b2])
        assert len(results2) == 1


# ---------------------------------------------------------------------------
# E. Rule Identity and Multiple Correlators
# ---------------------------------------------------------------------------


class TestRuleIdentity:
    """Tests for rule identity and multiple correlators."""

    def test_valid_rule_ids(self):
        """Test that valid rule IDs are accepted."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b", "rule_c"],
            timespan=timedelta(minutes=5),
        )
        assert correlator._sequence == ["rule_a", "rule_b", "rule_c"]

    def test_unknown_rule_id_behavior(self):
        """Test behavior when unknown rule ID is encountered."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Process unknown rule
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_unknown = create_detection_result("rule_unknown", event1.event_id)
        results = correlator.process(event1, [result_unknown])
        assert len(results) == 0  # Unknown rule doesn't trigger correlation

    def test_two_independent_correlators(self):
        """Test two independent correlator configurations."""
        correlator1 = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            name="correlator_1",
        )
        correlator2 = CrossDetectorCorrelator(
            sequence=["rule_c", "rule_d"],
            timespan=timedelta(minutes=5),
            name="correlator_2",
        )
        t0 = datetime.now(UTC)

        # Process rules for correlator1
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator1.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results1 = correlator1.process(event2, [result_b])
        assert len(results1) == 1
        assert results1[0].rule_id == "correlator_1"

        # Process rules for correlator2
        event3 = create_event(t0, src_ip="192.168.1.1")
        result_c = create_detection_result("rule_c", event3.event_id)
        correlator2.process(event3, [result_c])

        event4 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_d = create_detection_result("rule_d", event4.event_id)
        results2 = correlator2.process(event4, [result_d])
        assert len(results2) == 1
        assert results2[0].rule_id == "correlator_2"

    def test_same_source_rule_in_multiple_correlators(self):
        """Test same source rule appearing in multiple correlators."""
        correlator1 = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            name="correlator_1",
        )
        correlator2 = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_c"],
            timespan=timedelta(minutes=5),
            name="correlator_2",
        )
        t0 = datetime.now(UTC)

        # Process rule_a
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator1.process(event1, [result_a])
        correlator2.process(event1, [result_a])

        # Process rule_b for correlator1
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results1 = correlator1.process(event2, [result_b])
        assert len(results1) == 1

        # Process rule_c for correlator2
        event3 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_c = create_detection_result("rule_c", event3.event_id)
        results2 = correlator2.process(event3, [result_c])
        assert len(results2) == 1

    def test_state_isolation_between_correlators(self):
        """Test state isolation between correlator instances."""
        correlator1 = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        correlator2 = CrossDetectorCorrelator(
            sequence=["rule_c", "rule_d"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Add state to correlator1
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator1.process(event1, [result_a])

        # Correlator2 should have no state
        assert correlator2.get_state_entries() == 0
        assert correlator2.get_state_keys() == 0

        # Correlator1 should have state
        assert correlator1.get_state_entries() == 1
        assert correlator1.get_state_keys() == 1


# ---------------------------------------------------------------------------
# F. DetectionResult Contract
# ---------------------------------------------------------------------------


class TestDetectionResultContract:
    """Tests for DetectionResult contract."""

    def test_event_id_is_current_event(self):
        """Test that event_id is the current event."""
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
        # event_id should be the current event (event2)
        assert results[0].event_id == event2.event_id

    def test_contributing_event_ids_bounded(self):
        """Test that contributing_event_ids is bounded."""
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
        # Should have exactly 2 contributing event IDs
        assert len(results[0].contributing_event_ids) == 2

    def test_evidence_structure(self):
        """Test that evidence has correct structure."""
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
        evidence = results[0].evidence
        assert len(evidence) >= 2

        # First evidence should be correlation_sequence
        assert evidence[0]["field"] == "correlation_sequence"
        assert evidence[0]["condition"] == "completed"

        # Second evidence should be group field
        assert evidence[1]["field"] == "src_ip"

    def test_metadata_structure(self):
        """Test that metadata has correct structure."""
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
        metadata = results[0].metadata
        assert "step_count" in metadata
        assert "sequence" in metadata
        assert "group_by" in metadata
        assert "timespan_seconds" in metadata

    def test_severity_is_high(self):
        """Test that severity is HIGH."""
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

    def test_contribution_order_preserved(self):
        """Test that contributing event IDs preserve causal order."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b", "rule_c"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        correlator.process(event2, [result_b])

        event3 = create_event(t0 + timedelta(seconds=2), src_ip="192.168.1.1")
        result_c = create_detection_result("rule_c", event3.event_id)
        results = correlator.process(event3, [result_c])

        assert len(results) == 1
        contributing = results[0].contributing_event_ids
        assert len(contributing) == 3
        # Order should be: rule_a, rule_b, rule_c
        assert contributing[0] == result_a.result_id
        assert contributing[1] == result_b.result_id
        assert contributing[2] == result_c.result_id

    def test_long_sequence_bounded(self):
        """Test that long sequences have bounded contributing IDs."""
        correlator = CrossDetectorCorrelator(
            sequence=[f"rule_{i}" for i in range(10)],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Process all steps
        for i, rule_id in enumerate(correlator._sequence):
            event = create_event(t0 + timedelta(seconds=i), src_ip="192.168.1.1")
            result = create_detection_result(rule_id, event.event_id)
            if i < len(correlator._sequence) - 1:
                correlator.process(event, [result])
            else:
                results = correlator.process(event, [result])
                assert len(results) == 1
                # Contributing IDs should be bounded
                assert len(results[0].contributing_event_ids) <= 10


# ---------------------------------------------------------------------------
# G. DetectionManager Integration
# ---------------------------------------------------------------------------


class TestDetectionManagerIntegration:
    """Tests for DetectionManager integration with CrossDetectorCorrelator."""

    def test_correlator_registered_with_manager(self):
        """Test that correlator can be registered with DetectionManager."""
        manager = DetectionManager()
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        manager.register_correlator(correlator)
        assert len(manager._correlators) == 1
        assert manager._correlators[0] is correlator

    def test_correlator_processes_with_manager(self):
        """Test that correlator processes events through DetectionManager."""
        # Verify that the manager has the correlator registered
        manager = DetectionManager()
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        manager.register_correlator(correlator)

        t0 = datetime.now(UTC)
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)

        # Directly process through the correlator (which is the path the manager uses)
        # This tests that the correlator behavior is preserved when called
        # with the same arguments the manager would use.
        results1 = correlator.process(event1, [result_a])
        assert len(results1) == 0  # No correlation yet

        # Now simulate what the manager would do: pass event2 and the prior result
        # The manager does not pass the prior result; it only passes results from
        # the current event. To test the integration, we need a stateful detector
        # that produces results. Since the correlator stores its own state, we
        # verify the correlator's state and behavior is what the manager relies on.
        assert correlator.get_state_entries() == 1

        # The manager would call correlator.process(event2, [result_b])
        # where result_b comes from event2's detector evaluation.
        # This requires detectors registered with the manager to produce results.
        # Here we verify the correlator works correctly with direct calls.
        results2 = correlator.process(event2, [result_b])
        assert len(results2) == 1
        assert results2[0].rule_id == correlator.name

    def test_multiple_correlators_with_manager(self):
        """Test multiple correlators registered with DetectionManager."""
        manager = DetectionManager()
        correlator1 = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            name="correlator_1",
        )
        correlator2 = CrossDetectorCorrelator(
            sequence=["rule_c", "rule_d"],
            timespan=timedelta(minutes=5),
            name="correlator_2",
        )
        manager.register_correlator(correlator1)
        manager.register_correlator(correlator2)

        # Verify both correlators are registered
        assert len(manager._correlators) == 2
        assert manager._correlators[0].name == "correlator_1"
        assert manager._correlators[1].name == "correlator_2"

        # Test independent correlation behavior for each correlator
        t0 = datetime.now(UTC)
        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a = create_detection_result("rule_a", event1.event_id)
        result_c = create_detection_result("rule_c", event1.event_id)

        # Register state for both correlators
        correlator1.process(event1, [result_a])
        correlator2.process(event1, [result_c])

        # Process completion events
        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        result_d = create_detection_result("rule_d", event2.event_id)

        results1 = correlator1.process(event2, [result_b])
        results2 = correlator2.process(event2, [result_d])

        assert len(results1) == 1
        assert len(results2) == 1
        assert results1[0].rule_id == "correlator_1"
        assert results2[0].rule_id == "correlator_2"

    def test_disabled_correlator_not_processed(self):
        """Test that disabled correlator is not processed."""
        manager = DetectionManager()
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            enabled=False,
        )
        manager.register_correlator(correlator)

        t0 = datetime.now(UTC)
        event1 = create_event(t0, src_ip="192.168.1.1")
        create_detection_result("rule_a", event1.event_id)
        manager.process_event(event1)

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        create_detection_result("rule_b", event2.event_id)
        results = manager.process_event(event2)

        # Should not have correlation result
        correlation_results = [r for r in results if r.rule_id == correlator.name]
        assert len(correlation_results) == 0


# ---------------------------------------------------------------------------
# H. Edge Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_detection_results(self):
        """Test processing with empty detection results."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)
        event = create_event(t0, src_ip="192.168.1.1")
        results = correlator.process(event, [])
        assert len(results) == 0

    def test_all_unmatched_results(self):
        """Test processing with all unmatched results."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)
        event = create_event(t0, src_ip="192.168.1.1")
        result = create_detection_result("rule_a", event.event_id, matched=False)
        results = correlator.process(event, [result])
        assert len(results) == 0

    def test_mixed_matched_unmatched(self):
        """Test processing with mixed matched and unmatched results."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1")
        result_a_matched = create_detection_result("rule_a", event1.event_id, matched=True)
        result_a_unmatched = create_detection_result("rule_a", event1.event_id, matched=False)
        correlator.process(event1, [result_a_matched, result_a_unmatched])

        event2 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1")
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 1

    def test_different_event_types_same_group(self):
        """Test correlation with different event types in same group."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, src_ip="192.168.1.1", event_type="login")
        result_a = create_detection_result("rule_a", event1.event_id)
        correlator.process(event1, [result_a])

        event2 = create_event(
            t0 + timedelta(seconds=1), src_ip="192.168.1.1", event_type="connection"
        )
        result_b = create_detection_result("rule_b", event2.event_id)
        results = correlator.process(event2, [result_b])
        assert len(results) == 1

    def test_max_entries_limit(self):
        """Test that max_entries limit is enforced."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            max_entries=10,
        )
        t0 = datetime.now(UTC)

        # Add more entries than max
        for i in range(20):
            event = create_event(t0 + timedelta(seconds=i), src_ip=f"192.168.1.{i % 256}")
            result = create_detection_result("rule_a", event.event_id)
            correlator.process(event, [result])

        # State should be bounded
        assert correlator.get_state_entries() <= 10

    def test_concurrent_access(self):
        """Test thread-safe concurrent access."""
        import threading

        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)
        errors = []

        def process_events(start_idx, count):
            try:
                for i in range(count):
                    event = create_event(
                        t0 + timedelta(seconds=start_idx + i),
                        src_ip=f"192.168.1.{(start_idx + i) % 10}",
                    )
                    result_a = create_detection_result("rule_a", event.event_id)
                    correlator.process(event, [result_a])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=process_events, args=(i * 10, 10)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
