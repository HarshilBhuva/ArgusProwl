"""Tests for OrderedSequenceDetector and OrderedSequenceState."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from argusprowl.detection.detectors.ordered_sequence_correlation import OrderedSequenceDetector
from argusprowl.detection.detectors.ordered_sequence_state import (
    OrderedSequenceState,
)
from argusprowl.exceptions.exceptions import DetectionError
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


class TestOrderedSequenceState:
    """Tests for OrderedSequenceState."""

    def test_basic_sequence_completion(self):
        """Test that a basic 2-step sequence completes correctly."""
        state = OrderedSequenceState(
            group_key=("192.168.1.1",),
            window_duration=timedelta(minutes=5),
            total_steps=2,
        )
        t0 = datetime.now(UTC)

        # Step 1: login event
        event1 = create_event(t0, event_type="login")
        advanced, completed = state.try_advance(
            event1, [{"event_type": "login"}, {"event_type": "data_access"}]
        )
        assert advanced
        assert completed is None

        # Step 2: data_access event completes the sequence
        event2 = create_event(t0 + timedelta(seconds=1), event_type="data_access")
        advanced, completed = state.try_advance(
            event2, [{"event_type": "login"}, {"event_type": "data_access"}]
        )
        assert advanced
        assert completed is not None
        assert len(completed.steps) == 2

    def test_multiple_matching_partial_sequences(self):
        """Test that overlapping valid sequences can progress independently."""
        state = OrderedSequenceState(
            group_key=("192.168.1.1",),
            window_duration=timedelta(minutes=5),
            total_steps=2,
        )
        t0 = datetime.now(UTC)

        # Step 1: login event starts sequence 1
        event1 = create_event(t0, event_type="login")
        advanced, completed = state.try_advance(
            event1, [{"event_type": "login"}, {"event_type": "login"}]
        )
        assert advanced
        assert completed is None

        # Step 2: login event completes sequence 1 AND starts sequence 2
        event2 = create_event(t0 + timedelta(seconds=1), event_type="login")
        advanced, completed = state.try_advance(
            event2, [{"event_type": "login"}, {"event_type": "login"}]
        )
        assert advanced
        assert completed is not None
        assert len(completed.steps) == 2
        assert completed.steps[0].event.event_id == event1.event_id
        assert completed.steps[1].event.event_id == event2.event_id

        # Clear trigger
        state.check_and_clear_trigger(event2)

        # Step 3: login event completes sequence 2 AND starts sequence 3
        event3 = create_event(t0 + timedelta(seconds=2), event_type="login")
        advanced, completed = state.try_advance(
            event3, [{"event_type": "login"}, {"event_type": "login"}]
        )
        assert advanced
        assert completed is not None
        assert len(completed.steps) == 2
        assert completed.steps[0].event.event_id == event2.event_id
        assert completed.steps[1].event.event_id == event3.event_id

    def test_single_event_advances_multiple_sequences(self):
        """Test that a single event can advance multiple valid sequences."""
        state = OrderedSequenceState(
            group_key=("192.168.1.1",),
            window_duration=timedelta(minutes=5),
            total_steps=3,
        )
        t0 = datetime.now(UTC)

        # Start sequence 1
        event1 = create_event(t0, event_type="login")
        state.try_advance(
            event1,
            [{"event_type": "login"}, {"event_type": "login"}, {"event_type": "data_access"}],
        )

        # Start sequence 2 and advance sequence 1
        event2 = create_event(t0 + timedelta(seconds=1), event_type="login")
        state.try_advance(
            event2,
            [{"event_type": "login"}, {"event_type": "login"}, {"event_type": "data_access"}],
        )

        # Now we have two sequences:
        # Seq 1 is at step 2 (waiting for data_access)
        # Seq 2 is at step 1 (waiting for login)

        # Start sequence 3 and advance sequence 2
        event3 = create_event(t0 + timedelta(seconds=2), event_type="login")
        state.try_advance(
            event3,
            [{"event_type": "login"}, {"event_type": "login"}, {"event_type": "data_access"}],
        )

        # Now we have three sequences:
        # Seq 1 is at step 2 (waiting for data_access)
        # Seq 2 is at step 2 (waiting for data_access)
        # Seq 3 is at step 1 (waiting for login)

        # This single event should complete BOTH Seq 1 and Seq 2
        event4 = create_event(t0 + timedelta(seconds=3), event_type="data_access")
        advanced, completed = state.try_advance(
            event4,
            [{"event_type": "login"}, {"event_type": "login"}, {"event_type": "data_access"}],
        )

        assert advanced
        assert completed is not None
        # The first completed sequence is returned
        assert completed.steps[0].event.event_id == event1.event_id
        assert completed.steps[2].event.event_id == event4.event_id

    def test_wrong_order_no_completion(self):
        """Test that events in wrong order don't complete the sequence."""
        state = OrderedSequenceState(
            group_key=("192.168.1.1",),
            window_duration=timedelta(minutes=5),
            total_steps=2,
        )
        t0 = datetime.now(UTC)

        # Step 1: data_access event (wrong order)
        event1 = create_event(t0, event_type="data_access")
        advanced, completed = state.try_advance(
            event1, [{"event_type": "login"}, {"event_type": "data_access"}]
        )
        # Should start a new sequence that can't advance
        assert not advanced  # Doesn't match step 0

        # Step 2: login event (but we're still waiting for step 0)
        event2 = create_event(t0 + timedelta(seconds=1), event_type="login")
        advanced, completed = state.try_advance(
            event2, [{"event_type": "login"}, {"event_type": "data_access"}]
        )
        assert advanced  # Matches step 0, starts new sequence
        assert completed is None

    def test_three_step_sequence(self):
        """Test a 3-step sequence completes correctly."""
        state = OrderedSequenceState(
            group_key=("192.168.1.1",),
            window_duration=timedelta(minutes=5),
            total_steps=3,
        )
        t0 = datetime.now(UTC)

        # Step 1
        event1 = create_event(t0, event_type="scan")
        advanced, completed = state.try_advance(
            event1,
            [{"event_type": "scan"}, {"event_type": "exploit"}, {"event_type": "data_access"}],
        )
        assert advanced
        assert completed is None

        # Step 2
        event2 = create_event(t0 + timedelta(seconds=1), event_type="exploit")
        advanced, completed = state.try_advance(
            event2,
            [{"event_type": "scan"}, {"event_type": "exploit"}, {"event_type": "data_access"}],
        )
        assert advanced
        assert completed is None

        # Step 3 completes
        event3 = create_event(t0 + timedelta(seconds=2), event_type="data_access")
        advanced, completed = state.try_advance(
            event3,
            [{"event_type": "scan"}, {"event_type": "exploit"}, {"event_type": "data_access"}],
        )
        assert advanced
        assert completed is not None
        assert len(completed.steps) == 3

    def test_outside_timespan_expires(self):
        """Test that sequences expire when events are outside the window."""
        state = OrderedSequenceState(
            group_key=("192.168.1.1",),
            window_duration=timedelta(minutes=5),
            total_steps=2,
        )
        t0 = datetime.now(UTC)

        # Step 1
        event1 = create_event(t0, event_type="login")
        advanced, completed = state.try_advance(
            event1, [{"event_type": "login"}, {"event_type": "data_access"}]
        )
        assert advanced
        assert completed is None

        # Step 2 comes 6 minutes later - outside window
        # The sequence expires, but this event starts a new one
        event2 = create_event(t0 + timedelta(minutes=6), event_type="data_access")
        advanced, completed = state.try_advance(
            event2, [{"event_type": "login"}, {"event_type": "data_access"}]
        )
        # Does NOT match step 0 (data_access != login), so no new sequence started
        # and the old sequence expired
        assert not advanced
        assert completed is None

    def test_different_groups_isolated(self):
        """Test that different groups have isolated sequences."""
        OrderedSequenceState(
            group_key=("192.168.1.1",),
            window_duration=timedelta(minutes=5),
            total_steps=2,
        )
        t0 = datetime.now(UTC)

        # Note: OrderedSequenceState is per-group-key, but we test logic separately
        state1 = OrderedSequenceState(
            group_key=("192.168.1.1",),
            window_duration=timedelta(minutes=5),
            total_steps=2,
        )
        state2 = OrderedSequenceState(
            group_key=("192.168.1.2",),
            window_duration=timedelta(minutes=5),
            total_steps=2,
        )

        # Group 1: Step 1 only
        event1 = create_event(t0, src_ip="192.168.1.1", event_type="login")
        state1.try_advance(event1, [{"event_type": "login"}, {"event_type": "data_access"}])

        # Group 2: Complete sequence
        event2 = create_event(t0, src_ip="192.168.1.2", event_type="login")
        state2.try_advance(event2, [{"event_type": "login"}, {"event_type": "data_access"}])
        event3 = create_event(
            t0 + timedelta(seconds=1), src_ip="192.168.1.2", event_type="data_access"
        )
        _advanced, completed = state2.try_advance(
            event3, [{"event_type": "login"}, {"event_type": "data_access"}]
        )

        assert completed is not None
        assert len(completed.steps) == 2

        # Group 1 should still be pending
        assert not state1.triggered

    def test_triggered_state_cleared(self):
        """Test that triggered state is properly managed."""
        state = OrderedSequenceState(
            group_key=("192.168.1.1",),
            window_duration=timedelta(minutes=5),
            total_steps=2,
        )
        t0 = datetime.now(UTC)

        # Complete a sequence
        event1 = create_event(t0, event_type="login")
        state.try_advance(event1, [{"event_type": "login"}, {"event_type": "data_access"}])
        event2 = create_event(t0 + timedelta(seconds=1), event_type="data_access")
        state.try_advance(event2, [{"event_type": "login"}, {"event_type": "data_access"}])

        assert state.triggered
        assert state.trigger_event_id == event2.event_id

        # Check and clear
        was_triggered, completed = state.check_and_clear_trigger(event2)
        assert was_triggered
        assert completed is not None
        assert not state.triggered

    def test_get_contributing_event_ids(self):
        """Test that contributing event IDs are collected correctly."""
        state = OrderedSequenceState(
            group_key=("192.168.1.1",),
            window_duration=timedelta(minutes=5),
            total_steps=3,
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, event_type="scan")
        state.try_advance(
            event1,
            [{"event_type": "scan"}, {"event_type": "exploit"}, {"event_type": "data_access"}],
        )
        event2 = create_event(t0 + timedelta(seconds=1), event_type="exploit")
        state.try_advance(
            event2,
            [{"event_type": "scan"}, {"event_type": "exploit"}, {"event_type": "data_access"}],
        )
        event3 = create_event(t0 + timedelta(seconds=2), event_type="data_access")
        state.try_advance(
            event3,
            [{"event_type": "scan"}, {"event_type": "exploit"}, {"event_type": "data_access"}],
        )

        was_triggered, completed = state.check_and_clear_trigger(event3)
        assert was_triggered

        ids = completed.get_contributing_event_ids()
        assert len(ids) == 3
        assert ids[0] == event1.event_id
        assert ids[1] == event2.event_id
        assert ids[2] == event3.event_id

    def test_timespan_calculation(self):
        """Test that sequence timespan is calculated correctly."""
        state = OrderedSequenceState(
            group_key=("192.168.1.1",),
            window_duration=timedelta(minutes=5),
            total_steps=2,
        )
        t0 = datetime.now(UTC)

        event1 = create_event(t0, event_type="login")
        state.try_advance(event1, [{"event_type": "login"}, {"event_type": "data_access"}])
        event2 = create_event(t0 + timedelta(seconds=10), event_type="data_access")
        state.try_advance(event2, [{"event_type": "login"}, {"event_type": "data_access"}])

        was_triggered, completed = state.check_and_clear_trigger(event2)
        assert was_triggered

        timespan = completed.get_sequence_timespan()
        assert 9.5 <= timespan <= 10.5  # Allow for timing variations


class TestOrderedSequenceDetector:
    """Tests for OrderedSequenceDetector."""

    def test_basic_sequence_detection(self):
        """Test basic 2-step sequence detection."""
        detector = OrderedSequenceDetector(
            steps=[{"event_type": "login"}, {"event_type": "data_access"}],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        # Observe and track events
        event1 = create_event(t0, event_type="login")
        event2 = create_event(t0 + timedelta(seconds=1), event_type="data_access")
        detector.observe(event1)
        detector.observe(event2)

        # Detect on the same final event that was observed
        res = detector.detect(event2)
        assert res.matched
        assert res.event_id == event2.event_id
        assert len(res.contributing_event_ids) == 2

    def test_three_step_sequence(self):
        """Test 3-step sequence detection."""
        detector = OrderedSequenceDetector(
            steps=[
                {"event_type": "scan"},
                {"event_type": "exploit"},
                {"event_type": "data_access"},
            ],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        detector.observe(create_event(t0, event_type="scan"))
        detector.observe(create_event(t0 + timedelta(seconds=1), event_type="exploit"))
        event3 = create_event(t0 + timedelta(seconds=2), event_type="data_access")
        detector.observe(event3)

        res = detector.detect(event3)
        assert res.matched
        assert len(res.contributing_event_ids) == 3

    def test_wrong_order_not_detected(self):
        """Test that wrong order events don't trigger detection."""
        detector = OrderedSequenceDetector(
            steps=[{"event_type": "login"}, {"event_type": "data_access"}],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        # Wrong order: data_access before login
        detector.observe(create_event(t0, event_type="data_access"))
        detector.observe(create_event(t0 + timedelta(seconds=1), event_type="login"))

        # Neither should trigger
        event2 = create_event(t0 + timedelta(seconds=1), event_type="login")
        res = detector.detect(event2)
        assert not res.matched

    def test_different_groups_isolated(self):
        """Test that different groups don't combine sequences."""
        detector = OrderedSequenceDetector(
            steps=[{"event_type": "login"}, {"event_type": "data_access"}],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        # Group 1: login
        detector.observe(create_event(t0, src_ip="192.168.1.1", event_type="login"))

        # Group 2: completes sequence
        detector.observe(create_event(t0, src_ip="192.168.1.2", event_type="login"))
        event2 = create_event(
            t0 + timedelta(seconds=1), src_ip="192.168.1.2", event_type="data_access"
        )
        detector.observe(event2)

        # Group 2 should trigger
        res = detector.detect(event2)
        assert res.matched

        # Group 1 should NOT trigger even when we send data_access
        event3 = create_event(
            t0 + timedelta(seconds=2), src_ip="192.168.1.1", event_type="data_access"
        )
        detector.observe(event3)
        res = detector.detect(event3)
        assert res.matched  # This starts a new sequence for group 1!

    def test_multiple_group_fields(self):
        """Test grouping by multiple fields."""
        detector = OrderedSequenceDetector(
            steps=[{"event_type": "login"}, {"event_type": "data_access"}],
            timespan=timedelta(minutes=5),
            group_by=["src_ip", "hostname"],
        )
        t0 = datetime.now(UTC)

        # Different src_ip, same hostname - different groups
        detector.observe(
            create_event(t0, src_ip="192.168.1.1", hostname="host1", event_type="login")
        )
        detector.observe(
            create_event(t0, src_ip="192.168.1.2", hostname="host1", event_type="login")
        )

        # Complete for group 2
        event2 = create_event(
            t0 + timedelta(seconds=1),
            src_ip="192.168.1.2",
            hostname="host1",
            event_type="data_access",
        )
        detector.observe(event2)

        res = detector.detect(event2)
        assert res.matched

    def test_missing_group_field(self):
        """Test handling of missing group field."""
        detector = OrderedSequenceDetector(
            steps=[{"event_type": "login"}, {"event_type": "data_access"}],
            timespan=timedelta(minutes=5),
            group_by=["username"],  # Event doesn't have username
        )
        t0 = datetime.now(UTC)

        detector.observe(create_event(t0, event_type="login"))
        event2 = create_event(t0 + timedelta(seconds=1), event_type="data_access")
        detector.observe(event2)

        res = detector.detect(event2)
        assert res.matched

    def test_timespan_exceeded_no_completion(self):
        """Test that events outside timespan don't complete sequence."""
        detector = OrderedSequenceDetector(
            steps=[{"event_type": "login"}, {"event_type": "data_access"}],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        detector.observe(create_event(t0, event_type="login"))

        # 6 minutes later - outside window
        event2 = create_event(t0 + timedelta(minutes=6), event_type="data_access")
        detector.observe(event2)

        res = detector.detect(event2)
        # Should start new sequence but not complete (only step 1)
        assert not res.matched

    def test_maximum_timespan_consistency(self):
        """Test that maximum timespan is enforced."""
        # Exactly 30 days -> accepted
        detector = OrderedSequenceDetector(
            steps=[{"event_type": "login"}, {"event_type": "data_access"}],
            timespan=timedelta(days=30),
            group_by=["src_ip"],
        )
        assert detector._timespan == timedelta(days=30)

        # Greater than 30 days -> rejected
        with pytest.raises(ValueError, match="Timespan exceeds maximum allowed duration"):
            OrderedSequenceDetector(
                steps=[{"event_type": "login"}, {"event_type": "data_access"}],
                timespan=timedelta(days=30, seconds=1),
                group_by=["src_ip"],
            )

    def test_unmatched_event_does_not_start_sequence(self):
        """Test that events not matching any step don't start sequences."""
        detector = OrderedSequenceDetector(
            steps=[{"event_type": "login"}, {"event_type": "data_access"}],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        # This event doesn't match any step
        detector.observe(create_event(t0, event_type="unrelated"))

        # Now login should start a new sequence
        event2 = create_event(t0 + timedelta(seconds=1), event_type="login")
        detector.observe(event2)

        event3 = create_event(t0 + timedelta(seconds=2), event_type="data_access")
        detector.observe(event3)

        res = detector.detect(event3)
        assert res.matched

    def test_disabled_detector_returns_no_match(self):
        """Test that disabled detector returns no match."""
        detector = OrderedSequenceDetector(
            steps=[{"event_type": "login"}, {"event_type": "data_access"}],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
            enabled=False,
        )
        t0 = datetime.now(UTC)

        detector.observe(create_event(t0, event_type="login"))
        detector.observe(create_event(t0 + timedelta(seconds=1), event_type="data_access"))

        event2 = create_event(t0 + timedelta(seconds=1), event_type="data_access")
        res = detector.detect(event2)
        assert not res.matched

    def test_re_arm_after_completion(self):
        """Test that detector can re-arm after completing a sequence."""
        detector = OrderedSequenceDetector(
            steps=[{"event_type": "login"}, {"event_type": "data_access"}],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        # First sequence
        detector.observe(create_event(t0, event_type="login"))
        event2 = create_event(t0 + timedelta(seconds=1), event_type="data_access")
        detector.observe(event2)
        res = detector.detect(event2)
        assert res.matched

        # Second sequence - wait for first to expire (5 min window)
        event3 = create_event(t0 + timedelta(minutes=6), event_type="login")
        detector.observe(event3)
        event4 = create_event(t0 + timedelta(minutes=6, seconds=1), event_type="data_access")
        detector.observe(event4)

        res = detector.detect(event4)
        assert res.matched
        assert res.event_id == event4.event_id

    def test_evidence_contains_sequence_info(self):
        """Test that DetectionResult evidence contains sequence information."""
        detector = OrderedSequenceDetector(
            steps=[{"event_type": "login"}, {"event_type": "data_access"}],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        detector.observe(create_event(t0, event_type="login"))
        event2 = create_event(t0 + timedelta(seconds=1), event_type="data_access")
        detector.observe(event2)

        res = detector.detect(event2)
        assert res.matched

        # Check evidence
        evidence_dict = {e["field"]: e["observed"] for e in res.evidence}
        assert evidence_dict["sequence_steps"] == 2
        assert evidence_dict["src_ip"] == "192.168.1.1"
        assert evidence_dict["step_types"] == ["login", "data_access"]

    def test_max_keys_limit(self):
        """Test that max keys limit is enforced."""
        detector = OrderedSequenceDetector(
            steps=[{"event_type": "login"}, {"event_type": "data_access"}],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
            max_keys=2,
        )
        t0 = datetime.now(UTC)

        # Create 5 different groups
        for i in range(5):
            detector.observe(create_event(t0, src_ip=f"192.168.1.{i}", event_type="login"))
            event = create_event(
                t0 + timedelta(seconds=1), src_ip=f"192.168.1.{i}", event_type="data_access"
            )
            detector.observe(event)

        # State should be limited to max_keys
        assert detector.get_state_keys() <= 2


class TestOrderedSequenceRuleLoader:
    """Tests for RuleLoader integration with OrderedSequenceDetector."""

    def test_parse_valid_sequence_rule(self):
        """Test parsing a valid sequence rule."""
        import os
        import tempfile

        from argusprowl.detection.rule_loader import RuleLoader

        rule_yaml = """
rule_id: test_sequence
name: "Test Sequence"
detector: OrderedSequenceDetector
enabled: true
version: 1

parameters:
  correlation:
    type: sequence
    sequence:
      steps:
        - event_type: login
        - event_type: data_access
      group_by:
        - src_ip
      timespan: 5m
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(rule_yaml)
            temp_path = f.name

        try:
            loader = RuleLoader()
            rule = loader.load_rule(temp_path)
            assert rule.rule_id == "test_sequence"
            assert rule.detector == "OrderedSequenceDetector"

            detector = loader.create_detector(rule)
            assert detector.name == "test_sequence"
            assert detector.is_enabled()
        finally:
            os.unlink(temp_path)

    def test_parse_invalid_sequence_no_steps(self):
        """Test that missing steps raises an error."""
        import os
        import tempfile

        from argusprowl.detection.rule_loader import RuleLoader

        rule_yaml = """
rule_id: test_sequence
detector: OrderedSequenceDetector
enabled: true

parameters:
  correlation:
    type: sequence
    sequence:
      steps: []
      group_by:
        - src_ip
      timespan: 5m
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(rule_yaml)
            temp_path = f.name

        try:
            loader = RuleLoader()
            rule = loader.load_rule(temp_path)
            with pytest.raises(DetectionError):
                loader.create_detector(rule)
        finally:
            os.unlink(temp_path)

    def test_parse_invalid_sequence_single_step(self):
        """Test that single step raises an error."""
        import os
        import tempfile

        from argusprowl.detection.rule_loader import RuleLoader

        rule_yaml = """
rule_id: test_sequence
detector: OrderedSequenceDetector
enabled: true

parameters:
  correlation:
    type: sequence
    sequence:
      steps:
        - event_type: login
      group_by:
        - src_ip
      timespan: 5m
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(rule_yaml)
            temp_path = f.name

        try:
            loader = RuleLoader()
            rule = loader.load_rule(temp_path)
            with pytest.raises((DetectionError, ValueError)):
                loader.create_detector(rule)
        finally:
            os.unlink(temp_path)

    def test_parse_invalid_timespan(self):
        """Test that invalid timespan raises an error."""
        import os
        import tempfile

        from argusprowl.detection.rule_loader import RuleLoader

        rule_yaml = """
rule_id: test_sequence
detector: OrderedSequenceDetector
enabled: true

parameters:
  correlation:
    type: sequence
    sequence:
      steps:
        - event_type: login
        - event_type: data_access
      group_by:
        - src_ip
      timespan: invalid
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(rule_yaml)
            temp_path = f.name

        try:
            loader = RuleLoader()
            rule = loader.load_rule(temp_path)
            with pytest.raises(DetectionError):
                loader.create_detector(rule)
        finally:
            os.unlink(temp_path)

    def test_parse_invalid_group_by(self):
        """Test that invalid group_by raises an error."""
        import os
        import tempfile

        from argusprowl.detection.rule_loader import RuleLoader

        rule_yaml = """
rule_id: test_sequence
detector: OrderedSequenceDetector
enabled: true

parameters:
  correlation:
    type: sequence
    sequence:
      steps:
        - event_type: login
        - event_type: data_access
      group_by:
        - invalid_field
      timespan: 5m
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(rule_yaml)
            temp_path = f.name

        try:
            loader = RuleLoader()
            rule = loader.load_rule(temp_path)
            with pytest.raises(DetectionError):
                loader.create_detector(rule)
        finally:
            os.unlink(temp_path)

    def test_parse_invalid_step_field(self):
        """Test that invalid step field raises an error."""
        import os
        import tempfile

        from argusprowl.detection.rule_loader import RuleLoader

        rule_yaml = """
rule_id: test_sequence
detector: OrderedSequenceDetector
enabled: true

parameters:
  correlation:
    type: sequence
    sequence:
      steps:
        - invalid_field: value
        - event_type: data_access
      group_by:
        - src_ip
      timespan: 5m
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(rule_yaml)
            temp_path = f.name

        try:
            loader = RuleLoader()
            rule = loader.load_rule(temp_path)
            with pytest.raises(DetectionError):
                loader.create_detector(rule)
        finally:
            os.unlink(temp_path)


class TestOrderedSequenceReplay:
    """Tests for replay integration."""

    def test_semantic_replay_sequence(self) -> None:
        """Test semantic replay sequence with OrderedSequenceDetector."""
        from argusprowl.detection.detection_manager import DetectionManager
        from argusprowl.replay.replay_engine import ReplayEngine

        log_path = Path("/tmp/test_sequence_replay.log")
        base_time = datetime.now(UTC)

        # Create events for a 3-step sequence
        events = [
            create_event(timestamp=base_time, src_ip="10.0.0.1", event_type="scan"),
            create_event(
                timestamp=base_time + timedelta(seconds=1), src_ip="10.0.0.1", event_type="exploit"
            ),
            create_event(
                timestamp=base_time + timedelta(seconds=2),
                src_ip="10.0.0.1",
                event_type="data_access",
            ),
        ]

        # Add a second sequence for same IP after window expires
        events.extend(
            [
                create_event(
                    timestamp=base_time + timedelta(minutes=6), src_ip="10.0.0.1", event_type="scan"
                ),
                create_event(
                    timestamp=base_time + timedelta(minutes=6, seconds=1),
                    src_ip="10.0.0.1",
                    event_type="exploit",
                ),
                create_event(
                    timestamp=base_time + timedelta(minutes=6, seconds=2),
                    src_ip="10.0.0.1",
                    event_type="data_access",
                ),
            ]
        )

        class MockReplayReader:
            def __init__(self, log_path):
                self._log_path = log_path

            def read_events(self):
                yield from events

        try:
            detector = OrderedSequenceDetector(
                steps=[
                    {"event_type": "scan"},
                    {"event_type": "exploit"},
                    {"event_type": "data_access"},
                ],
                timespan=timedelta(minutes=5),
                group_by=["src_ip"],
            )
            manager = DetectionManager()
            manager.register_detector(detector)

            results = []

            class CapturingReplayEngine(ReplayEngine):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self._reader = MockReplayReader(kwargs.get("log_path"))

                def _process_replay_event(self, event, on_feature_vector=None):
                    res = super()._process_replay_event(event, on_feature_vector)
                    results.extend([r for r in res if r.matched])
                    return res

            with log_path.open("w") as f:
                f.write("")

            replay = CapturingReplayEngine(
                log_path=log_path,
                detection_manager=manager,
            )
            replay.run()

            # Should have 2 detections
            assert len(results) == 2

            # First detection
            res1 = results[0]
            assert res1.event_id == events[2].event_id
            assert len(res1.contributing_event_ids) == 3

            # Second detection
            res2 = results[1]
            assert res2.event_id == events[5].event_id
            assert len(res2.contributing_event_ids) == 3

        finally:
            log_path.unlink(missing_ok=True)
