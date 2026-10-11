"""Tests for OrderedSequenceDetector re-arm behavior."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from argusprowl.detection.detectors.ordered_sequence_correlation import OrderedSequenceDetector
from argusprowl.models.normalized_event import NormalizedEvent


def create_event(timestamp, event_type, **kwargs):
    return NormalizedEvent(
        event_id=uuid4(),
        timestamp=timestamp,
        event_type=event_type,
        source_type="test",
        src_ip="192.168.1.1",
        **kwargs,
    )


def test_sequence_rearm():
    """
    Test that completion does not suppress a genuinely new sequence.
    Scenario: A -> B -> complete, A -> B -> complete
    """
    detector = OrderedSequenceDetector(
        steps=[{"event_type": "A"}, {"event_type": "B"}],
        timespan=timedelta(minutes=5),
    )
    t0 = datetime.now(UTC)

    # First sequence
    e1 = create_event(t0, "A")
    e2 = create_event(t0 + timedelta(seconds=1), "B")
    detector.observe(e1)
    detector.observe(e2)
    res1 = detector.detect(e2)
    assert res1.matched

    # Second sequence
    e3 = create_event(t0 + timedelta(seconds=2), "A")
    e4 = create_event(t0 + timedelta(seconds=3), "B")
    detector.observe(e3)
    detector.observe(e4)
    res2 = detector.detect(e4)
    assert res2.matched


def test_overlapping_sequences():
    """
    Test overlapping sequences: A -> A -> B
    If the rule is A -> B, then the second A should start a new sequence.
    """
    detector = OrderedSequenceDetector(
        steps=[{"event_type": "A"}, {"event_type": "B"}],
        timespan=timedelta(minutes=5),
    )
    t0 = datetime.now(UTC)

    # Event 1: A (starts Seq 1)
    e1 = create_event(t0, "A")
    detector.observe(e1)

    # Event 2: A (starts Seq 2, Seq 1 is still at step 0)
    e2 = create_event(t0 + timedelta(seconds=1), "A")
    detector.observe(e2)

    # Event 3: B (completes Seq 1 AND Seq 2)
    e3 = create_event(t0 + timedelta(seconds=2), "B")
    detector.observe(e3)

    # The detector.detect(e3) should return a result.
    res = detector.detect(e3)
    assert res.matched
    # Since both completed, the state should have been triggered.
    # After detect(e3), the trigger is cleared.

    # If we observe another B, it shouldn't match anything.
    e4 = create_event(t0 + timedelta(seconds=3), "B")
    detector.observe(e4)
    res2 = detector.detect(e4)
    assert not res2.matched
