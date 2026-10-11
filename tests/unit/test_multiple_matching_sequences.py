"""Regression tests for OrderedSequenceState multiple matching sequences."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from argusprowl.detection.detectors.ordered_sequence_state import OrderedSequenceState
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


def test_multiple_matching_partial_sequences():
    """
    Test case:
    - Two valid partial sequences exist for the same group.
    - A new event matches the next expected step of BOTH sequences.
    - Verify if advancing only the first one loses a valid detection.
    """
    state = OrderedSequenceState(
        group_key=("192.168.1.1",),
        window_duration=timedelta(minutes=5),
        total_steps=3,
    )
    t0 = datetime.now(UTC)

    # Sequence 1: Step 0
    e1 = create_event(t0, "step0")
    state.try_advance(
        e1, [{"event_type": "step0"}, {"event_type": "step1"}, {"event_type": "step2"}]
    )

    # Sequence 2: Step 0 (starts a second partial sequence)
    e2 = create_event(t0 + timedelta(seconds=1), "step0")
    state.try_advance(
        e2, [{"event_type": "step0"}, {"event_type": "step1"}, {"event_type": "step2"}]
    )

    # Now we have two sequences at step 0.
    # Event e3 matches step 1 for BOTH.
    e3 = create_event(t0 + timedelta(seconds=2), "step1")
    advanced, completed = state.try_advance(
        e3, [{"event_type": "step0"}, {"event_type": "step1"}, {"event_type": "step2"}]
    )

    assert advanced
    assert completed is None

    # Current implementation: only the FIRST matching sequence is advanced.
    # Sequence 1 is now at step 1. Sequence 2 is still at step 0.

    # Event e4 matches step 2 for Sequence 1 AND step 1 for Sequence 2.
    e4 = create_event(t0 + timedelta(seconds=3), "step2")
    advanced, completed = state.try_advance(
        e4, [{"event_type": "step0"}, {"event_type": "step1"}, {"event_type": "step2"}]
    )

    # Sequence 1 should complete.
    assert advanced
    assert completed is not None
    assert len(completed.steps) == 3
    assert completed.steps[0].event.event_id in [e1.event_id, e2.event_id]
    assert completed.steps[1].event.event_id == e3.event_id
    assert completed.steps[2].event.event_id == e4.event_id

    # Now, if we had another event e5 that matched step 2 for Sequence 2...
    # But wait, Sequence 2 is still at step 0. It needs step 1.
    # If e3 was consumed by Sequence 1, Sequence 2 missed its chance to advance to step 1.
    # If e3 could have advanced BOTH, then Sequence 2 would also be at step 1.

    # Let's test if we lose a detection.
    # Scenario:
    # Seq 1: Step 0 (e1) -> Step 1 (e3) -> Step 2 (e4)  -- DETECTED
    # Seq 2: Step 0 (e2) -> Step 1 (e3) -> Step 2 (e5)  -- SHOULD BE DETECTED if e3 advances both

    state2 = OrderedSequenceState(
        group_key=("192.168.1.1",),
        window_duration=timedelta(minutes=5),
        total_steps=3,
    )
    t0 = datetime.now(UTC)
    e1 = create_event(t0, "step0")
    state2.try_advance(
        e1, [{"event_type": "step0"}, {"event_type": "step1"}, {"event_type": "step2"}]
    )
    e2 = create_event(t0 + timedelta(seconds=1), "step0")
    state2.try_advance(
        e2, [{"event_type": "step0"}, {"event_type": "step1"}, {"event_type": "step2"}]
    )

    # e3 matches step 1 for both.
    e3 = create_event(t0 + timedelta(seconds=2), "step1")
    rule = [{"event_type": "step0"}, {"event_type": "step1"}, {"event_type": "step2"}]
    state2.try_advance(e3, rule)

    # e4 matches step 2 for Seq 1.
    e4 = create_event(t0 + timedelta(seconds=3), "step2")
    state2.try_advance(e4, rule)

    # e5 matches step 2 for Seq 2.
    e5 = create_event(t0 + timedelta(seconds=4), "step2")
    advanced, completed = state2.try_advance(e5, rule)

    # If e3 advanced both, then Seq 2 should be at step 1 and e4 should have completed it too.
    # Wait, if e4 matches step 2, it completes ALL sequences at step 1.
    # So Seq 1 and Seq 2 both complete on e4.
    # Then e5 will not complete anything because there are no more sequences at step 1.
    # This means the test should expect completion on e4.
    assert completed is None, (
        "e5 should not complete anything because e4 already completed all sequences"
    )
