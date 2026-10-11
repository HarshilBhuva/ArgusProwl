"""Tests for OrderedSequenceDetector timespan enforcement."""

from datetime import timedelta

import pytest

from argusprowl.detection.detectors.ordered_sequence_correlation import OrderedSequenceDetector


def test_timespan_maximum_enforcement():
    """Test that timespans exceeding MAX_ALLOWED_TIMESPAN are rejected."""
    # MAX_ALLOWED_TIMESPAN is 30 days. Try 31 days.
    with pytest.raises(ValueError, match="Timespan exceeds maximum allowed duration"):
        OrderedSequenceDetector(
            steps=[{"event_type": "a"}, {"event_type": "b"}],
            timespan=timedelta(days=31),
        )


def test_timespan_within_limit_accepted():
    """Test that timespans within the limit are accepted."""
    # 30 days should be accepted.
    detector = OrderedSequenceDetector(
        steps=[{"event_type": "a"}, {"event_type": "b"}],
        timespan=timedelta(days=30),
    )
    assert detector._timespan == timedelta(days=30)
