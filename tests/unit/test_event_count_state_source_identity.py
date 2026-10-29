"""Regression tests for source-scoped deduplication and event-time ordering."""

from datetime import UTC, datetime, timedelta

from argusprowl.detection.detectors.event_count_state import EventCountState
from argusprowl.models.normalized_event import NormalizedEvent


def _event(
    *,
    timestamp: datetime,
    hostname: str,
    record_id: str,
    channel: str = "Security",
) -> NormalizedEvent:
    return NormalizedEvent(
        source_type="windows_event_log",
        event_type="authentication_failure",
        timestamp=timestamp,
        hostname=hostname,
        source_record_id=record_id,
        metadata={"channel": channel},
    )


def test_source_record_ids_are_scoped_to_host_and_channel() -> None:
    now = datetime.now(UTC)
    state = EventCountState(("src",), timedelta(minutes=5))

    host_a = _event(timestamp=now, hostname="host-a", record_id="42")
    host_b = _event(timestamp=now + timedelta(seconds=1), hostname="host-b", record_id="42")
    host_a_duplicate = _event(
        timestamp=now + timedelta(seconds=2), hostname="host-a", record_id="42"
    )
    host_a_other_channel = _event(
        timestamp=now + timedelta(seconds=3),
        hostname="host-a",
        record_id="42",
        channel="System",
    )

    assert state.add(host_a) is True
    assert state.add(host_b) is True
    assert state.add(host_a_duplicate) is False
    assert state.add(host_a_other_channel) is True
    assert state.count == 3


def test_late_events_are_inserted_in_event_time_order() -> None:
    now = datetime.now(UTC)
    state = EventCountState(("src",), timedelta(minutes=5))
    newest = _event(timestamp=now, hostname="host-a", record_id="3")
    oldest = _event(
        timestamp=now - timedelta(seconds=30), hostname="host-a", record_id="1"
    )
    middle = _event(
        timestamp=now - timedelta(seconds=10), hostname="host-a", record_id="2"
    )

    assert state.add(newest)
    assert state.add(oldest)
    assert state.add(middle)
    assert [item.timestamp for item in state.observations] == [
        oldest.timestamp,
        middle.timestamp,
        newest.timestamp,
    ]
    assert state.get_timespan() == 30.0


def test_events_older_than_newest_active_window_are_rejected() -> None:
    now = datetime.now(UTC)
    state = EventCountState(("src",), timedelta(seconds=60))
    assert state.add(_event(timestamp=now, hostname="host-a", record_id="new"))

    stale = _event(
        timestamp=now - timedelta(seconds=61), hostname="host-a", record_id="stale"
    )
    assert state.add(stale) is False
    assert [item.source_record_id for item in state.observations] == ["new"]
