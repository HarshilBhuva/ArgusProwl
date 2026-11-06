"""Event-time ordering and eviction tests for SlidingWindow."""

from datetime import UTC, datetime, timedelta

from argusprowl.feature_engineering.sliding_window import SlidingWindow
from argusprowl.models.normalized_event import NormalizedEvent


def _event(timestamp: datetime, uid: str) -> NormalizedEvent:
    return NormalizedEvent(
        source_type="test",
        event_type="network_connection",
        timestamp=timestamp,
        src_ip="192.0.2.10",
        dst_ip="203.0.113.10",
        dst_port=443,
        attributes={"uid": uid},
    )


def test_sliding_window_keeps_out_of_order_events_sorted() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    window = SlidingWindow(window_size_seconds=60)
    for offset in (0, 20, 10, 30, 25):
        window.add(_event(start + timedelta(seconds=offset), str(offset)))

    events = window.get_events(start + timedelta(seconds=30))
    assert [event.timestamp for event in events] == sorted(
        event.timestamp for event in events
    )
    assert [event.attributes["uid"] for event in events] == ["0", "10", "20", "25", "30"]


def test_sliding_window_drops_events_older_than_watermark_cutoff() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    window = SlidingWindow(window_size_seconds=10)
    window.add(_event(start, "current"))
    window.add(_event(start + timedelta(seconds=20), "advance"))
    window.add(_event(start + timedelta(seconds=1), "too-late"))

    events = window.get_events(start + timedelta(seconds=20))
    assert [event.attributes["uid"] for event in events] == ["advance"]


def test_sliding_window_capacity_evicts_oldest_event_time() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    window = SlidingWindow(window_size_seconds=3600, max_events=2)
    for offset in (0, 20, 10):
        window.add(_event(start + timedelta(seconds=offset), str(offset)))

    events = window.get_events(start + timedelta(seconds=20))
    assert [event.attributes["uid"] for event in events] == ["10", "20"]
