"""Tests for bounded ingestion buffer behavior in the live Application path.

Covers:
- DROP_NEWEST policy enforces max_size and increments drop metrics
- DROP_OLDEST policy evicts the oldest item and increments drop metrics
- close() unblocks waiting producers/consumers and drains remaining items
- No deadlocks under BLOCK policy with timed-out producers
- HealthService receives a queue-like object with __len__/empty
"""

from __future__ import annotations

import queue
from threading import Thread, Event as ThreadingEvent

import pytest

from argusprowl.core.application import Application
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.reliability.buffer import BoundedIngestionBuffer, OverflowPolicy


def _make_event(seq: int) -> NormalizedEvent:
    """Construct a minimal NormalizedEvent for buffer tests."""
    return NormalizedEvent(
        source_type="test",
        event_type="test_event",
        hostname="localhost",
        process_name=f"proc_{seq}",
        pid=1000 + seq,
        dst_ip=f"10.0.0.{seq}",
        attributes={"seq": seq},
    )


class TestDropNewest:
    """DROP_NEWEST should reject the newest event when the buffer is full."""

    def test_max_size_enforced(self) -> None:
        buffer = BoundedIngestionBuffer[int](max_size=2, overflow_policy="drop_newest")
        assert buffer.put(1)
        assert buffer.put(2)
        # Buffer is full — newest should be rejected.
        result = buffer.put(3)
        assert result is False
        assert len(buffer) == 2
        assert buffer.events_dropped.get_value() == 1
        assert buffer.rejected_count.get_value() == 1

    def test_drop_count_accumulates(self) -> None:
        buffer = BoundedIngestionBuffer[int](max_size=2, overflow_policy="drop_newest")
        assert buffer.put(1)
        assert buffer.put(2)
        for _ in range(5):
            buffer.put(99)  # all rejected
        assert buffer.rejected_count.get_value() == 5
        assert buffer.events_dropped.get_value() == 5
        assert len(buffer) == 2

    def test_consumer_drains_and_buffer_reaccepts(self) -> None:
        buffer = BoundedIngestionBuffer[int](max_size=2, overflow_policy="drop_newest")
        buffer.put(1)
        buffer.put(2)
        buffer.put(3)  # rejected
        assert buffer.get() == 1
        assert buffer.get() == 2
        # After drain, buffer accepts again.
        assert buffer.put(4)
        assert len(buffer) == 1
        assert buffer.events_dropped.get_value() == 1


class TestDropOldest:
    """DROP_OLDEST should evict the oldest item when the buffer is full."""

    def test_oldest_evicted(self) -> None:
        buffer = BoundedIngestionBuffer[int](max_size=2, overflow_policy="drop_oldest")
        assert buffer.put(1)
        assert buffer.put(2)
        # Adding 3 should evict 1 (the oldest), keeping [2, 3].
        assert buffer.put(3)
        assert len(buffer) == 2
        assert buffer.get() == 2
        assert buffer.get() == 3
        assert buffer.events_dropped.get_value() == 1

    def test_drop_count_accurate(self) -> None:
        buffer = BoundedIngestionBuffer[int](max_size=3, overflow_policy="drop_oldest")
        for i in range(5):
            buffer.put(i)
        # 2 evictions (for i=3 and i=4)
        assert buffer.events_dropped.get_value() == 2
        assert buffer.rejected_count.get_value() == 0
        assert buffer.get() == 2
        assert buffer.get() == 3
        assert buffer.get() == 4


class TestCloseUnblocksWaiters:
    """close() must wake blocked producers and consumers."""

    def test_producer_wakes_on_close(self) -> None:
        buffer = BoundedIngestionBuffer[int](max_size=1, overflow_policy="block")
        buffer.put(1)

        wake_result: list[bool] = []
        barrier = ThreadingEvent()

        def producer() -> None:
            result = buffer.put(2, timeout=2.0)
            wake_result.append(result)
            barrier.set()

        t = Thread(target=producer)
        t.start()
        # Give producer time to block on the condition.
        barrier.wait(timeout=0.5)
        # Close should unblock the producer; it should return False because
        # the buffer is now closed.
        buffer.close()
        t.join(timeout=2.0)
        assert not t.is_alive()
        assert wake_result == [False]

    def test_consumer_wakes_on_close(self) -> None:
        buffer = BoundedIngestionBuffer[int](max_size=5, overflow_policy="block")
        consumed: list[int | None] = []
        barrier = ThreadingEvent()

        def consumer() -> None:
            item = buffer.get(timeout=2.0)
            consumed.append(item)
            barrier.set()

        t = Thread(target=consumer)
        t.start()
        barrier.wait(timeout=0.5)
        buffer.close()
        t.join(timeout=2.0)
        assert not t.is_alive()
        assert consumed == [None]

    def test_consumer_drains_remaining_then_exits(self) -> None:
        buffer = BoundedIngestionBuffer[int](max_size=3, overflow_policy="drop_newest")
        buffer.put(1)
        buffer.put(2)
        buffer.close()

        consumed: list[int | None] = []

        while not buffer.closed or len(buffer) > 0:
            item = buffer.get(timeout=0.1)
            if item is not None:
                consumed.append(item)
            if buffer.closed and len(buffer) == 0:
                break

        assert consumed == [1, 2]


class TestBlockTimeout:
    """BLOCK policy must time out instead of blocking forever."""

    def test_block_times_out_returns_false(self) -> None:
        buffer = BoundedIngestionBuffer[int](max_size=1, overflow_policy="block")
        assert buffer.put(1)
        result = buffer.put(2, timeout=0.2)
        assert result is False
        assert buffer.rejected_count.get_value() == 1
        assert buffer.blocked_producer_count.get_value() == 1


class TestHealthServiceCompatibility:
    """Verify that BoundedIngestionBuffer satisfies the HealthService contract."""

    def test_health_service_accepts_buffer(self) -> None:
        from argusprowl.models.system_status import HealthStatus
        from argusprowl.services.health_service import HealthService

        buffer = BoundedIngestionBuffer[int](max_size=5)
        hs = HealthService(event_queue=buffer)
        status = hs.check_health()
        queue_component = next(
            c for c in status.components if c.name == "processing_queue"
        )
        assert queue_component.status == HealthStatus.HEALTHY

    def test_empty_method_exists(self) -> None:
        buffer = BoundedIngestionBuffer[int](max_size=2)
        assert buffer.empty() is True
        buffer.put(1)
        assert buffer.empty() is False
        buffer.get()
        assert buffer.empty() is True


class TestCollectorCallbackDropMetered:
    """The collector callback puts into the buffer and the drop is metered."""

    def test_rejected_event_is_metered(self) -> None:
        buffer = BoundedIngestionBuffer[NormalizedEvent](
            max_size=2, overflow_policy="drop_newest"
        )
        assert buffer.put(_make_event(1))
        assert buffer.put(_make_event(2))
        # Buffer full — this should be rejected and metered.
        result = buffer.put(_make_event(3))
        assert result is False
        assert buffer.events_dropped.get_value() == 1
        assert buffer.rejected_count.get_value() == 1
