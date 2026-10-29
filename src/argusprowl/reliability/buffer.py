"""A bounded, FIFO ingestion buffer with explicit overload policy."""

import logging
import time
from collections import deque
from enum import StrEnum
from threading import Condition
from typing import TypeVar

from argusprowl.metrics.collector import MetricsCollector
from argusprowl.metrics.metrics import Counter, Gauge, Histogram

T = TypeVar("T")


class OverflowPolicy(StrEnum):
    """Behaviour when a bounded buffer is full."""

    BLOCK = "block"
    DROP_NEWEST = "drop_newest"
    DROP_OLDEST = "drop_oldest"


class BoundedIngestionBuffer[T]:
    """Thread-safe FIFO buffer with O(1) enqueue/dequeue and O(capacity) memory.

    The default rejects the newest event.  This keeps the existing queued
    sequence intact and, importantly, makes data loss observable rather than
    silently making producers wait forever.  Callers can choose ``BLOCK`` when
    their source can safely apply backpressure.
    """

    def __init__(
        self,
        max_size: int,
        overflow_policy: OverflowPolicy | str = OverflowPolicy.DROP_NEWEST,
        metrics_collector: MetricsCollector | None = None,
    ) -> None:
        if not isinstance(max_size, int) or max_size <= 0:
            raise ValueError("max_size must be a positive integer")
        self.max_size = max_size
        self.overflow_policy = OverflowPolicy(overflow_policy)
        self._items: deque[T] = deque()
        self._condition = Condition()
        self._closed = False
        self._logger = logging.getLogger("argusprowl.reliability.buffer")
        self.events_received = self._counter(metrics_collector, "events_received")
        self.events_buffered = self._counter(metrics_collector, "events_buffered")
        self.events_processed = self._counter(metrics_collector, "events_processed")
        self.events_dropped = self._counter(metrics_collector, "events_dropped")
        self.enqueue_count = self._counter(metrics_collector, "enqueue_count")
        self.dequeue_count = self._counter(metrics_collector, "dequeue_count")
        self.rejected_count = self._counter(metrics_collector, "rejected_count")
        self.blocked_producer_count = self._counter(metrics_collector, "blocked_producer_count")
        self.queue_depth = self._gauge(metrics_collector, "queue_depth")
        self.max_queue_depth = self._gauge(metrics_collector, "max_queue_depth")
        self.consumer_processing_latency = self._histogram(
            metrics_collector, "consumer_processing_latency_seconds"
        )

    @staticmethod
    def _counter(metrics: MetricsCollector | None, name: str) -> Counter:
        if metrics is None:
            return Counter(name)
        try:
            return metrics.get_counter(name)
        except KeyError:
            return metrics.register_counter(name)

    @staticmethod
    def _gauge(metrics: MetricsCollector | None, name: str) -> Gauge:
        if metrics is None:
            return Gauge(name)
        try:
            return metrics.get_gauge(name)
        except KeyError:
            return metrics.register_gauge(name)

    @staticmethod
    def _histogram(metrics: MetricsCollector | None, name: str) -> Histogram:
        if metrics is None:
            return Histogram(name)
        try:
            return metrics.get_histogram(name)
        except KeyError:
            return metrics.register_histogram(name)

    def put(self, item: T, timeout: float | None = None) -> bool:
        """Add an item, returning ``False`` for explicit rejection/closure."""
        self.events_received.increment()
        with self._condition:
            if self._closed:
                self.rejected_count.increment()
                self.events_dropped.increment()
                return False
            if len(self._items) >= self.max_size:
                if self.overflow_policy is OverflowPolicy.DROP_OLDEST:
                    self._items.popleft()
                    self.events_dropped.increment()
                    self._logger.warning("Ingestion buffer saturated; dropped oldest event")
                elif self.overflow_policy is OverflowPolicy.DROP_NEWEST:
                    self.events_dropped.increment()
                    self.rejected_count.increment()
                    self._logger.warning("Ingestion buffer saturated; rejected newest event")
                    return False
                else:
                    self.blocked_producer_count.increment()
                    deadline = None if timeout is None else time.monotonic() + timeout
                    while len(self._items) >= self.max_size and not self._closed:
                        remaining = None if deadline is None else deadline - time.monotonic()
                        if remaining is not None and remaining <= 0:
                            self.rejected_count.increment()
                            self.events_dropped.increment()
                            return False
                        self._condition.wait(remaining)
                    if self._closed:
                        self.rejected_count.increment()
                        self.events_dropped.increment()
                        return False
            self._items.append(item)
            depth = len(self._items)
            self.enqueue_count.increment()
            self.events_buffered.increment()
            self.queue_depth.set(depth)
            if depth > self.max_queue_depth.get_value():
                self.max_queue_depth.set(depth)
            self._condition.notify()
            return True

    def get(self, timeout: float | None = None) -> T | None:
        """Remove the oldest item, or return ``None`` after timeout/closure."""
        with self._condition:
            deadline = None if timeout is None else time.monotonic() + timeout
            while not self._items and not self._closed:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return None
                self._condition.wait(remaining)
            if not self._items:
                return None
            item = self._items.popleft()
            self.dequeue_count.increment()
            self.events_processed.increment()
            self.queue_depth.set(len(self._items))
            self._condition.notify_all()
            return item

    def record_processing_latency(self, seconds: float) -> None:
        self.consumer_processing_latency.observe(max(0.0, seconds))

    def close(self) -> None:
        """Stop accepting work and wake blocked producers/consumers."""
        with self._condition:
            self._closed = True
            self._condition.notify_all()

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

    def __len__(self) -> int:
        with self._condition:
            return len(self._items)

    def empty(self) -> bool:
        """Return True when no items are currently queued."""
        with self._condition:
            return not self._items

    def get_nowait(self) -> T:
        """Remove and return an item without blocking.

        Raises:
            queue.Empty: If the buffer is empty or closed.
        """
        import queue

        item = self.get(timeout=0)
        if item is None:
            raise queue.Empty
        return item
