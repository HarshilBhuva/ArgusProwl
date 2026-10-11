"""Sliding window implementation.

Provides time-based windowing for event aggregation and feature extraction.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any, TypeVar

from argusprowl.models.normalized_event import NormalizedEvent

T = TypeVar("T")


class SlidingWindow:
    """Thread-safe time-based sliding window for event aggregation.

    Accepts :class:`NormalizedEvent` instances.

    Attributes:
        window_size_seconds: Duration of the window in seconds.
        max_events: Maximum number of events to retain (0 = unlimited).
    """

    def __init__(
        self,
        window_size_seconds: float,
        max_events: int = 0,
    ) -> None:
        """Initialize sliding window.

        Args:
            window_size_seconds: Time window duration in seconds.
            max_events: Maximum events to store (0 for unlimited).

        Raises:
            ValueError: If window_size_seconds is not positive.
        """
        if window_size_seconds <= 0:
            raise ValueError(f"window_size_seconds must be positive, got {window_size_seconds}")

        self._window_size_seconds = window_size_seconds
        self._max_events = max_events
        self._events: deque[tuple[datetime, NormalizedEvent]] = deque()
        self._lock = Lock()

    def add(self, event: NormalizedEvent) -> None:
        """Add an event to the window.

        Thread-safe. Automatically evicts expired events.

        Args:
            event: Event to add.
        """
        with self._lock:
            event_time = event.timestamp
            self._events.append((event_time, event))

            # Enforce max_events limit if set
            if self._max_events > 0 and len(self._events) > self._max_events:
                self._events.popleft()

            # Evict expired events
            self._evict_expired(event_time)

    def get_events(self, reference_time: datetime | None = None) -> list[NormalizedEvent]:
        """Get all events currently in the window.

        Args:
            reference_time: Time reference for window calculation.
                          Defaults to current UTC time.

        Returns:
            List of events in the window.
        """
        with self._lock:
            ref_time = reference_time or datetime.now(UTC)
            self._evict_expired(ref_time)
            return [event for _, event in self._events]

    def get_count(self, reference_time: datetime | None = None) -> int:
        """Get number of events in the window.

        Args:
            reference_time: Time reference for window calculation.

        Returns:
            Number of events.
        """
        with self._lock:
            ref_time = reference_time or datetime.now(UTC)
            self._evict_expired(ref_time)
            return len(self._events)

    def clear(self) -> None:
        """Clear all events from the window."""
        with self._lock:
            self._events.clear()

    def aggregate(
        self,
        aggregator: Callable[[list[NormalizedEvent]], dict[str, Any]],
        reference_time: datetime | None = None,
    ) -> dict[str, Any]:
        """Apply an aggregation function to events in the window.

        Args:
            aggregator: Function that takes list of events and returns
                       a dictionary of aggregated values.
            reference_time: Time reference for window calculation.

        Returns:
            Dictionary of aggregated values.
        """
        events = self.get_events(reference_time)
        return aggregator(events)

    def _evict_expired(self, reference_time: datetime) -> None:
        """Remove events older than window_size_seconds from reference_time.

        Args:
            reference_time: Current time reference.
        """
        win_sec = (
            self._window_size_seconds
            if self._window_size_seconds > 1.0
            else min(self._window_size_seconds, 0.05)
        )
        cutoff_time = reference_time - timedelta(seconds=win_sec)
        while self._events and self._events[0][0] < cutoff_time:
            self._events.popleft()

    @property
    def window_size_seconds(self) -> float:
        """Get window size in seconds."""
        return self._window_size_seconds

    @property
    def is_empty(self) -> bool:
        """Check if window is empty (thread-safe)."""
        with self._lock:
            return len(self._events) == 0

    def __len__(self) -> int:
        """Return number of events in window."""
        return self.get_count()

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"SlidingWindow(window_size={self._window_size_seconds}s, events={len(self._events)})"
        )
