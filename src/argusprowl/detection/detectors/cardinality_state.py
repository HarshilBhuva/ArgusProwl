"""Cardinality correlation state tracking.

Provides bounded in-memory state for counting unique values within time windows,
grouped by configurable fields. Used by CardinalityCorrelationDetector.
"""

from __future__ import annotations

from collections import Counter, deque
from datetime import timedelta
from threading import Lock
from typing import Any

from argusprowl.models.normalized_event import NormalizedEvent


class CardinalityState:
    """Bounded state for cardinality correlation.

    Tracks unique values of a specific field within a sliding time window,
    grouped by a key tuple. Enforces capacity limits via LRU/FIFO eviction.

    Attributes:
        group_key: The grouping key tuple (e.g., src_ip).
        window_duration: Maximum age of observations before expiration.
        max_observations: Hard limit on observations per key.
    """

    def __init__(
        self,
        group_key: tuple[str, ...],
        window_duration: timedelta,
        max_observations: int = 1000,
    ) -> None:
        """Initialize cardinality state.

        Args:
            group_key: Tuple of field values identifying this group.
            window_duration: Sliding window duration for event retention.
            max_observations: Maximum observations to retain per key.
        """
        self._group_key = group_key
        self._window_duration = window_duration
        self._max_observations = max_observations

        # deque of (timestamp, event_id, cardinality_value)
        self._observations: deque[tuple[Any, Any, Any]] = deque(maxlen=max_observations)
        self._unique_counts: Counter[Any] = Counter()

        self._triggered = False
        self._trigger_event_id: Any = None
        self._trigger_count: int = 0
        self._lock = Lock()

    @property
    def group_key(self) -> tuple[str, ...]:
        """Return the grouping key."""
        return self._group_key

    @property
    def unique_count(self) -> int:
        """Return current unique value count within window."""
        with self._lock:
            return len(self._unique_counts)

    @property
    def triggered(self) -> bool:
        """Return whether threshold has been crossed."""
        with self._lock:
            return self._triggered

    @property
    def trigger_event_id(self) -> Any:
        """Return the triggering event ID."""
        with self._lock:
            return self._trigger_event_id

    @property
    def trigger_count(self) -> int:
        """Return the unique count at threshold crossing."""
        with self._lock:
            return self._trigger_count

    def _expire_old_observations(self, reference_time: Any) -> None:
        """Remove observations older than the window duration.

        Must be called with lock held.
        """
        cutoff = reference_time - self._window_duration
        while self._observations and self._observations[0][0] < cutoff:
            _, _, val = self._observations.popleft()
            self._unique_counts[val] -= 1
            if self._unique_counts[val] <= 0:
                del self._unique_counts[val]

    def add(self, event: NormalizedEvent, cardinality_value: Any) -> bool:
        """Add an event and its cardinality value to this group's observations.

        Expired events are removed before adding. Returns False if the
        event was a duplicate (same event_id).

        Args:
            event: The event to add.
            cardinality_value: The value to track for uniqueness.

        Returns:
            True if added, False if duplicate event.
        """
        with self._lock:
            self._expire_old_observations(event.timestamp)

            # Check for duplicate event_id
            for _, eid, _ in self._observations:
                if eid == event.event_id:
                    return False

            # If we are at max capacity, the deque will automatically popleft.
            # We need to manually update the counter for the evicted item.
            if len(self._observations) == self._max_observations:
                _, _, evicted_val = self._observations[0]
                self._unique_counts[evicted_val] -= 1
                if self._unique_counts[evicted_val] <= 0:
                    del self._unique_counts[evicted_val]

            self._observations.append((event.timestamp, event.event_id, cardinality_value))
            self._unique_counts[cardinality_value] += 1
            return True

    def check_threshold(
        self, threshold: int, event: NormalizedEvent | None = None
    ) -> tuple[bool, int, Any]:
        """Check if threshold is met and return detection info.

        Args:
            threshold: Minimum unique count to trigger detection.
            event: Optional event whose timestamp defines the window.

        Returns:
            Tuple of (triggered, unique_count, trigger_event_id).
            If triggered, trigger_event_id is the event that crossed threshold.
        """
        with self._lock:
            reference_time = (
                event.timestamp
                if event is not None
                else (self._observations[-1][0] if self._observations else None)
            )

            if reference_time is not None:
                self._expire_old_observations(reference_time)

            current_unique_count = len(self._unique_counts)

            # Re-arm if the original trigger event has expired from the window
            if self._triggered:
                trigger_still_present = any(
                    eid == self._trigger_event_id for _, eid, _ in self._observations
                )
                if not trigger_still_present:
                    self._triggered = False
                    self._trigger_event_id = None
                    self._trigger_count = 0

            if current_unique_count >= threshold and not self._triggered:
                self._triggered = True
                self._trigger_count = current_unique_count
                self._trigger_event_id = self._observations[-1][1]
                return True, current_unique_count, self._trigger_event_id

            if current_unique_count < threshold and self._triggered:
                self._triggered = False
                self._trigger_event_id = None
                self._trigger_count = 0

            return False, current_unique_count, None

    def reset_trigger(self) -> None:
        """Reset the triggered state (for re-arm after window expires)."""
        with self._lock:
            self._triggered = False
            self._trigger_event_id = None
            self._trigger_count = 0

    def get_contributing_event_ids(self, limit: int = 50) -> tuple[Any, ...]:
        """Return up to `limit` event IDs in the current window."""
        with self._lock:
            # Return the most recent event IDs up to the limit
            return tuple(eid for _, eid, _ in list(self._observations)[-limit:])

    def get_sample_values(self, limit: int = 5) -> list[Any]:
        """Return a deterministically sorted sample of unique values."""
        with self._lock:
            return sorted(list(self._unique_counts.keys()))[:limit]

    def get_timespan(self) -> float:
        """Return the timespan of observations in seconds."""
        with self._lock:
            if len(self._observations) < 2:
                return 0.0
            first = self._observations[0][0]
            last = self._observations[-1][0]
            return (last - first).total_seconds()
