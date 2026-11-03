"""Cardinality correlation state tracking.

Provides bounded in-memory state for counting unique values within time windows,
grouped by configurable fields. Used by CardinalityCorrelationDetector.
"""

from __future__ import annotations

import math
from collections import Counter, deque
from datetime import datetime, timedelta
from threading import Lock
from typing import Any
from uuid import UUID

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
        self._max_event_time: datetime | None = None
        self._late_event_count = 0
        self._lock = Lock()

    @property
    def late_event_count(self) -> int:
        """Return the number of out-of-order events rejected by this state."""
        with self._lock:
            return self._late_event_count

    def to_dict(self) -> dict[str, object]:
        """Return a versioned, JSON-compatible cardinality state snapshot."""
        with self._lock:
            return {
                "schema_version": 1,
                "group_key": list(self._group_key),
                "window_duration_seconds": self._window_duration.total_seconds(),
                "max_observations": self._max_observations,
                "max_event_time": (
                    self._max_event_time.isoformat()
                    if self._max_event_time is not None
                    else None
                ),
                "late_event_count": self._late_event_count,
                "observations": [
                    {
                        "timestamp": timestamp.isoformat(),
                        "event_id": str(event_id),
                        "value": value,
                    }
                    for timestamp, event_id, value in self._observations
                ],
                "triggered": self._triggered,
                "trigger_event_id": (
                    str(self._trigger_event_id)
                    if self._trigger_event_id is not None
                    else None
                ),
                "trigger_count": self._trigger_count,
            }

    @classmethod
    def from_dict(cls, snapshot: dict[str, object]) -> CardinalityState:
        """Restore a validated cardinality snapshot."""
        if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1:
            raise ValueError("Unsupported cardinality state snapshot schema.")
        group_key = snapshot.get("group_key")
        duration = snapshot.get("window_duration_seconds")
        capacity = snapshot.get("max_observations")
        raw_observations = snapshot.get("observations")
        if (
            not isinstance(group_key, list)
            or not group_key
            or any(not isinstance(part, str) for part in group_key)
        ):
            raise ValueError("Cardinality snapshot group_key is invalid.")
        if (
            not isinstance(duration, (int, float))
            or isinstance(duration, bool)
            or duration <= 0
            or duration > 31_536_000
            or not math.isfinite(float(duration))
        ):
            raise ValueError("Cardinality snapshot window duration is invalid.")
        if (
            not isinstance(capacity, int)
            or isinstance(capacity, bool)
            or not 1 <= capacity <= 1_000_000
        ):
            raise ValueError("Cardinality snapshot capacity is invalid.")
        if not isinstance(raw_observations, list) or len(raw_observations) > capacity:
            raise ValueError("Cardinality snapshot observations are invalid.")

        observations: list[tuple[datetime, UUID, Any]] = []
        for item in raw_observations:
            if not isinstance(item, dict):
                raise ValueError("Cardinality snapshot contains an invalid observation.")
            raw_timestamp = item.get("timestamp")
            raw_event_id = item.get("event_id")
            value = item.get("value")
            if (
                not isinstance(raw_timestamp, str)
                or not isinstance(raw_event_id, str)
                or not (
                    value is None
                    or isinstance(value, (str, int, float, bool))
                )
                or (isinstance(value, float) and not math.isfinite(value))
            ):
                raise ValueError("Cardinality snapshot observation fields are invalid.")
            timestamp = datetime.fromisoformat(raw_timestamp)
            if timestamp.tzinfo is None:
                raise ValueError("Cardinality snapshot timestamps must be timezone-aware.")
            observations.append((timestamp, UUID(raw_event_id), value))
        if observations != sorted(observations, key=lambda item: item[0]):
            raise ValueError("Cardinality snapshot observations are not time ordered.")
        if len({item[1] for item in observations}) != len(observations):
            raise ValueError("Cardinality snapshot contains duplicate event identities.")

        raw_watermark = snapshot.get("max_event_time")
        if raw_watermark is not None and not isinstance(raw_watermark, str):
            raise ValueError("Cardinality snapshot watermark is invalid.")
        watermark = datetime.fromisoformat(raw_watermark) if raw_watermark is not None else None
        if watermark is not None and watermark.tzinfo is None:
            raise ValueError("Cardinality snapshot watermark must be timezone-aware.")
        if observations and (watermark is None or observations[-1][0] > watermark):
            raise ValueError("Cardinality snapshot observations exceed the watermark.")

        late_count = snapshot.get("late_event_count")
        triggered = snapshot.get("triggered")
        trigger_count = snapshot.get("trigger_count")
        raw_trigger_id = snapshot.get("trigger_event_id")
        if not isinstance(late_count, int) or isinstance(late_count, bool) or late_count < 0:
            raise ValueError("Cardinality snapshot late-event count is invalid.")
        if not isinstance(triggered, bool):
            raise ValueError("Cardinality snapshot trigger flag is invalid.")
        if not isinstance(trigger_count, int) or isinstance(trigger_count, bool) or trigger_count < 0:
            raise ValueError("Cardinality snapshot trigger count is invalid.")
        if raw_trigger_id is not None and not isinstance(raw_trigger_id, str):
            raise ValueError("Cardinality snapshot trigger identity is invalid.")
        if triggered and raw_trigger_id is None:
            raise ValueError("Triggered cardinality state requires a trigger identity.")

        state = cls(
            group_key=tuple(group_key),
            window_duration=timedelta(seconds=float(duration)),
            max_observations=capacity,
        )
        state._observations = deque(observations, maxlen=capacity)
        state._unique_counts = Counter(item[2] for item in observations)
        state._max_event_time = watermark
        state._late_event_count = late_count
        state._triggered = triggered
        state._trigger_event_id = UUID(raw_trigger_id) if raw_trigger_id is not None else None
        state._trigger_count = trigger_count
        return state

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
            if self._max_event_time is not None and event.timestamp < self._max_event_time:
                self._late_event_count += 1
                return False
            if self._max_event_time is None or event.timestamp > self._max_event_time:
                self._max_event_time = event.timestamp
            self._expire_old_observations(self._max_event_time)

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
            if event is not None and (
                self._max_event_time is None or event.timestamp > self._max_event_time
            ):
                self._max_event_time = event.timestamp
            reference_time = self._max_event_time

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
