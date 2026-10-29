"""Event-count correlation state tracking.

Provides bounded in-memory state for counting events within time windows,
grouped by configurable fields. Used by EventCountCorrelationDetector.
"""

from __future__ import annotations

from collections import deque
from datetime import timedelta
from threading import Lock
from typing import Any

from argusprowl.models.normalized_event import NormalizedEvent


class EventCountState:
    """Bounded state for event-count correlation.

    Tracks events grouped by a key tuple, maintaining a sliding time window
    and enforcing capacity limits via LRU/FIFO eviction.

    Attributes:
        group_key: The grouping key tuple (e.g., src_ip, dst_ip).
        observations: Time-ordered deque of events within the window.
        window_duration: Maximum age of observations before expiration.
        max_observations: Hard limit on observations per key.
        max_keys: Hard limit on total keys (enforced by parent).
        triggered: Whether the threshold has been crossed in this window.
        trigger_event_id: The event that caused the threshold crossing.
        trigger_count: The count at the time of threshold crossing.
    """

    def __init__(
        self,
        group_key: tuple[str, ...],
        window_duration: timedelta,
        max_observations: int = 1000,
    ) -> None:
        """Initialize event count state.

        Args:
            group_key: Tuple of field values identifying this group.
            window_duration: Sliding window duration for event retention.
            max_observations: Maximum observations to retain per key.
        """
        self._group_key = group_key
        self._observations: deque[NormalizedEvent] = deque(maxlen=max_observations)
        self._window_duration = window_duration
        self._max_observations = max_observations
        self._triggered = False
        self._trigger_event_id: Any = None
        self._trigger_count: int = 0
        self._lock = Lock()

    @property
    def group_key(self) -> tuple[str, ...]:
        """Return the grouping key."""
        return self._group_key

    @property
    def count(self) -> int:
        """Return current observation count within window."""
        with self._lock:
            return len(self._observations)

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
        """Return the count at threshold crossing."""
        with self._lock:
            return self._trigger_count

    @property
    def observations(self) -> list[NormalizedEvent]:
        """Return current observations (copy for safety)."""
        with self._lock:
            return list(self._observations)

    def add(self, event: NormalizedEvent) -> bool:
        """Add an event to this group's observations.

        Expired events are removed before adding. Returns False if the
        event was a duplicate (same source_record_id or event_id).

        Args:
            event: The event to add.

        Returns:
            True if added, False if duplicate.
        """
        with self._lock:
            # Event timestamps may arrive out of order. Anchor the sliding
            # window to the newest event time observed, not the incoming event.
            newest_time = max(
                (obs.timestamp for obs in self._observations),
                default=event.timestamp,
            )
            reference_time = max(newest_time, event.timestamp)
            cutoff = reference_time - self._window_duration
            self._observations = deque(
                (obs for obs in self._observations if obs.timestamp >= cutoff),
                maxlen=self._max_observations,
            )

            # Ignore events that are already outside the active event-time
            # window; inserting them would make an old event look current.
            if event.timestamp < cutoff:
                return False

            # A source record ID is only unique inside its source scope
            # (e.g. host + channel/stream), not globally.
            for obs in self._observations:
                if obs.event_id == event.event_id:
                    return False
                if (
                    event.source_record_id is not None
                    and obs.source_record_id == event.source_record_id
                    and self._source_scope(obs) == self._source_scope(event)
                ):
                    return False

            ordered = sorted((*self._observations, event), key=lambda item: item.timestamp)
            self._observations = deque(ordered, maxlen=self._max_observations)
            return True

    @staticmethod
    def _source_scope(event: NormalizedEvent) -> tuple[str | None, ...]:
        """Return fields that scope a source-local record identifier."""
        metadata = event.metadata or {}
        return (
            event.source_type,
            event.hostname,
            event.sensor,
            str(metadata.get("channel")) if metadata.get("channel") is not None else None,
            str(metadata.get("stream")) if metadata.get("stream") is not None else None,
            str(metadata.get("log_path")) if metadata.get("log_path") is not None else None,
        )

    def check_threshold(
        self, threshold: int, event: NormalizedEvent | None = None
    ) -> tuple[bool, int, Any]:
        """Check if threshold is met and return detection info.

        Args:
            threshold: Minimum count to trigger detection.
            event: Optional event whose timestamp defines the window.

        Returns:
            Tuple of (triggered, count, trigger_event_id).
            If triggered, trigger_event_id is the event that crossed threshold.
        """
        with self._lock:
            # Keep window evaluation monotonic even when a late event is
            # passed to detect() after newer observations have arrived.
            newest_time = max(
                (obs.timestamp for obs in self._observations),
                default=event.timestamp if event is not None else None,
            )
            reference_time = newest_time
            if reference_time is not None:
                cutoff = reference_time - self._window_duration
                self._observations = deque(
                    (obs for obs in self._observations if obs.timestamp >= cutoff),
                    maxlen=self._max_observations,
                )

            current_count = len(self._observations)

            # Re-arm if the original trigger event has expired from the window
            if self._triggered:
                trigger_still_present = any(
                    obs.event_id == self._trigger_event_id for obs in self._observations
                )
                if not trigger_still_present:
                    self._triggered = False
                    self._trigger_event_id = None
                    self._trigger_count = 0

            if current_count >= threshold and not self._triggered:
                # Threshold crossed - record the triggering event
                self._triggered = True
                self._trigger_count = current_count
                # The last event in the window is the triggering event
                self._trigger_event_id = self._observations[-1].event_id
                return True, current_count, self._trigger_event_id

            if current_count < threshold and self._triggered:
                # Threshold no longer met - re-arm
                self._triggered = False
                self._trigger_event_id = None
                self._trigger_count = 0

            return False, current_count, None

    def reset_trigger(self) -> None:
        """Reset the triggered state (for re-arm after window expires)."""
        with self._lock:
            self._triggered = False
            self._trigger_event_id = None
            self._trigger_count = 0

    def get_contributing_event_ids(self) -> tuple[Any, ...]:
        """Return all event IDs in the current window."""
        with self._lock:
            return tuple(obs.event_id for obs in self._observations)

    def get_timespan(self) -> float:
        """Return the timespan of observations in seconds."""
        with self._lock:
            if len(self._observations) < 2:
                return 0.0
            first = self._observations[0].timestamp
            last = self._observations[-1].timestamp
            return (last - first).total_seconds()
