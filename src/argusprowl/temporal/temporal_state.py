"""Temporal state model for beaconing detection.

Provides bounded in-memory state tracking for network observations,
enabling periodicity analysis without persistent storage.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class TemporalObservation:
    """A single temporal observation of network behavior.

    Attributes:
        event_id: Unique event identifier.
        timestamp: UTC timestamp of the observation.
        dst_ip: Destination IP address.
        dst_port: Destination port number.
        src_ip: Source IP address (may be None).
        process_name: Process name (may be None).
        pid: Process ID (may be None).
        username: Username (may be None).
        hostname: Hostname (may be None).
        protocol: Transport protocol (may be None).
        direction: Network direction (may be None).
        command_line: Command line (may be None).
        source_record_id: Native source identity (may be None).
    """

    event_id: UUID
    timestamp: datetime
    dst_ip: str
    dst_port: int
    src_ip: str | None = None
    process_name: str | None = None
    pid: int | None = None
    username: str | None = None
    hostname: str | None = None
    protocol: str | None = None
    direction: str | None = None
    command_line: str | None = None
    source_record_id: str | None = None

    def identity_keys(self) -> frozenset[str]:
        """Return stable identity keys used for temporal idempotency.

        ``event_id`` is argusprowl's identity for a normalized event.
        ``source_record_id`` is the native source identity (for example Zeek
        ``uid``) and is required for replay, where a new ``event_id`` is
        generated on each parse of the same source record.
        """
        keys = {f"id:{self.event_id}"}
        if self.source_record_id:
            keys.add(f"src:{self.source_record_id}")
        return frozenset(keys)


@dataclass(slots=True)
class TemporalBucket:
    """Bounded temporal bucket tracking observations for a single key.

    A key is defined by (dst_ip, dst_port) pair.

    Attributes:
        key: The (dst_ip, dst_port) tuple identifying this bucket.
        observations: Bounded deque of observations.
        max_observations: Maximum observations to retain.
        window_duration: Time window for analysis.
        lock: Thread safety lock.
    """

    key: tuple[str, int]
    observations: deque[TemporalObservation] = field(default_factory=deque)
    max_observations: int = 1000
    window_duration: timedelta = field(default_factory=lambda: timedelta(hours=1))
    allowed_lateness: timedelta | None = None
    lock: Lock = field(default_factory=Lock, repr=False)
    _max_event_time: datetime | None = field(default=None, init=False, repr=False)
    _late_event_count: int = field(default=0, init=False, repr=False)
    _identity_index: set[str] = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.max_observations < 1:
            raise ValueError("max_observations must be positive")
        if self.window_duration <= timedelta(0):
            raise ValueError("window_duration must be positive")
        if self.allowed_lateness is None:
            self.allowed_lateness = self.window_duration
        if self.allowed_lateness < timedelta(0):
            raise ValueError("allowed_lateness cannot be negative")
        if self.allowed_lateness > self.window_duration:
            raise ValueError("allowed_lateness cannot exceed window_duration")
        for observation in self.observations:
            self._identity_index.update(observation.identity_keys())

    @property
    def watermark(self) -> datetime | None:
        """Return the greatest accepted event timestamp."""
        with self.lock:
            return self._max_event_time

    @property
    def late_event_count(self) -> int:
        """Return the number of observations rejected beyond allowed lateness."""
        with self.lock:
            return self._late_event_count

    def add(self, observation: TemporalObservation) -> bool:
        """Add an observation using an indexed, append-first hot path.

        In-order events are amortized O(1): duplicate checks use a set,
        expiration removes from the deque head, and no full sort occurs.
        Late-but-allowed events use a slower ordered insertion path.
        """
        with self.lock:
            previous_watermark = self._max_event_time
            if previous_watermark is not None:
                lateness_cutoff = previous_watermark - self.allowed_lateness
                if observation.timestamp < lateness_cutoff:
                    self._late_event_count += 1
                    return False

            if self._is_duplicate_unlocked(observation):
                return False

            watermark = observation.timestamp if previous_watermark is None else max(previous_watermark, observation.timestamp)
            cutoff = watermark - self.window_duration
            while self.observations and self.observations[0].timestamp < cutoff:
                expired = self.observations.popleft()
                self._remove_identity_unlocked(expired)

            if observation.timestamp < cutoff:
                self._late_event_count += 1
                return False

            self._max_event_time = watermark
            incoming_key = self._order_key(observation)
            if not self.observations or incoming_key >= self._order_key(self.observations[-1]):
                self.observations.append(observation)
            else:
                ordered = list(self.observations)
                keys = [self._order_key(item) for item in ordered]
                ordered.insert(bisect_right(keys, incoming_key), observation)
                self.observations = deque(ordered)

            self._identity_index.update(observation.identity_keys())
            while len(self.observations) > self.max_observations:
                evicted = self.observations.popleft()
                self._remove_identity_unlocked(evicted)
            return True

    @staticmethod
    def _order_key(observation: TemporalObservation) -> tuple[datetime, str]:
        """Return the stable event-time ordering key."""
        return observation.timestamp, str(observation.event_id)

    def _remove_identity_unlocked(self, observation: TemporalObservation) -> None:
        """Remove identities for an expired or evicted observation."""
        self._identity_index.difference_update(observation.identity_keys())

    def _is_duplicate_unlocked(self, observation: TemporalObservation) -> bool:
        """Return True when any incoming identity is already retained."""
        return not self._identity_index.isdisjoint(observation.identity_keys())

    def _calculate_intervals_unlocked(self) -> list[float]:
        """Calculate intervals between consecutive observations in seconds.

        Assumes caller holds self.lock.

        Returns:
            List of interval durations in seconds.
        """
        if len(self.observations) < 2:
            return []
        intervals: list[float] = []
        prev = self.observations[0].timestamp
        for obs in list(self.observations)[1:]:
            intervals.append((obs.timestamp - prev).total_seconds())
            prev = obs.timestamp
        return intervals

    def get_interval_seconds(self) -> list[float]:
        """Calculate intervals between consecutive observations in seconds.

        Returns:
            List of interval durations in seconds.
        """
        with self.lock:
            return self._calculate_intervals_unlocked()

    def get_stats(self) -> dict[str, Any]:
        """Get statistical summary of observations.

        Returns:
            Dictionary with statistical metrics.
        """
        with self.lock:
            if not self.observations:
                return {
                    "count": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "duration_seconds": 0.0,
                    "mean_interval": 0.0,
                    "std_interval": 0.0,
                    "intervals": [],
                }

            observations = list(self.observations)
            first = observations[0].timestamp
            last = observations[-1].timestamp
            duration = (last - first).total_seconds()
            intervals = self._calculate_intervals_unlocked()

            from argusprowl.feature_engineering.statistics import calculate_mean, calculate_std_dev

            return {
                "count": len(observations),
                "first_seen": first.isoformat(),
                "last_seen": last.isoformat(),
                "duration_seconds": duration,
                "mean_interval": calculate_mean(intervals) if intervals else 0.0,
                "std_interval": calculate_std_dev(intervals) if len(intervals) >= 2 else 0.0,
                "intervals": intervals[:100],  # Limit for serialization
            }

    def __len__(self) -> int:
        with self.lock:
            return len(self.observations)
