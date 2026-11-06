"""Temporal engine for beaconing detection.

Provides bounded in-memory state tracking and periodicity analysis
for detecting suspicious beaconing behavior.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import timedelta
from threading import Condition, Lock
from typing import Any

from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.temporal.periodicity import calculate_periodicity_score, classify_periodicity
from argusprowl.temporal.temporal_state import TemporalBucket, TemporalObservation


class TemporalEngine:
    """Bounded temporal engine for tracking network observations.

    Tracks observations by (dst_ip, dst_port) key and provides
    periodicity analysis for beaconing detection.

    The engine is bounded to prevent unbounded memory growth:
    - Maximum tracked keys
    - Maximum observations per key
    - Maximum window duration

    Thread-safe for concurrent access from multiple collectors.
    """

    def __init__(
        self,
        max_keys: int = 10000,
        max_observations_per_key: int = 1000,
        window_duration: timedelta = timedelta(hours=1),
        allowed_lateness: timedelta | None = None,
    ) -> None:
        """Initialize temporal engine.

        Args:
            max_keys: Maximum number of (dst_ip, dst_port) keys to track.
            max_observations_per_key: Maximum observations per key.
            window_duration: Time window for analysis.
            allowed_lateness: Maximum event-time delay accepted behind the watermark.
                Defaults to the analysis window duration.
        """
        if max_keys < 1:
            raise ValueError("max_keys must be positive")
        if max_observations_per_key < 1:
            raise ValueError("max_observations_per_key must be positive")
        if window_duration <= timedelta(0):
            raise ValueError("window_duration must be positive")
        if allowed_lateness is not None and not timedelta(0) <= allowed_lateness <= window_duration:
            raise ValueError("allowed_lateness must be between zero and window_duration")
        self._max_keys = max_keys
        self._max_observations = max_observations_per_key
        self._window_duration = window_duration
        self._allowed_lateness = allowed_lateness
        self._buckets: OrderedDict[tuple[str, int], TemporalBucket] = OrderedDict()
        self._lock = Lock()
        self._condition = Condition(self._lock)
        self._inflight: dict[tuple[str, ...], int] = {}
        self._clearing = False

    def observe(self, event: NormalizedEvent) -> None:
        """Record an observation for temporal analysis.

        Args:
            event: NormalizedEvent with network connection information.
        """
        if event.dst_ip is None:
            return

        host = event.src_ip or event.hostname
        key = (
            (host, event.dst_ip, event.dst_port or 0)
            if host
            else (event.dst_ip, event.dst_port or 0)
        )

        observation = TemporalObservation(
            event_id=event.event_id,
            timestamp=event.timestamp,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port or 0,
            src_ip=event.src_ip,
            process_name=event.process_name,
            pid=getattr(event, "pid", None),
            username=event.username,
            hostname=event.hostname,
            protocol=event.protocol,
            direction=event.attributes.get("direction") if event.attributes else None,
            command_line=event.command_line,
            source_record_id=event.source_record_id,
        )

        bucket = self._acquire_bucket(key)
        try:
            bucket.add(observation)
        finally:
            self._release_bucket(key)


    def _acquire_bucket(self, key: tuple[str, ...]) -> TemporalBucket:
        """Acquire a bucket reference without holding the registry lock on add."""
        with self._condition:
            while self._clearing:
                self._condition.wait()

            bucket = self._buckets.get(key)
            if bucket is None:
                while len(self._buckets) >= self._max_keys:
                    # Never evict a bucket while a producer or reader is using it.
                    evictable = next(
                        (candidate for candidate in self._buckets if self._inflight.get(candidate, 0) == 0),
                        None,
                    )
                    if evictable is not None:
                        del self._buckets[evictable]
                        break
                    self._condition.wait()
                    while self._clearing:
                        self._condition.wait()

                bucket = TemporalBucket(
                    key=key,
                    max_observations=self._max_observations,
                    window_duration=self._window_duration,
                    allowed_lateness=self._allowed_lateness,
                )
                self._buckets[key] = bucket

            self._inflight[key] = self._inflight.get(key, 0) + 1
            self._buckets.move_to_end(key)
            return bucket

    def _acquire_existing_bucket(
        self,
        dst_ip: str,
        port: int,
        src_ip: str | None,
    ) -> tuple[tuple[str, ...], TemporalBucket] | None:
        """Find and pin a bucket for a read operation."""
        with self._condition:
            while self._clearing:
                self._condition.wait()
            key: tuple[str, ...] | None = None
            bucket: TemporalBucket | None = None
            if src_ip is not None:
                candidate = (src_ip, dst_ip, port)
                bucket = self._buckets.get(candidate)
                if bucket is not None:
                    key = candidate
            if bucket is None:
                candidate = (dst_ip, port)
                bucket = self._buckets.get(candidate)
                if bucket is not None:
                    key = candidate
            if bucket is None:
                for candidate, candidate_bucket in self._buckets.items():
                    if (len(candidate) == 3 and candidate[1] == dst_ip and candidate[2] == port) or (
                        len(candidate) == 2 and candidate[0] == dst_ip and candidate[1] == port
                    ):
                        key = candidate
                        bucket = candidate_bucket
                        break
            if key is None or bucket is None:
                return None
            self._inflight[key] = self._inflight.get(key, 0) + 1
            return key, bucket

    def _release_bucket(self, key: tuple[str, ...]) -> None:
        """Release a pinned bucket and wake waiters when it becomes evictable."""
        with self._condition:
            remaining = self._inflight.get(key, 0) - 1
            if remaining > 0:
                self._inflight[key] = remaining
            else:
                self._inflight.pop(key, None)
            self._condition.notify_all()

    def get_analysis(
        self,
        dst_ip: str,
        dst_port: int | None = None,
        src_ip: str | None = None,
    ) -> dict[str, Any] | None:
        """Get periodicity analysis for a specific destination."""
        port = dst_port if dst_port is not None else 0
        acquired = self._acquire_existing_bucket(dst_ip, port, src_ip)
        if acquired is None:
            return None
        key, bucket = acquired
        try:
            if len(bucket) < 2:
                return None

            stats = bucket.get_stats()
            intervals = stats.get("intervals", [])
            if not intervals:
                return None

            periodicity_score = calculate_periodicity_score(intervals)
            classification = classify_periodicity(periodicity_score)
            with bucket.lock:
                latest = bucket.observations[-1] if bucket.observations else None

            result: dict[str, Any] = {
                **stats,
                "periodicity_score": periodicity_score,
                "periodicity_classification": classification,
                "key": [dst_ip, port],
            }
            if latest is not None:
                result["process_name"] = latest.process_name
                result["pid"] = latest.pid
                result["username"] = latest.username
                result["hostname"] = latest.hostname
                result["direction"] = latest.direction
                result["command_line"] = latest.command_line
            return result
        finally:
            self._release_bucket(key)

    def get_all_analyses(self) -> list[dict[str, Any]]:
        """Get periodicity analysis for a pinned snapshot of tracked buckets."""
        with self._condition:
            while self._clearing:
                self._condition.wait()
            snapshot = list(self._buckets.items())
            for key, _bucket in snapshot:
                self._inflight[key] = self._inflight.get(key, 0) + 1

        results = []
        try:
            for key, bucket in snapshot:
                if len(bucket) >= 2:
                    stats = bucket.get_stats()
                    intervals = stats.get("intervals", [])
                    if intervals:
                        periodicity_score = calculate_periodicity_score(intervals)
                        classification = classify_periodicity(periodicity_score)
                        dst_ip = key[1] if len(key) == 3 else key[0]
                        dst_port = key[2] if len(key) == 3 else key[1]
                        results.append(
                            {
                                **stats,
                                "periodicity_score": periodicity_score,
                                "periodicity_classification": classification,
                                "key": [dst_ip, dst_port],
                            }
                        )
            return results
        finally:
            for key, _bucket in snapshot:
                self._release_bucket(key)

    def get_key_count(self) -> int:
        """Get number of tracked keys.

        Returns:
            Number of active (dst_ip, dst_port) keys.
        """
        with self._lock:
            return len(self._buckets)

    def clear(self) -> None:
        """Clear all temporal state."""
        with self._condition:
            self._clearing = True
            while self._inflight:
                self._condition.wait()
            self._buckets.clear()
            self._clearing = False
            self._condition.notify_all()

    @property
    def max_keys(self) -> int:
        return self._max_keys

    @property
    def max_observations_per_key(self) -> int:
        return self._max_observations

    @property
    def window_duration(self) -> timedelta:
        return self._window_duration
