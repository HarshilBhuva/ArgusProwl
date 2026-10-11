"""Temporal engine for beaconing detection.

Provides bounded in-memory state tracking and periodicity analysis
for detecting suspicious beaconing behavior.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import timedelta
from threading import Lock
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
    ) -> None:
        """Initialize temporal engine.

        Args:
            max_keys: Maximum number of (dst_ip, dst_port) keys to track.
            max_observations_per_key: Maximum observations per key.
            window_duration: Time window for analysis.
        """
        self._max_keys = max_keys
        self._max_observations = max_observations_per_key
        self._window_duration = window_duration
        self._buckets: OrderedDict[tuple[str, int], TemporalBucket] = OrderedDict()
        self._lock = Lock()

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

        with self._lock:
            if key in self._buckets:
                bucket = self._buckets[key]
                bucket.add(observation)
                # Move to end for LRU
                self._buckets.move_to_end(key)
            else:
                if len(self._buckets) >= self._max_keys:
                    # Evict oldest (least recently used)
                    self._buckets.popitem(last=False)
                bucket = TemporalBucket(
                    key=key,
                    max_observations=self._max_observations,
                    window_duration=self._window_duration,
                )
                bucket.add(observation)
                self._buckets[key] = bucket

    def get_analysis(
        self,
        dst_ip: str,
        dst_port: int | None = None,
        src_ip: str | None = None,
    ) -> dict[str, Any] | None:
        """Get periodicity analysis for a specific destination.

        Args:
            dst_ip: Destination IP address.
            dst_port: Destination port (optional, None for any port).
            src_ip: Source IP address or host identifier (optional).

        Returns:
            Analysis dictionary or None if not found.
        """
        port = dst_port if dst_port is not None else 0

        with self._lock:
            bucket = None
            if src_ip is not None:
                bucket = self._buckets.get((src_ip, dst_ip, port))
            if bucket is None:
                bucket = self._buckets.get((dst_ip, port))
            if bucket is None:
                # Find matching bucket by destination
                for k, b in self._buckets.items():
                    if (len(k) == 3 and k[1] == dst_ip and k[2] == port) or (
                        len(k) == 2 and k[0] == dst_ip and k[1] == port
                    ):
                        bucket = b
                        break

            if bucket is None or len(bucket) < 2:
                return None

            stats = bucket.get_stats()
            intervals = stats.get("intervals", [])

            if not intervals:
                return None

            periodicity_score = calculate_periodicity_score(intervals)
            classification = classify_periodicity(periodicity_score)

            # Extract process identity from most recent observation
            observations = list(bucket.observations)
            latest = observations[-1] if observations else None

            # Standardized [dst_ip, dst_port] key for downstream consumers
            key_dst = [dst_ip, port]

            result: dict[str, Any] = {
                **stats,
                "periodicity_score": periodicity_score,
                "periodicity_classification": classification,
                "key": key_dst,
            }

            if latest is not None:
                result["process_name"] = latest.process_name
                result["pid"] = latest.pid
                result["username"] = latest.username
                result["hostname"] = latest.hostname
                result["direction"] = latest.direction
                result["command_line"] = latest.command_line

            return result

    def get_all_analyses(self) -> list[dict[str, Any]]:
        """Get periodicity analysis for all tracked destinations.

        Returns:
            List of analysis dictionaries.
        """
        results = []
        with self._lock:
            for key, bucket in self._buckets.items():
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

    def get_key_count(self) -> int:
        """Get number of tracked keys.

        Returns:
            Number of active (dst_ip, dst_port) keys.
        """
        with self._lock:
            return len(self._buckets)

    def clear(self) -> None:
        """Clear all temporal state."""
        with self._lock:
            self._buckets.clear()

    @property
    def max_keys(self) -> int:
        return self._max_keys

    @property
    def max_observations_per_key(self) -> int:
        return self._max_observations

    @property
    def window_duration(self) -> timedelta:
        return self._window_duration
