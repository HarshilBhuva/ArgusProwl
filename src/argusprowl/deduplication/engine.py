"""Atomic, bounded alert deduplication and occurrence aggregation."""

import heapq
import logging
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from threading import RLock

from argusprowl.deduplication.cache import DeduplicationCache, InMemoryDeduplicationCache
from argusprowl.deduplication.fingerprint import AlertFingerprint, FingerprintConfig
from argusprowl.deduplication.models import DeduplicationState
from argusprowl.metrics.collector import MetricsCollector
from argusprowl.metrics.metrics import Counter, Gauge
from argusprowl.models.alert import Alert


@dataclass(frozen=True, slots=True)
class DeduplicationResult:
    emit: bool
    alert: Alert | None
    state: DeduplicationState

    @property
    def suppressed(self) -> bool:
        return not self.emit


class AlertDeduplicationEngine:
    """Deduplicates *alerts* atomically; it never sees or suppresses events.

    A process-local lock makes check/update atomic for threads in this process.
    The cache interface permits a distributed atomic-store implementation later.
    """

    def __init__(
        self,
        *,
        cooldown: float = 300.0,
        state_ttl: float | None = None,
        max_fingerprints: int = 10_000,
        fingerprint: AlertFingerprint | None = None,
        cache: DeduplicationCache | None = None,
        detector_cooldowns: dict[str, float] | None = None,
        clock: Callable[[], datetime] | None = None,
        metrics_collector: MetricsCollector | None = None,
    ) -> None:
        if cooldown < 0:
            raise ValueError("cooldown must be non-negative")
        self.cooldown = cooldown
        self.state_ttl = state_ttl if state_ttl is not None else max(cooldown * 2, 3600.0)
        if self.state_ttl < cooldown:
            raise ValueError("state_ttl must be at least cooldown")
        self._fingerprint = fingerprint or AlertFingerprint(FingerprintConfig())
        self._cache = cache or InMemoryDeduplicationCache(max_fingerprints)
        self._detector_cooldowns = detector_cooldowns or {}
        if any(value < 0 for value in self._detector_cooldowns.values()):
            raise ValueError("detector cooldowns must be non-negative")
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = RLock()
        self._expiry_heap: list[tuple[float, str]] = []
        self._logger = logging.getLogger("argusprowl.deduplication")
        self.alerts_received = self._counter(metrics_collector, "alerts_received")
        self.alerts_emitted = self._counter(metrics_collector, "alerts_emitted")
        self.alerts_suppressed = self._counter(metrics_collector, "alerts_suppressed")
        self.duplicate_occurrences = self._counter(metrics_collector, "duplicate_occurrences")
        self.active_fingerprints = self._gauge(metrics_collector, "active_fingerprints")
        self.fingerprint_expirations = self._counter(metrics_collector, "fingerprint_expirations")

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

    def process(self, alert: Alert) -> DeduplicationResult:
        self.alerts_received.increment()
        now = self._as_utc(self._clock())
        fingerprint = self._fingerprint.create(alert)
        cooldown = self._detector_cooldowns.get(alert.source, self.cooldown)
        with self._lock:
            self._expire(now)
            previous = self._cache.get(fingerprint)
            if previous is None:
                state = DeduplicationState(
                    fingerprint,
                    alert.source,
                    now,
                    now,
                    1,
                    now + timedelta(seconds=cooldown),
                    alert.alert_id,
                    fingerprint_version=self._fingerprint.config.version,
                )
                self._cache.put(state)
                self._schedule_expiry(state)
                self.active_fingerprints.set(len(self._cache))
                self.alerts_emitted.increment()
                return DeduplicationResult(True, self._with_state(alert, state), state)
            state = replace(
                previous,
                last_seen=now,
                occurrence_count=previous.occurrence_count + 1,
                cooldown_until=now + timedelta(seconds=cooldown),
            )
            self._cache.put(state)
            self._schedule_expiry(state)
            self.duplicate_occurrences.increment()
            self.active_fingerprints.set(len(self._cache))
            if now < previous.cooldown_until:
                self.alerts_suppressed.increment()
                self._logger.debug("Suppressed duplicate alert fingerprint=%s", fingerprint[:15])
                return DeduplicationResult(False, None, state)
            self.alerts_emitted.increment()
            return DeduplicationResult(True, self._with_state(alert, state), state)

    def expire(self) -> int:
        with self._lock:
            return self._expire(self._as_utc(self._clock()))

    def forget(self, alert: Alert) -> None:
        """Remove one local state entry (compatibility/admin recovery hook)."""
        with self._lock:
            self._cache.remove(self._fingerprint.create(alert))
            self.active_fingerprints.set(len(self._cache))

    def clear(self) -> None:
        """Remove all state when an operator explicitly clears cooldowns."""
        with self._lock:
            for state in tuple(self._cache.items()):
                self._cache.remove(state.fingerprint)
            self._expiry_heap.clear()
            self.active_fingerprints.set(0)

    def _expire(self, now: datetime) -> int:
        removed = 0
        now_ts = now.timestamp()
        while self._expiry_heap and self._expiry_heap[0][0] <= now_ts:
            expiry, fingerprint = heapq.heappop(self._expiry_heap)
            state = self._cache.get(fingerprint)
            if (
                state is not None
                and (state.last_seen + timedelta(seconds=self.state_ttl)).timestamp() == expiry
            ):
                self._cache.remove(fingerprint)
                removed += 1
                self.fingerprint_expirations.increment()
                self._logger.debug("Expired alert fingerprint=%s", fingerprint[:15])
        self.active_fingerprints.set(len(self._cache))
        return removed

    def _schedule_expiry(self, state: DeduplicationState) -> None:
        heapq.heappush(
            self._expiry_heap,
            ((state.last_seen + timedelta(seconds=self.state_ttl)).timestamp(), state.fingerprint),
        )

    @staticmethod
    def _with_state(alert: Alert, state: DeduplicationState) -> Alert:
        metadata = dict(alert.metadata)
        metadata.update(
            {
                "fingerprint": state.fingerprint,
                "fingerprint_version": state.fingerprint_version,
                "first_seen": state.first_seen.isoformat(),
                "last_seen": state.last_seen.isoformat(),
                "occurrence_count": state.occurrence_count,
                "deduplicated_alert_id": str(state.alert_id),
            }
        )
        return replace(alert, metadata=metadata)

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
