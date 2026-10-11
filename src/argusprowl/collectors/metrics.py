"""Per-collector metrics.

Each collector instance owns one :class:`CollectorMetrics` object that wraps
thread-safe :class:`~app.metrics.metrics.Counter`, :class:`~app.metrics.metrics.Gauge`,
and :class:`~app.metrics.metrics.Histogram` primitives from the metrics
subsystem.  The companion :class:`CollectorMetricsSnapshot` is a plain frozen
dataclass suitable for serialization or health reporting.
"""

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar

from argusprowl.metrics.metrics import Counter, Gauge, Histogram


@dataclass(frozen=True, slots=True)
class CollectorMetricsSnapshot:
    """Immutable point-in-time snapshot of collector metrics.

    Attributes:
        events_collected: Total events produced by the collector.
        errors_total: Total errors encountered since start.
        state_transitions_total: Total state-machine transitions executed.
        last_error_time: UTC datetime of the most recent error, or None.
        uptime_seconds: Seconds the collector has been in RUNNING state.
        collection_duration_p50: Median collect() call duration in seconds.
        collection_duration_p99: 99th-percentile collect() call duration.
        captured_at: UTC datetime this snapshot was taken.
    """

    events_collected: int
    errors_total: int
    state_transitions_total: int
    last_error_time: datetime | None
    uptime_seconds: float
    collection_duration_p50: float
    collection_duration_p99: float
    captured_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, object]:
        """Serialize snapshot to a plain dict for logging or APIs."""
        return {
            "events_collected": self.events_collected,
            "errors_total": self.errors_total,
            "state_transitions_total": self.state_transitions_total,
            "last_error_time": self.last_error_time.isoformat() if self.last_error_time else None,
            "uptime_seconds": round(self.uptime_seconds, 3),
            "collection_duration_p50": round(self.collection_duration_p50, 6),
            "collection_duration_p99": round(self.collection_duration_p99, 6),
            "captured_at": self.captured_at.isoformat(),
        }


class CollectorMetrics:
    """Thread-safe per-collector metric container.

    Wraps the platform's :class:`~app.metrics.metrics.Counter`,
    :class:`~app.metrics.metrics.Gauge`, and :class:`~app.metrics.metrics.Histogram`
    primitives.  All methods are safe to call from concurrent threads.

    Attributes:
        collector_name: Name of the owning collector (used as metric prefix).
    """

    # Histogram bucket boundaries for collect() call durations (seconds).
    _DURATION_BUCKETS: ClassVar[list[float]] = [
        0.0005,
        0.001,
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
        5.0,
        10.0,
    ]

    def __init__(self, collector_name: str) -> None:
        """Initialise metrics for a named collector.

        Args:
            collector_name: Unique collector identifier used as metric name prefix.
        """
        self.collector_name = collector_name
        prefix = collector_name

        self._events_collected = Counter(
            f"{prefix}.events_collected",
            "Total number of events produced by this collector.",
        )
        self._errors_total = Counter(
            f"{prefix}.errors_total",
            "Total number of errors encountered by this collector.",
        )
        self._state_transitions_total = Counter(
            f"{prefix}.state_transitions_total",
            "Total number of lifecycle state transitions executed.",
        )
        self._last_error_epoch = Gauge(
            f"{prefix}.last_error_epoch",
            "Unix epoch of the most recent collector error (0 = no error).",
        )
        self._uptime_seconds = Gauge(
            f"{prefix}.uptime_seconds",
            "Seconds spent in RUNNING state since last start.",
        )
        self._collection_duration = Histogram(
            f"{prefix}.collection_duration_seconds",
            "Time spent inside a single collect() call, in seconds.",
            buckets=self._DURATION_BUCKETS,
        )
        # Internal wall-clock reference for uptime accumulation.
        self._running_since: float | None = None

    # ------------------------------------------------------------------ mutators

    def record_event_collected(self, count: int = 1) -> None:
        """Increment the events-collected counter.

        Args:
            count: Number of events to add (default 1).
        """
        self._events_collected.increment(count)

    def record_error(self) -> None:
        """Record one error and stamp the last-error epoch gauge."""
        self._errors_total.increment()
        self._last_error_epoch.set(time.time())

    def record_state_transition(self) -> None:
        """Increment the state-transitions counter."""
        self._state_transitions_total.increment()

    def record_collection_duration(self, seconds: float) -> None:
        """Observe a collect() call duration.

        Args:
            seconds: Wall-clock time of the collect() call in seconds.
        """
        self._collection_duration.observe(seconds)

    def mark_running(self) -> None:
        """Record the moment the collector enters RUNNING state."""
        self._running_since = time.monotonic()

    def mark_stopped(self) -> None:
        """Accumulate elapsed uptime when the collector leaves RUNNING state."""
        if self._running_since is not None:
            elapsed = time.monotonic() - self._running_since
            self._uptime_seconds.increment(elapsed)
            self._running_since = None

    # ------------------------------------------------------------------ snapshot

    def snapshot(self) -> CollectorMetricsSnapshot:
        """Return an immutable point-in-time snapshot of all metrics.

        Computes current uptime including any in-progress running period.

        Returns:
            Immutable :class:`CollectorMetricsSnapshot`.
        """
        # Uptime = accumulated + current running period (if any)
        uptime = self._uptime_seconds.get_value()
        if self._running_since is not None:
            uptime += time.monotonic() - self._running_since

        # Extract percentile approximations from histogram data
        hist_data = self._collection_duration.get_value()
        p50, p99 = self._compute_percentiles(hist_data)

        last_error_epoch = self._last_error_epoch.get_value()
        last_error_time: datetime | None = None
        if last_error_epoch > 0:
            last_error_time = datetime.fromtimestamp(last_error_epoch, tz=UTC)

        return CollectorMetricsSnapshot(
            events_collected=self._events_collected.get_value(),
            errors_total=self._errors_total.get_value(),
            state_transitions_total=self._state_transitions_total.get_value(),
            last_error_time=last_error_time,
            uptime_seconds=uptime,
            collection_duration_p50=p50,
            collection_duration_p99=p99,
        )

    def reset(self) -> None:
        """Reset all metrics to their initial state."""
        self._events_collected.reset()
        self._errors_total.reset()
        self._state_transitions_total.reset()
        self._last_error_epoch.reset()
        self._uptime_seconds.reset()
        self._collection_duration.reset()
        self._running_since = None

    # ------------------------------------------------------------------ private

    @staticmethod
    def _compute_percentiles(hist_data: dict[str, object]) -> tuple[float, float]:
        """Approximate p50 and p99 from histogram bucket data.

        Uses linear interpolation within the median and 99th-percentile buckets.

        Args:
            hist_data: Dictionary returned by :meth:`~app.metrics.metrics.Histogram.get_value`.

        Returns:
            Tuple of (p50, p99) approximations in seconds.
        """
        total: int = hist_data.get("count", 0)  # type: ignore[assignment]
        if total == 0:
            return 0.0, 0.0

        buckets: dict[float, int] = hist_data.get("buckets", {})  # type: ignore[assignment]
        sorted_bounds = sorted(buckets.keys())

        def _interpolate(target_count: int) -> float:
            cumulative = 0
            prev_bound = 0.0
            for bound in sorted_bounds:
                bucket_count = buckets[bound]
                if cumulative + bucket_count >= target_count:
                    # Linear interpolation within bucket
                    fraction = (
                        (target_count - cumulative) / bucket_count if bucket_count > 0 else 0.0
                    )
                    return prev_bound + fraction * (bound - prev_bound)
                cumulative += bucket_count
                prev_bound = bound
            # Beyond the last bucket
            return sorted_bounds[-1] if sorted_bounds else 0.0

        p50 = _interpolate(max(1, int(total * 0.50)))
        p99 = _interpolate(max(1, int(total * 0.99)))
        return p50, p99

    def __repr__(self) -> str:
        """String representation."""
        snap = self.snapshot()
        return (
            f"CollectorMetrics(collector={self.collector_name!r}, "
            f"events={snap.events_collected}, "
            f"errors={snap.errors_total})"
        )
