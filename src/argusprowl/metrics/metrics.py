"""Metrics data structures.

Defines base metric types and implementations for counters, gauges,
and histograms.
"""

import threading
from abc import ABC, abstractmethod
from typing import Any


class Metric(ABC):
    """Abstract base class for metrics.

    All metric types must implement this interface.
    """

    @abstractmethod
    def get_value(self) -> Any:
        """Get current metric value."""

    @abstractmethod
    def reset(self) -> None:
        """Reset metric to initial state."""


class Counter(Metric):
    """Thread-safe counter metric.

    Tracks monotonically increasing values (e.g., events processed).

    Attributes:
        name: Metric name.
        description: Metric description.
        value: Current counter value.
    """

    def __init__(self, name: str, description: str = "") -> None:
        """Initialize counter.

        Args:
            name: Metric name.
            description: Metric description.
        """
        self._name = name
        self._description = description
        self._value = 0
        self._lock = threading.Lock()

    def increment(self, amount: int = 1) -> None:
        """Increment counter by amount.

        Args:
            amount: Amount to increment by (default 1).
        """
        with self._lock:
            self._value += amount

    def get_value(self) -> int:
        """Get current counter value.

        Returns:
            Current counter value.
        """
        with self._lock:
            return self._value

    def reset(self) -> None:
        """Reset counter to zero."""
        with self._lock:
            self._value = 0

    @property
    def name(self) -> str:
        """Metric name."""
        return self._name

    @property
    def description(self) -> str:
        """Metric description."""
        return self._description

    def __repr__(self) -> str:
        """String representation."""
        return f"Counter(name={self._name!r}, value={self._value})"


class Gauge(Metric):
    """Thread-safe gauge metric.

    Tracks values that can go up and down (e.g., queue depth, memory usage).

    Attributes:
        name: Metric name.
        description: Metric description.
        value: Current gauge value.
    """

    def __init__(self, name: str, description: str = "") -> None:
        """Initialize gauge.

        Args:
            name: Metric name.
            description: Metric description.
        """
        self._name = name
        self._description = description
        self._value = 0.0
        self._lock = threading.Lock()

    def set(self, value: float) -> None:
        """Set gauge to specific value.

        Args:
            value: Value to set.
        """
        with self._lock:
            self._value = value

    def increment(self, amount: float = 1.0) -> None:
        """Increment gauge by amount.

        Args:
            amount: Amount to increment by.
        """
        with self._lock:
            self._value += amount

    def decrement(self, amount: float = 1.0) -> None:
        """Decrement gauge by amount.

        Args:
            amount: Amount to decrement by.
        """
        with self._lock:
            self._value -= amount

    def get_value(self) -> float:
        """Get current gauge value.

        Returns:
            Current gauge value.
        """
        with self._lock:
            return self._value

    def reset(self) -> None:
        """Reset gauge to zero."""
        with self._lock:
            self._value = 0.0

    @property
    def name(self) -> str:
        """Metric name."""
        return self._name

    @property
    def description(self) -> str:
        """Metric description."""
        return self._description

    def __repr__(self) -> str:
        """String representation."""
        return f"Gauge(name={self._name!r}, value={self._value})"


class Histogram(Metric):
    """Thread-safe histogram metric.

    Tracks distribution of values (e.g., execution times).

    Attributes:
        name: Metric name.
        description: Metric description.
        buckets: List of bucket boundaries.
        counts: Count of values in each bucket.
        sum: Sum of all values.
        count: Total count of values.
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        buckets: list[float] | None = None,
    ) -> None:
        """Initialize histogram.

        Args:
            name: Metric name.
            description: Metric description.
            buckets: List of bucket boundaries (must be sorted).
        """
        self._name = name
        self._description = description
        self._buckets = buckets or [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        self._counts = [0] * len(self._buckets)
        self._sum = 0.0
        self._count = 0
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        """Observe a value.

        Args:
            value: Value to observe.
        """
        with self._lock:
            self._sum += value
            self._count += 1

            # Increment appropriate buckets
            for i, bucket in enumerate(self._buckets):
                if value <= bucket or (i == 0 and value >= bucket):
                    self._counts[i] += 1

    def get_value(self) -> dict[str, Any]:
        """Get histogram statistics.

        Returns:
            Dictionary with histogram data.
        """
        with self._lock:
            return {
                "count": self._count,
                "sum": self._sum,
                "mean": self._sum / self._count if self._count > 0 else 0.0,
                "buckets": dict(zip(self._buckets, self._counts, strict=False)),
            }

    def reset(self) -> None:
        """Reset histogram to initial state."""
        with self._lock:
            self._counts = [0] * len(self._buckets)
            self._sum = 0.0
            self._count = 0

    @property
    def name(self) -> str:
        """Metric name."""
        return self._name

    @property
    def description(self) -> str:
        """Metric description."""
        return self._description

    def __repr__(self) -> str:
        """String representation."""
        return f"Histogram(name={self._name!r}, count={self._count})"
